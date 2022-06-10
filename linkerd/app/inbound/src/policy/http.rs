#![allow(dead_code)] // FIXME

use crate::{
    metrics::authz::HttpAuthzMetrics,
    policy::{AllowPolicy, RoutePermit},
};
use futures::{future, TryFutureExt};
use linkerd_app_core::{
    metrics::{RouteAuthzLabels, RouteLabels},
    svc::{self, ServiceExt},
    tls,
    transport::{ClientAddr, Remote},
    Error,
};
use linkerd_server_policy::{
    http_route::{
        self,
        filter::{InvalidRedirect, Redirection},
    },
    Meta as RouteMeta, RouteFilter,
};
use std::{sync::Arc, task};

/// A middleware that enforces policy on each HTTP request.
///
/// This enforcement is done lazily on each request so that policy updates are
/// honored as the connection progresses.
///
/// The inner service is created for each request, so it's expected that this is
/// combined with caching.
///
/// TODO this needs a better name to reflect its not solely about authorization.
#[derive(Clone, Debug)]
pub struct NewHttpPolicy<N> {
    metrics: HttpAuthzMetrics,
    inner: N,
}

#[derive(Clone, Debug)]
pub struct AuthorizeHttp<T, N> {
    target: T,
    client_addr: Remote<ClientAddr>,
    tls: tls::ConditionalServerTls,
    policy: AllowPolicy,
    metrics: HttpAuthzMetrics,
    inner: N,
}

#[derive(Debug, thiserror::Error)]
#[error("no route found for request")]
pub struct HttpRouteNotFound(());

#[derive(Debug, thiserror::Error)]
#[error("invalid redirect: {0}")]
pub struct HttpRouteInvalidRedirect(#[from] pub InvalidRedirect);

#[derive(Debug, thiserror::Error)]
#[error("request redirected to {}", .0.location)]
pub struct HttpRouteRedirect(pub Redirection);

#[derive(Debug, thiserror::Error)]
#[error("unknown filter type in route: {} {} {}", .0.group, .0.kind, .0.name)]
pub struct HttpRouteUnknownFilter(Arc<RouteMeta>);

#[derive(Debug, thiserror::Error)]
#[error("unauthorized request on route")]
pub struct HttpRouteUnauthorized(());

// === impl NewHttpPolicy ===

impl<N> NewHttpPolicy<N> {
    pub fn layer(metrics: HttpAuthzMetrics) -> impl svc::layer::Layer<N, Service = Self> + Clone {
        svc::layer::mk(move |inner| Self {
            metrics: metrics.clone(),
            inner,
        })
    }
}

impl<T, N> svc::NewService<T> for NewHttpPolicy<N>
where
    T: svc::Param<AllowPolicy>
        + svc::Param<Remote<ClientAddr>>
        + svc::Param<tls::ConditionalServerTls>,
    N: Clone,
{
    type Service = AuthorizeHttp<T, N>;

    fn new_service(&self, target: T) -> Self::Service {
        let client_addr = target.param();
        let tls = target.param();
        let policy = target.param();
        AuthorizeHttp {
            target,
            client_addr,
            tls,
            policy,
            metrics: self.metrics.clone(),
            inner: self.inner.clone(),
        }
    }
}

// === impl AuthorizeHttp ===

impl<B, T, N, S> svc::Service<http::Request<B>> for AuthorizeHttp<T, N>
where
    T: Clone,
    N: svc::NewService<(RoutePermit, T), Service = S>,
    S: svc::Service<http::Request<B>>,
    S::Error: Into<Error>,
{
    type Response = S::Response;
    type Error = Error;
    type Future = future::Either<
        future::ErrInto<svc::stack::Oneshot<S, http::Request<B>>, Error>,
        future::Ready<Result<Self::Response, Error>>,
    >;

    #[inline]
    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let dst = self.policy.dst_addr();
        let labels = self.policy.server_label();

        let routes = self.policy.http_routes();
        let (rt_match, route) =
            match http_route::find(routes.as_deref().into_iter().flatten(), &req) {
                Some(rt) => rt,
                None => {
                    // TODO metrics...
                    return future::Either::Right(future::err(HttpRouteNotFound(()).into()));
                }
            };

        let labels = RouteLabels {
            route: route.meta.clone(),
            server: labels,
        };

        let authz = match route
            .authorizations
            .iter()
            .find(|a| super::is_authorized(a, self.client_addr, &self.tls))
        {
            Some(authz) => authz,
            None => {
                tracing::info!(
                    server.group = %labels.server.0.group,
                    server.kind = %labels.server.0.kind,
                    server.name = %labels.server.0.name,
                    route.group = %labels.route.group,
                    route.kind = %labels.route.kind,
                    route.name = %labels.route.name,
                    client.tls = ?self.tls,
                    client.ip = %self.client_addr.ip(),
                    "Request denied",
                );
                self.metrics.deny(labels, dst, self.tls.clone());
                return future::Either::Right(future::err(HttpRouteUnauthorized(()).into()));
            }
        };

        let permit = {
            let labels = RouteAuthzLabels {
                route: labels,
                authz: authz.meta.clone(),
            };
            tracing::debug!(
                server.group = %labels.route.server.0.group,
                server.kind = %labels.route.server.0.kind,
                server.name = %labels.route.server.0.name,
                route.group = %labels.route.route.group,
                route.kind = %labels.route.route.kind,
                route.name = %labels.route.route.name,
                authz.group = %labels.authz.group,
                authz.kind = %labels.authz.kind,
                authz.name = %labels.authz.name,
                client.tls = ?self.tls,
                client.ip = %self.client_addr.ip(),
                "Request authorized",
            );
            RoutePermit { dst, labels }
        };

        self.metrics.allow(&permit, self.tls.clone());

        // TODO should we have metrics about filter usage?
        for filter in &route.filters {
            match filter {
                RouteFilter::RequestHeaders(rh) => {
                    rh.apply(req.headers_mut());
                }

                RouteFilter::Redirect(redir) => match redir.apply(req.uri(), &rt_match) {
                    Ok(Some(redirection)) => {
                        return future::Either::Right(future::err(
                            HttpRouteRedirect(redirection).into(),
                        ))
                    }

                    Err(invalid) => {
                        return future::Either::Right(future::err(
                            HttpRouteInvalidRedirect(invalid).into(),
                        ))
                    }

                    Ok(None) => {
                        tracing::debug!("Ignoring irrelvant redirect");
                    }
                },

                RouteFilter::Unknown => {
                    let meta = route.meta.clone();
                    return future::Either::Right(future::err(HttpRouteUnknownFilter(meta).into()));
                }
            }
        }

        let svc = self.inner.new_service((permit, self.target.clone()));
        future::Either::Left(svc.oneshot(req).err_into::<Error>())
    }
}
