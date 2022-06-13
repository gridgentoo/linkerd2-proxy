#![allow(dead_code)] // FIXME

use super::Routes;
use crate::{
    metrics::authz::HttpAuthzMetrics,
    policy::{AllowPolicy, RoutePermit},
};
use futures::{future, TryFutureExt};
use linkerd_app_core::{
    metrics::{RouteAuthzLabels, RouteLabels},
    svc::{self, ServiceExt},
    tls,
    transport::{ClientAddr, OrigDstAddr, Remote},
    Error,
};
use linkerd_server_policy::{grpc, http, Authorization, Meta as RouteMeta};
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
    meta: Meta,
    policy: AllowPolicy,
    metrics: HttpAuthzMetrics,
    inner: N,
}

#[derive(Clone, Debug)]
struct Meta {
    dst: OrigDstAddr,
    client: Remote<ClientAddr>,
    tls: tls::ConditionalServerTls,
}

#[derive(Debug, thiserror::Error)]
#[error("no route found for request")]
pub struct HttpRouteNotFound(());

#[derive(Debug, thiserror::Error)]
#[error("invalid redirect: {0}")]
pub struct HttpRouteInvalidRedirect(#[from] pub http::filter::InvalidRedirect);

#[derive(Debug, thiserror::Error)]
#[error("request redirected to {}", .0.location)]
pub struct HttpRouteRedirect(pub http::filter::Redirection);

#[derive(Debug, thiserror::Error)]
#[error("API indicated an HTTP error response: {}: {}", .0.status, .0.message)]
pub struct HttpRouteErrorResponse(pub http::filter::RespondWithError);

#[derive(Debug, thiserror::Error)]
#[error("API indicated an gRPC error response: {}: {}", .0.code, .0.message)]
pub struct GrpcRouteErrorResponse(pub grpc::filter::RespondWithError);

#[derive(Debug, thiserror::Error)]
#[error("unknown filter type in route: {} {} {}", .0.group(), .0.kind(), .0.name())]
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
        let client = target.param();
        let tls = target.param();
        let policy: AllowPolicy = target.param();
        let dst = policy.dst_addr();
        AuthorizeHttp {
            target,
            policy,
            meta: Meta { client, dst, tls },
            metrics: self.metrics.clone(),
            inner: self.inner.clone(),
        }
    }
}

// === impl AuthorizeHttp ===

impl<B, T, N, S> svc::Service<::http::Request<B>> for AuthorizeHttp<T, N>
where
    T: Clone,
    N: svc::NewService<(RoutePermit, T), Service = S>,
    S: svc::Service<::http::Request<B>>,
    S::Error: Into<Error>,
{
    type Response = S::Response;
    type Error = Error;
    type Future = future::Either<
        future::ErrInto<svc::stack::Oneshot<S, ::http::Request<B>>, Error>,
        future::Ready<Result<Self::Response, Error>>,
    >;

    #[inline]
    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: ::http::Request<B>) -> Self::Future {
        let labels = self.policy.server_label();

        match self.policy.routes() {
            None => future::Either::Right({
                // TODO metrics...
                future::err(HttpRouteNotFound(()).into())
            }),

            Some(Routes::Http(routes)) => future::Either::Left({
                let (rt_match, route) = match http::find(&*routes, &req) {
                    Some(rtm) => rtm,
                    None => {
                        // TODO metrics...
                        return future::Either::Right(future::err(HttpRouteNotFound(()).into()));
                    }
                };

                let labels = RouteLabels {
                    route: route.meta.clone(),
                    server: labels,
                };

                let permit = match Self::authorize(
                    &*route.authorizations,
                    &self.meta,
                    labels,
                    &self.metrics,
                ) {
                    Ok(p) => p,
                    Err(deny) => return future::Either::Right(future::err(deny.into())),
                };

                // TODO should we have metrics about filter usage?
                for filter in &route.filters {
                    match filter {
                        http::Filter::RequestHeaders(rh) => {
                            rh.apply(req.headers_mut());
                        }

                        http::Filter::Redirect(redir) => match redir.apply(req.uri(), &rt_match) {
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

                        http::Filter::Error(respond) => {
                            return future::Either::Right(future::err(
                                HttpRouteErrorResponse(respond.clone()).into(),
                            ));
                        }

                        http::Filter::Unknown => {
                            let meta = route.meta.clone();
                            return future::Either::Right(future::err(
                                HttpRouteUnknownFilter(meta).into(),
                            ));
                        }
                    }
                }

                self.inner
                    .new_service((permit, self.target.clone()))
                    .oneshot(req)
                    .err_into::<Error>()
            }),

            Some(Routes::Grpc(routes)) => future::Either::Left({
                let (rt_match, route) = match grpc::find(&*routes, &req) {
                    Some(rtm) => rtm,
                    None => {
                        // TODO metrics...
                        return future::Either::Right(future::err(HttpRouteNotFound(()).into()));
                    }
                };

                let labels = RouteLabels {
                    route: route.meta.clone(),
                    server: labels,
                };

                let permit = match Self::authorize(
                    &*route.authorizations,
                    &self.meta,
                    labels,
                    &self.metrics,
                ) {
                    Ok(p) => p,
                    Err(deny) => return future::Either::Right(future::err(deny.into())),
                };

                // TODO should we have metrics about filter usage?
                for filter in &route.filters {
                    match filter {
                        grpc::Filter::RequestHeaders(rh) => {
                            rh.apply(req.headers_mut());
                        }

                        grpc::Filter::Error(respond) => {
                            return future::Either::Right(future::err(
                                GrpcRouteErrorResponse(respond.clone()).into(),
                            ));
                        }

                        grpc::Filter::Unknown => {
                            let meta = route.meta.clone();
                            return future::Either::Right(future::err(
                                HttpRouteUnknownFilter(meta).into(),
                            ));
                        }
                    }
                }

                self.inner
                    .new_service((permit, self.target.clone()))
                    .oneshot(req)
                    .err_into::<Error>()
            }),
        }
    }
}

impl<T, N> AuthorizeHttp<T, N> {
    pub fn authorize<'a>(
        authzs: impl IntoIterator<Item = &'a Authorization>,
        meta: &Meta,
        labels: RouteLabels,
        metrics: &HttpAuthzMetrics,
    ) -> Result<RoutePermit, HttpRouteUnauthorized> {
        let authz = match authzs
            .into_iter()
            .find(|a| super::is_authorized(a, meta.client, &meta.tls))
        {
            Some(authz) => authz,
            None => {
                tracing::info!(
                    server.group = %labels.server.0.group(),
                    server.kind = %labels.server.0.kind(),
                    server.name = %labels.server.0.name(),
                    route.group = %labels.route.group(),
                    route.kind = %labels.route.kind(),
                    route.name = %labels.route.name(),
                    client.tls = ?meta.tls,
                    client.ip = %meta.client.ip(),
                    "Request denied",
                );
                metrics.deny(labels, meta.dst, meta.tls.clone());
                return Err(HttpRouteUnauthorized(()));
            }
        };

        let permit = {
            let labels = RouteAuthzLabels {
                route: labels,
                authz: authz.meta.clone(),
            };
            tracing::debug!(
                server.group = %labels.route.server.0.group(),
                server.kind = %labels.route.server.0.kind(),
                server.name = %labels.route.server.0.name(),
                route.group = %labels.route.route.group(),
                route.kind = %labels.route.route.kind(),
                route.name = %labels.route.route.name(),
                authz.group = %labels.authz.group(),
                authz.kind = %labels.authz.kind(),
                authz.name = %labels.authz.name(),
                client.tls = ?meta.tls,
                client.ip = %meta.client.ip(),
                "Request authorized",
            );
            RoutePermit {
                dst: meta.dst,
                labels,
            }
        };

        metrics.allow(&permit, meta.tls.clone());
        Ok(permit)
    }
}
