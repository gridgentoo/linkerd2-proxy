#![allow(dead_code)] // FIXME

use crate::metrics::authz::HttpAuthzMetrics;

use super::super::{AllowPolicy, ServerPermit};
use futures::future;
use linkerd_app_core::{
    svc, tls,
    transport::{ClientAddr, Remote},
    Error,
};
use linkerd_server_policy::{
    self as policy,
    http_route::{
        self,
        filter::{InvalidRedirect, Redirection},
        /* HttpRouteMatch, */
    },
};
use std::task;

/// A middleware that enforces policy on each HTTP request.
///
/// This enforcement is done lazily on each request so that policy updates are honored as the
/// connection progresses.
///
/// The inner service is created for each request, so it's expected that this is combined with
/// caching.
#[derive(Clone, Debug)]
pub struct NewAuthorizeHttp<N> {
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
pub enum RouteError {
    #[error("no route found for request")]
    NotFound,

    #[error("invalid redirect: {0}")]
    InvalidRedirect(#[from] InvalidRedirect),

    #[error("request redirected")]
    Redirect(Redirection),
}

// === impl NewAuthorizeHttp ===

impl<N> NewAuthorizeHttp<N> {
    pub fn layer(metrics: HttpAuthzMetrics) -> impl svc::layer::Layer<N, Service = Self> + Clone {
        svc::layer::mk(move |inner| Self {
            metrics: metrics.clone(),
            inner,
        })
    }
}

impl<T, N> svc::NewService<T> for NewAuthorizeHttp<N>
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
    N: svc::NewService<(ServerPermit, T), Service = S>,
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
        let routes = self.policy.http_routes();
        let (rt_match, route) =
            match http_route::find(routes.as_deref().into_iter().flatten(), &req) {
                Some(rt) => rt,
                None => return future::Either::Right(future::err(RouteError::NotFound.into())),
            };

        let _authz = match route
            .authorizations
            .iter()
            .find(|a| super::super::is_authorized(a, self.client_addr, &self.tls))
        {
            Some(authz) => authz,
            None => {
                // tracing::info!(
                //     server = %format_args!("{}:{}", self.policy.server_label().kind, self.policy.server_label().name),
                //     tls = ?self.tls,
                //     client = %self.client_addr,
                //     "Request denied",
                // );
                // self.metrics.deny(&self.policy, self.tls.clone());
                // return future::Either::Right(future::err(e.into()))
                todo!()
            }
        };
        // TODO permit, metrics, etc..

        for filter in &route.filters {
            match filter {
                policy::RouteFilter::RequestHeaders(rh) => {
                    rh.apply(req.headers_mut());
                }
                policy::RouteFilter::Redirect(redir) => match redir.apply(req.uri(), &rt_match) {
                    Ok(redirection) => {
                        return future::Either::Right(future::err(
                            RouteError::Redirect(redirection).into(),
                        ))
                    }
                    Err(invalid) => {
                        return future::Either::Right(future::err(
                            RouteError::InvalidRedirect(invalid).into(),
                        ))
                    }
                },
                policy::RouteFilter::Unknown => {
                    // XXX should we throw an error? log a warning?
                }
            }
        }

        // tracing::trace!(policy = ?self.policy, "Authorizing request");
        // match self.policy.check_authorized(self.client_addr, &self.tls) {
        //     Ok(permit) => {
        //         tracing::debug!(
        //             ?permit,
        //             tls = ?self.tls,
        //             client = %self.client_addr,
        //             "Request authorized",
        //         );
        //         self.metrics.allow(&permit, self.tls.clone());
        //         let svc = self.inner.new_service((permit, self.target.clone()));
        //         future::Either::Left(svc.oneshot(req).err_into::<Error>())
        //     }
        // }
        todo!()
    }
}
