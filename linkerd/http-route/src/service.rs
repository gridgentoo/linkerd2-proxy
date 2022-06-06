use futures::TryFutureExt;
use linkerd_stack::Service;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use crate::HttpRouteMatch;

pub trait Routes {
    type Route;
    type Error;

    fn find<B>(&self, req: &http::Request<B>) -> Option<(HttpRouteMatch, &Self::Route)>;

    fn apply<B>(
        &self,
        rt_match: HttpRouteMatch,
        route: &Self::Route,
        req: &mut http::Request<B>,
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug)]
pub struct RouteService<R, S> {
    routes: R,
    inner: S,
}

#[derive(Debug, thiserror::Error)]
pub enum Error<R, S> {
    #[error("no route found")]
    RouteNotFound,

    #[error("failed to route request: {0}")]
    Route(#[source] R),

    #[error("service failed: {0}")]
    Service(#[source] S),
}

// === impl RouteService ===

impl<R: Routes, S> RouteService<R, S> {
    pub fn new(routes: R, inner: S) -> Self {
        Self { routes, inner }
    }
}

impl<B, R, S> Service<http::Request<B>> for RouteService<R, S>
where
    R: Routes,
    R::Error: Send + 'static,
    S: Service<http::Request<B>>,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = Error<R::Error, S::Error>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Error<R::Error, S::Error>>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::Service)
    }

    #[inline]
    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let (rt_match, route) = match self.routes.find(&req) {
            Some(rt) => rt,
            None => return Box::pin(futures::future::err(Error::RouteNotFound)),
        };

        if let Err(e) = self.routes.apply(rt_match, route, &mut req) {
            return Box::pin(futures::future::err(Error::Route(e)));
        }

        Box::pin(self.inner.call(req).map_err(Error::Service))
    }
}

// === impl Routes ===

impl<T: Routes> Routes for std::sync::Arc<T> {
    type Route = T::Route;
    type Error = T::Error;

    #[inline]
    fn find<B>(&self, req: &http::Request<B>) -> Option<(HttpRouteMatch, &Self::Route)> {
        T::find(self, req)
    }

    #[inline]
    fn apply<B>(
        &self,
        rt_match: HttpRouteMatch,
        route: &Self::Route,
        req: &mut http::Request<B>,
    ) -> Result<(), Self::Error> {
        T::apply(self, rt_match, route, req)
    }
}
