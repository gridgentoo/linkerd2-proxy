use super::{ApplyRoute, HttpRoute};
use crate::RouteError;
use futures::TryFutureExt;
use linkerd_stack::Service;
use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

pub trait Routes<R> {
    fn routes(&self) -> &[HttpRoute<R>];
}

#[derive(Clone, Debug)]
pub struct RouteService<T: Routes<R>, R, S> {
    routes: T,
    inner: S,
    _marker: PhantomData<R>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error<R, S> {
    #[error("failed to route request: {0}")]
    Route(#[source] RouteError<R>),

    #[error("service failed: {0}")]
    Service(#[source] S),
}

// === impl RouteService ===

impl<T: Routes<R>, R, S> RouteService<T, R, S> {
    pub fn new(routes: T, inner: S) -> Self {
        Self {
            routes,
            inner,
            _marker: PhantomData,
        }
    }
}

impl<B, T, R, S> Service<http::Request<B>> for RouteService<T, R, S>
where
    T: Routes<R>,
    R: ApplyRoute + Send + 'static,
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
        if let Err(e) = crate::find_and_apply(self.routes.routes(), &mut req) {
            return Box::pin(futures::future::err(Error::Route(e)));
        }

        Box::pin(self.inner.call(req).map_err(Error::Service))
    }
}
