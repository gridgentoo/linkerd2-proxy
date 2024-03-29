use super::TransportHeader;
use bytes::BytesMut;
use linkerd_error::{Error, Result};
use linkerd_io as io;
use linkerd_stack::{layer, NewService, Service, ServiceExt};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time;
use tracing::{debug, trace};

#[derive(Clone, Debug, Default)]
pub struct NewTransportHeaderServer<N> {
    inner: N,
    timeout: time::Duration,
}

#[derive(Clone, Debug, Default)]
pub struct TransportHeaderServer<T, N> {
    target: T,
    inner: N,
    timeout: time::Duration,
}

impl<N> NewTransportHeaderServer<N> {
    pub fn layer(timeout: time::Duration) -> impl layer::Layer<N, Service = Self> + Copy {
        layer::mk(move |inner| Self { inner, timeout })
    }
}

impl<T, N: Clone> NewService<T> for NewTransportHeaderServer<N> {
    type Service = TransportHeaderServer<T, N>;

    fn new_service(&self, target: T) -> Self::Service {
        TransportHeaderServer {
            target,
            timeout: self.timeout,
            inner: self.inner.clone(),
        }
    }
}

impl<T, I, N, S> Service<I> for TransportHeaderServer<T, N>
where
    T: Clone + Send + 'static,
    I: io::AsyncRead + Send + Unpin + 'static,
    N: NewService<(TransportHeader, T), Service = S> + Clone + Send + 'static,
    S: Service<io::PrefixedIo<I>> + Send,
    S::Error: Into<Error>,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response>> + Send + 'static>>;

    #[inline]
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut io: I) -> Self::Future {
        let timeout = self.timeout;
        let target = self.target.clone();
        let inner = self.inner.clone();
        Box::pin(async move {
            trace!("Reading transport header");
            let mut buf = BytesMut::with_capacity(1024 * 64);
            let hdr = time::timeout(timeout, TransportHeader::read_prefaced(&mut io, &mut buf))
                .await
                .map_err(|_| {
                    debug!("Transport header timed out");
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Reading a transport header timed out",
                    )
                })??
                .ok_or_else(|| {
                    debug!("No transport header read");
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Connection did not include a transport header",
                    )
                })?;
            debug!(header = ?hdr, "Read transport header");
            let svc = inner.new_service((hdr, target));
            svc.oneshot(io::PrefixedIo::new(buf.freeze(), io))
                .await
                .map_err(Into::into)
        })
    }
}
