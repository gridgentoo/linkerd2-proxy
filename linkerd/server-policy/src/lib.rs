#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

mod authz;
#[cfg(feature = "proto")]
mod proto;

pub use self::authz::{Authentication, Authorization, Network, Suffix};
pub use linkerd_http_route::filter;
use linkerd_http_route::{
    filter::{InvalidRedirect, Redirection},
    service::Routes,
    ApplyRoute, HttpRouteMatch,
};
use std::{sync::Arc, time};

pub type HttpRoute = linkerd_http_route::HttpRoute<RoutePolicy>;
pub type HttpRule = linkerd_http_route::HttpRule<RoutePolicy>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    pub protocol: Protocol,
    pub authorizations: Arc<[Authorization]>,
    pub kind: Arc<str>,
    pub name: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Detect {
        http: HttpConfig,
        timeout: time::Duration,
    },
    Http1(HttpConfig),
    Http2(HttpConfig),
    Grpc {
        disable_info_headers: bool,
        // TODO gRPC routes https://gateway-api.sigs.k8s.io/geps/gep-1016/
    },
    Opaque,
    Tls,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HttpConfig {
    pub disable_info_headers: bool,
    pub routes: Vec<HttpRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoutePolicy {
    pub authorizations: Arc<[Authorization]>,
    pub filters: Vec<RouteFilter>,
    pub labels: Labels,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Labels(Arc<[(String, String)]>);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RouteFilter {
    RequestHeaders(filter::ModifyRequestHeader),
    Redirect(filter::RedirectRequest),
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("invalid redirect: {0}")]
    InvalidRedirect(#[from] InvalidRedirect),

    #[error("request redirected")]
    Redirect(Redirection),
}

// === impl Labels ===

impl std::ops::Deref for Labels {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// === impl HttpConfig ===

impl Routes<RoutePolicy> for HttpConfig {
    fn routes(&self) -> &[linkerd_http_route::HttpRoute<R>] {
        &*self.routes
    }
}

// === impl RoutePolicy ===

impl ApplyRoute for RoutePolicy {
    type Error = RouteError;

    fn apply_route<B>(
        &self,
        rm: HttpRouteMatch,
        req: &mut http::Request<B>,
    ) -> Result<(), RouteError> {
        // TODO use request extensions to find client information.
        for authz in &*self.authorizations {
            let _ = authz;
        }

        for filter in &self.filters {
            match filter {
                RouteFilter::RequestHeaders(rh) => {
                    rh.apply(req.headers_mut());
                }
                RouteFilter::Redirect(redir) => {
                    let redirection = redir.apply(req.uri(), &rm)?;
                    return Err(RouteError::Redirect(redirection));
                }
            }
        }

        req.extensions_mut().insert(self.labels.clone());

        Ok(())
    }
}
