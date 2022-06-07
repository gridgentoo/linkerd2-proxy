#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

pub mod authz;
#[cfg(feature = "proto")]
mod proto;

pub use self::authz::{Authentication, Authorization};
pub use linkerd_http_route::{
    self as http_route,
    filter::{ModifyRequestHeader, RedirectRequest},
};
use std::{borrow::Cow, hash::Hash, sync::Arc, time};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    pub protocol: Protocol,
    pub authorizations: Arc<[Authorization]>,
    pub meta: Arc<Meta>,
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

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Meta {
    pub group: Cow<'static, str>,
    pub kind: Cow<'static, str>,
    pub name: Cow<'static, str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpConfig {
    pub disable_info_headers: bool,
    pub routes: Arc<[HttpRoute]>,
}

pub type HttpRoute = linkerd_http_route::HttpRoute<RoutePolicy>;
pub type HttpRule = linkerd_http_route::HttpRule<RoutePolicy>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoutePolicy {
    pub authorizations: Arc<[Authorization]>,
    pub filters: Vec<RouteFilter>,
    pub meta: Arc<Meta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RouteFilter {
    RequestHeaders(ModifyRequestHeader),

    Redirect(RedirectRequest),

    /// Indicates that the filter kind is unknown to the proxy (e.g., because
    /// the controller is on a new version of the protobuf).
    ///
    /// Route handlers must be careful about this situation, as it may not be
    /// appropriate for a proxy to skip filtering logic.
    Unknown,
}

// === impl HttpConfig ===

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            disable_info_headers: false,
            routes: vec![].into(),
        }
    }
}
