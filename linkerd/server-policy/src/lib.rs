#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

mod authz;
#[cfg(feature = "proto")]
mod proto;

pub use self::authz::{Authentication, Authorization, Network, Suffix};
pub use linkerd_http_route::{
    self as http_route,
    filter::{ModifyRequestHeader, RedirectRequest},
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
    pub labels: RouteLabels,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouteLabels(Arc<[(String, String)]>);

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

// === impl RouteLabels ===

impl From<std::collections::HashMap<String, String>> for RouteLabels {
    fn from(labels: std::collections::HashMap<String, String>) -> Self {
        let mut kvs = labels.into_iter().collect::<Vec<_>>();
        kvs.sort_by(|(k0, _), (k1, _)| k0.cmp(k1));
        Self(kvs.into())
    }
}

impl std::ops::Deref for RouteLabels {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
