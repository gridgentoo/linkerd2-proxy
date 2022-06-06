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
    pub labels: Arc<Labels>,
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpConfig {
    pub disable_info_headers: bool,
    pub routes: Arc<[HttpRoute]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoutePolicy {
    pub authorizations: Arc<[Authorization]>,
    pub filters: Vec<RouteFilter>,
    pub labels: Arc<Labels>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Labels {
    pub kind: String,
    pub name: String,
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

#[derive(Debug, thiserror::Error)]
pub enum InvalidLabels {
    #[error("missing label 'kind'")]
    MissingKind,

    #[error("missing label 'name'")]
    MissingName,
}

// === impl Labels ===

impl TryFrom<std::collections::HashMap<String, String>> for Labels {
    type Error = InvalidLabels;

    fn try_from(labels: std::collections::HashMap<String, String>) -> Result<Self, InvalidLabels> {
        let kind = labels
            .get("kind")
            .ok_or(InvalidLabels::MissingKind)?
            .clone();
        let name = labels
            .get("name")
            .ok_or(InvalidLabels::MissingName)?
            .clone();
        Ok(Self { kind, name })
    }
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
