#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

pub mod authz;
#[cfg(feature = "proto")]
mod proto;

pub use self::authz::{Authentication, Authorization};
pub use linkerd_grpc_route as grpc_route;
pub use linkerd_http_route as http_route;
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
    Grpc(GrpcConfig),
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
pub struct RoutePolicy<T> {
    pub meta: Arc<Meta>,
    pub authorizations: Arc<[Authorization]>,
    pub filters: Vec<T>,
}

pub type HttpRoute = http_route::HttpRoute<RoutePolicy<HttpRouteFilter>>;
pub type HttpRule = http_route::HttpRule<RoutePolicy<HttpRouteFilter>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpConfig {
    pub routes: Arc<[HttpRoute]>,
}

pub type GrpcRoute = grpc_route::GrpcRoute<RoutePolicy<GrpcRouteFilter>>;
pub type GrpcRule = grpc_route::GrpcRule<RoutePolicy<GrpcRouteFilter>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrpcConfig {
    pub routes: Arc<[GrpcRoute]>,
}

// === impl HttpConfig ===

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            routes: vec![].into(),
        }
    }
}

// === impl HttpRouteFilter ===

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HttpRouteFilter {
    Error(http_route::filter::RespondWithError),

    RequestHeaders(http_route::filter::ModifyRequestHeader),

    Redirect(http_route::filter::RedirectRequest),

    /// Indicates that the filter kind is unknown to the proxy (e.g., because
    /// the controller is on a new version of the protobuf).
    ///
    /// Route handlers must be careful about this situation, as it may not be
    /// appropriate for a proxy to skip filtering logic.
    Unknown,
}

// === impl GrpcConfig ===

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            routes: vec![].into(),
        }
    }
}

// === impl GrpcRouteFilter ===

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GrpcRouteFilter {
    Error(grpc_route::filter::RespondWithError),

    RequestHeaders(http_route::filter::ModifyRequestHeader),

    /// Indicates that the filter kind is unknown to the proxy (e.g., because
    /// the controller is on a new version of the protobuf).
    ///
    /// Route handlers must be careful about this situation, as it may not be
    /// appropriate for a proxy to skip filtering logic.
    Unknown,
}
