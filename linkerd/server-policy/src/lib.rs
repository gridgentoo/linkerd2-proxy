#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

mod authz;
#[cfg(feature = "proto")]
mod proto;

pub use self::authz::{Authentication, Authorization, Network, Suffix};
pub use linkerd_http_routes::{filter, HttpRoutes};
use std::{sync::Arc, time};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    pub protocol: Protocol,
    pub authorizations: Vec<Authorization>,
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
    },
    Opaque,
    Tls,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HttpConfig {
    pub disable_info_headers: bool,
    pub routes: HttpRoutes<RoutePolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoutePolicy {
    pub authorizations: Arc<[Authorization]>,
    pub filters: Vec<RouteFilter>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RouteFilter {
    RequestHeaders(filter::ModifyRequestHeader),
    Redirect(filter::RedirectRequest),
}
