#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

pub use linkerd_authz::{Authentication, Authorization, Network, Suffix};
pub use linkerd_http_routes::InboundRoutes;
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
    Grpc(HttpConfig),
    Opaque,
    Tls,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HttpConfig {
    pub info_headers: bool,
    pub routes: InboundRoutes,
}
