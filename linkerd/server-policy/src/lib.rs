#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

pub mod authz;
pub mod grpc;
pub mod http;

pub use self::authz::{Authentication, Authorization};
use std::{hash::Hash, sync::Arc, time};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    pub protocol: Protocol,
    pub authorizations: Arc<[Authorization]>,
    pub meta: Arc<Meta>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Detect {
        http: Arc<[http::Route]>,
        timeout: time::Duration,
    },
    Http1(Arc<[http::Route]>),
    Http2(Arc<[http::Route]>),
    Grpc(Arc<[grpc::Route]>),
    Opaque,
    Tls,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoutePolicy<T> {
    pub meta: Arc<Meta>,
    pub authorizations: Arc<[Authorization]>,
    pub filters: Vec<T>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Meta {
    Default {
        name: &'static str,
    },
    Resource {
        group: String,
        kind: String,
        name: String,
    },
}

impl Meta {
    pub fn name(&self) -> &str {
        match self {
            Meta::Default { name } => name,
            Meta::Resource { name, .. } => &*name,
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Meta::Default { .. } => "default",
            Meta::Resource { kind, .. } => &*kind,
        }
    }

    pub fn group(&self) -> &str {
        match self {
            Meta::Default { .. } => "",
            Meta::Resource { group, .. } => &*group,
        }
    }
}
