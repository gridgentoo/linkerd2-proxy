use crate::*;
use http_route::proto::ErrorResponderError;
use ipnet::IpNet;
use linkerd2_proxy_api::{inbound as api, net::InvalidIpNetwork};
use linkerd_http_route::{
    proto::{HostMatchError, RequestHeaderModifierError, RequestRedirectError, RouteMatchError},
    MatchHost, MatchRequest,
};
use std::{borrow::Cow, net::IpAddr, sync::Arc, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum InvalidServer {
    #[error("missing protocol detection timeout")]
    MissingDetectTimeout,

    #[error("invalid protocol detection timeout: {0:?}")]
    NegativeDetectTimeout(Duration),

    #[error("missing protocol detection timeout")]
    MissingProxyProtocol,

    #[error("invalid label: {0}")]
    Meta(#[from] InvalidMeta),

    #[error("invalid authorization: {0}")]
    Authz(#[from] InvalidAuthz),

    #[error("invalid gRPC route: {0}")]
    GrpcRoute(#[from] InvalidGrpcRoute),

    #[error("invalid HTTP route: {0}")]
    HttpRoute(#[from] InvalidHttpRoute),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidAuthz {
    #[error("missing networks")]
    MissingNetworks,

    #[error("missing network")]
    MissingNetwork,

    #[error("missing authentications")]
    MissingAuthentications,

    #[error("invalid network: {0}")]
    Network(#[from] InvalidIpNetwork),

    #[error("invalid label: {0}")]
    Meta(#[from] InvalidMeta),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidMeta {
    #[error("missing 'name' label")]
    Name,

    #[error("missing 'kind' label")]
    Kind,

    #[error("missing 'group' label")]
    Group,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidHttpRoute {
    #[error("invalid host match: {0}")]
    HostMatch(#[from] HostMatchError),

    #[error("invalid route match: {0}")]
    RouteMatch(#[from] RouteMatchError),

    #[error("invalid request header modifier: {0}")]
    RequestHeaderModifier(#[from] RequestHeaderModifierError),

    #[error("invalid request redirect: {0}")]
    Redirect(#[from] RequestRedirectError),

    #[error("invalid error responder: {0}")]
    ErrorRespnder(#[from] ErrorResponderError),

    #[error("invalid authorization: {0}")]
    Authz(#[from] InvalidAuthz),

    #[error("invalid labels: {0}")]
    Meta(#[from] InvalidMeta),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidGrpcRoute {
    #[error("invalid host match: {0}")]
    HostMatch(#[from] HostMatchError),

    #[error("invalid route match: {0}")]
    RouteMatch(#[from] grpc_route::proto::RouteMatchError),

    #[error("invalid request header modifier: {0}")]
    RequestHeaderModifier(#[from] RequestHeaderModifierError),

    #[error("invalid error responder: {0}")]
    ErrorRespnder(#[from] grpc_route::proto::ErrorResponderError),

    #[error("invalid authorization: {0}")]
    Authz(#[from] InvalidAuthz),

    #[error("invalid labels: {0}")]
    Meta(#[from] InvalidMeta),
}

impl TryFrom<api::Server> for ServerPolicy {
    type Error = InvalidServer;

    fn try_from(proto: api::Server) -> Result<Self, Self::Error> {
        let protocol = match proto
            .protocol
            .and_then(|api::ProxyProtocol { kind }| kind)
            .ok_or(InvalidServer::MissingProxyProtocol)?
        {
            api::proxy_protocol::Kind::Detect(api::proxy_protocol::Detect {
                timeout,
                http_routes,
            }) => {
                let http = HttpConfig::try_new(http_routes)?;
                Protocol::Detect {
                    http,
                    timeout: timeout
                        .ok_or(InvalidServer::MissingDetectTimeout)?
                        .try_into()
                        .map_err(InvalidServer::NegativeDetectTimeout)?,
                }
            }

            api::proxy_protocol::Kind::Http1(api::proxy_protocol::Http1 { routes }) => {
                let http = HttpConfig::try_new(routes)?;
                Protocol::Http1(http)
            }

            api::proxy_protocol::Kind::Http2(api::proxy_protocol::Http2 { routes }) => {
                let http = HttpConfig::try_new(routes)?;
                Protocol::Http2(http)
            }

            api::proxy_protocol::Kind::Grpc(api::proxy_protocol::Grpc { routes }) => {
                let http = GrpcConfig::try_new(routes)?;
                Protocol::Grpc(http)
            }

            api::proxy_protocol::Kind::Tls(_) => Protocol::Tls,
            api::proxy_protocol::Kind::Opaque(_) => Protocol::Opaque,
        };

        let authorizations = mk_authorizations(proto.authorizations)?;

        let meta = Meta::try_new_with_default(proto.labels, "policy.linkerd.io", "server")?;
        Ok(ServerPolicy {
            protocol,
            authorizations,
            meta,
        })
    }
}

fn mk_authorizations(authzs: Vec<api::Authz>) -> Result<Arc<[Authorization]>, InvalidAuthz> {
    let loopback = Authorization {
        authentication: Authentication::Unauthenticated,
        networks: vec![
            authz::Network {
                net: IpAddr::from([127, 0, 0, 1]).into(),
                except: vec![],
            },
            authz::Network {
                net: IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]).into(),
                except: vec![],
            },
        ],
        meta: Arc::new(Meta {
            group: "default".into(),
            kind: "default".into(),
            name: "localhost".into(),
        }),
    };

    authzs
        .into_iter()
        .map(Authorization::try_from)
        .chain(Some(Ok(loopback)))
        .collect::<Result<Arc<[_]>, _>>()
}

impl TryFrom<api::Authz> for Authorization {
    type Error = InvalidAuthz;

    fn try_from(proto: api::Authz) -> Result<Self, Self::Error> {
        let api::Authz {
            labels,
            authentication,
            networks,
        } = proto;

        if networks.is_empty() {
            return Err(InvalidAuthz::MissingNetworks);
        }
        let networks = networks
            .into_iter()
            .map(|api::Network { net, except }| {
                let net = net.ok_or(InvalidAuthz::MissingNetwork)?.try_into()?;
                let except = except
                    .into_iter()
                    .map(|net| net.try_into())
                    .collect::<Result<Vec<IpNet>, _>>()?;
                Ok(authz::Network { net, except })
            })
            .collect::<Result<Vec<_>, InvalidAuthz>>()?;

        let authn = match authentication
            .and_then(|api::Authn { permit }| permit)
            .ok_or(InvalidAuthz::MissingAuthentications)?
        {
            api::authn::Permit::Unauthenticated(_) => Authentication::Unauthenticated,
            api::authn::Permit::MeshTls(api::authn::PermitMeshTls { clients }) => {
                match clients.ok_or(InvalidAuthz::MissingAuthentications)? {
                    api::authn::permit_mesh_tls::Clients::Unauthenticated(_) => {
                        Authentication::TlsUnauthenticated
                    }
                    api::authn::permit_mesh_tls::Clients::Identities(ids) => {
                        let identities = ids
                            .identities
                            .into_iter()
                            .map(|api::Identity { name }| name)
                            .collect();
                        let suffixes = ids
                            .suffixes
                            .into_iter()
                            .map(|api::IdentitySuffix { parts }| authz::Suffix::from(parts))
                            .collect();
                        Authentication::TlsAuthenticated {
                            identities,
                            suffixes,
                        }
                    }
                }
            }
        };

        let meta = Meta::try_new_with_default(labels, "policy.linkerd.io", "serverauthorization")?;
        Ok(Authorization {
            networks,
            authentication: authn,
            meta,
        })
    }
}

impl Meta {
    fn try_new(
        mut labels: std::collections::HashMap<String, String>,
    ) -> Result<Arc<Meta>, InvalidMeta> {
        let group = labels.remove("group").ok_or(InvalidMeta::Group)?;
        let kind = labels.remove("kind").ok_or(InvalidMeta::Kind)?;
        let name = labels.remove("name").ok_or(InvalidMeta::Name)?;
        Ok(Arc::new(Meta {
            group: group.into(),
            kind: kind.into(),
            name: name.into(),
        }))
    }

    fn try_new_with_default(
        mut labels: std::collections::HashMap<String, String>,
        default_group: &'static str,
        default_kind: &'static str,
    ) -> Result<Arc<Meta>, InvalidMeta> {
        let name = labels.remove("name").ok_or(InvalidMeta::Name)?;

        let group = labels
            .remove("group")
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed(default_group));

        if let Some(kind) = labels.remove("kind") {
            return Ok(Arc::new(Meta {
                group,
                kind: kind.into(),
                name: name.into(),
            }));
        }

        // Older control plane versions don't set the kind label and, instead, may
        // encode kinds in the name like `default:deny`.
        let mut parts = name.splitn(2, ':');
        let meta = match (parts.next().unwrap().to_owned(), parts.next()) {
            (kind, Some(name)) => Meta {
                group,
                kind: kind.into(),
                name: name.to_owned().into(),
            },
            (name, None) => Meta {
                group,
                kind: default_kind.into(),
                name: name.into(),
            },
        };

        Ok(Arc::new(meta))
    }
}

impl HttpConfig {
    fn try_new(routes: Vec<api::HttpRoute>) -> Result<Self, InvalidHttpRoute> {
        let routes = routes
            .into_iter()
            .map(Self::try_route)
            .collect::<Result<Arc<[HttpRoute]>, InvalidHttpRoute>>()?;
        Ok(HttpConfig { routes })
    }

    fn try_route(proto: api::HttpRoute) -> Result<HttpRoute, InvalidHttpRoute> {
        let api::HttpRoute {
            hosts,
            authorizations,
            rules,
            labels,
        } = proto;

        let hosts = hosts
            .into_iter()
            .map(MatchHost::try_from)
            .collect::<Result<Vec<_>, HostMatchError>>()?;

        let authzs = mk_authorizations(authorizations)?;
        let meta = Meta::try_new(labels)?;
        let rules = rules
            .into_iter()
            .map(|r| Self::try_rule(authzs.clone(), meta.clone(), r))
            .collect::<Result<Vec<_>, InvalidHttpRoute>>()?;

        Ok(HttpRoute { hosts, rules })
    }

    fn try_rule(
        authorizations: Arc<[Authorization]>,
        meta: Arc<Meta>,
        proto: api::http_route::Rule,
    ) -> Result<HttpRule, InvalidHttpRoute> {
        let matches = proto
            .matches
            .into_iter()
            .map(MatchRequest::try_from)
            .collect::<Result<Vec<_>, RouteMatchError>>()?;

        let policy = {
            use api::http_route::filter;

            let filters = proto
                .filters
                .into_iter()
                .map(|f| match f.kind {
                    Some(filter::Kind::RequestHeaderModifier(rhm)) => {
                        Ok(HttpRouteFilter::RequestHeaders(rhm.try_into()?))
                    }
                    Some(filter::Kind::Redirect(rr)) => {
                        Ok(HttpRouteFilter::Redirect(rr.try_into()?))
                    }
                    Some(filter::Kind::Error(rsp)) => Ok(HttpRouteFilter::Error(rsp.try_into()?)),
                    None => Ok(HttpRouteFilter::Unknown),
                })
                .collect::<Result<Vec<_>, InvalidHttpRoute>>()?;

            RoutePolicy {
                authorizations,
                filters,
                meta,
            }
        };

        Ok(HttpRule { matches, policy })
    }
}

impl GrpcConfig {
    fn try_new(routes: Vec<api::GrpcRoute>) -> Result<Self, InvalidGrpcRoute> {
        let routes = routes
            .into_iter()
            .map(Self::try_route)
            .collect::<Result<Arc<[GrpcRoute]>, InvalidGrpcRoute>>()?;
        Ok(GrpcConfig { routes })
    }

    fn try_route(proto: api::GrpcRoute) -> Result<GrpcRoute, InvalidGrpcRoute> {
        let api::GrpcRoute {
            hosts,
            authorizations,
            rules,
            labels,
        } = proto;

        let hosts = hosts
            .into_iter()
            .map(MatchHost::try_from)
            .collect::<Result<Vec<_>, HostMatchError>>()?;

        let authzs = mk_authorizations(authorizations)?;
        let meta = Meta::try_new(labels)?;
        let rules = rules
            .into_iter()
            .map(|r| Self::try_rule(authzs.clone(), meta.clone(), r))
            .collect::<Result<Vec<_>, InvalidGrpcRoute>>()?;

        Ok(GrpcRoute { hosts, rules })
    }

    fn try_rule(
        authorizations: Arc<[Authorization]>,
        meta: Arc<Meta>,
        proto: api::grpc_route::Rule,
    ) -> Result<GrpcRule, InvalidGrpcRoute> {
        let matches = proto
            .matches
            .into_iter()
            .map(grpc_route::MatchRequest::try_from)
            .collect::<Result<Vec<_>, grpc_route::proto::RouteMatchError>>()?;

        let policy = {
            use api::grpc_route::filter;

            let filters = proto
                .filters
                .into_iter()
                .map(|f| match f.kind {
                    Some(filter::Kind::Error(rsp)) => Ok(GrpcRouteFilter::Error(rsp.try_into()?)),
                    Some(filter::Kind::RequestHeaderModifier(rhm)) => {
                        Ok(GrpcRouteFilter::RequestHeaders(rhm.try_into()?))
                    }
                    None => Ok(GrpcRouteFilter::Unknown),
                })
                .collect::<Result<Vec<_>, InvalidGrpcRoute>>()?;

            RoutePolicy {
                authorizations,
                filters,
                meta,
            }
        };

        Ok(GrpcRule { matches, policy })
    }
}
