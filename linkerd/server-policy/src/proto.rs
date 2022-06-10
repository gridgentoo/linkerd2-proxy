use crate::*;
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
    InvalidLabel(#[from] InvalidLabel),

    #[error("invalid authorization: {0}")]
    InvalidAuthz(#[from] InvalidAuthz),

    #[error("invalid HTTP route: {0}")]
    InvalidHttpRoute(#[from] InvalidHttpRoute),
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
    InvalidNetwork(#[from] InvalidIpNetwork),

    #[error("invalid label: {0}")]
    InvalidLabel(#[from] InvalidLabel),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidLabel {
    #[error("missing 'name' label")]
    MissingName,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidHttpRoute {
    #[error("invalid host match: {0}")]
    InvalidHostMatch(#[from] HostMatchError),

    #[error("invalid route match: {0}")]
    InvalidRouteMatch(#[from] RouteMatchError),

    #[error("invalid request header modifier: {0}")]
    InvalidRequestHeaderModifier(#[from] RequestHeaderModifierError),

    #[error("invalid request redirect: {0}")]
    InvalidRedirect(#[from] RequestRedirectError),

    #[error("invalid authorization: {0}")]
    InvalidAuthz(#[from] InvalidAuthz),

    #[error("invalid filter with an unkown kind")]
    MissingFilter,

    #[error("invalid labels: {0}")]
    InvalidLabel(#[from] InvalidLabel),
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
                let http = HttpConfig::try_new(routes)?;
                Protocol::Grpc(http)
            }

            api::proxy_protocol::Kind::Tls(_) => Protocol::Tls,
            api::proxy_protocol::Kind::Opaque(_) => Protocol::Opaque,
        };

        let authorizations = mk_authorizations(proto.authorizations)?;

        let meta = Meta::try_new(proto.labels, "server")?;
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

        let meta = Meta::try_new(labels, "serverauthorization")?;
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
        default_kind: &'static str,
    ) -> Result<Arc<Meta>, InvalidLabel> {
        let name = labels.remove("name").ok_or(InvalidLabel::MissingName)?;

        let group = labels
            .remove("group")
            .map(Cow::Owned)
            // If no group is specified, we leave it blank. This is to avoid setting
            // a group when using synthetic kinds like "default".
            .unwrap_or(Cow::Borrowed(""));

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
        let meta = Meta::try_new(labels, "httproute")?;
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
            use api::http_route::rule::filter;

            let filters = proto
                .filters
                .into_iter()
                .map(|f| match f.kind {
                    Some(filter::Kind::RequestHeaderModifier(rhm)) => {
                        Ok(RouteFilter::RequestHeaders(rhm.try_into()?))
                    }
                    Some(filter::Kind::Redirect(rr)) => Ok(RouteFilter::Redirect(rr.try_into()?)),
                    Some(filter::Kind::Error(rsp)) => Ok(RouteFilter::Error(rsp.try_into()?)),
                    None => Ok(RouteFilter::Unknown),
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
