use crate::*;
use ipnet::IpNet;
use linkerd2_proxy_api::{inbound as api, net::InvalidIpNetwork};
use linkerd_http_route::{
    proto::{HostMatchError, RequestHeaderModifierError, RequestRedirectError, RouteMatchError},
    MatchHost, MatchRequest,
};
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing 'name' label")]
    MissingNameLabel,

    #[error("protocol missing detect timeout")]
    MissingDetectTimeout,
    #[error("protocol has a negative detect timeout: {0:?}")]
    NegativeDetectTimeout(time::Duration),

    #[error("server missing proxy protocol")]
    MissingProxyProtocol,

    #[error("authorization missing networks")]
    MissingNetworks,

    #[error("authorization has invalid network: {0}")]
    InvalidNetwork(#[from] InvalidIpNetwork),

    #[error("authorization permits no clients")]
    MissingClients,

    #[error("authentication is not valid")]
    InvalidAuthentication,

    #[error("invalid host match: {0}")]
    InvalidHostMatch(#[from] HostMatchError),

    #[error("invalid route match: {0}")]
    InvalidRouteMatch(#[from] RouteMatchError),

    #[error("invalid request header modifier: {0}")]
    InvalidRequestHeaderModifier(#[from] RequestHeaderModifierError),

    #[error("invalid request redirect: {0}")]
    InvalidRedirect(#[from] RequestRedirectError),

    #[error("invalid filter with an unkown kind")]
    MissingFilter,
}

impl TryFrom<api::Server> for ServerPolicy {
    type Error = Error;

    fn try_from(proto: api::Server) -> Result<ServerPolicy, Self::Error> {
        let protocol = match proto.protocol {
            Some(api::ProxyProtocol { kind: Some(k) }) => match k {
                api::proxy_protocol::Kind::Detect(api::proxy_protocol::Detect {
                    timeout,
                    http_disable_informational_headers,
                    http_routes,
                }) => Protocol::Detect {
                    timeout: timeout
                        .ok_or(Error::MissingDetectTimeout)?
                        .try_into()
                        .map_err(Error::NegativeDetectTimeout)?,
                    http: HttpConfig::try_new(http_disable_informational_headers, http_routes)?,
                },

                api::proxy_protocol::Kind::Http1(api::proxy_protocol::Http1 {
                    disable_informational_headers,
                    routes,
                }) => Protocol::Http1(HttpConfig::try_new(disable_informational_headers, routes)?),

                api::proxy_protocol::Kind::Http2(api::proxy_protocol::Http2 {
                    disable_informational_headers,
                    routes,
                }) => Protocol::Http2(HttpConfig::try_new(disable_informational_headers, routes)?),

                api::proxy_protocol::Kind::Grpc(api::proxy_protocol::Grpc {
                    disable_informational_headers,
                }) => Protocol::Grpc {
                    disable_info_headers: disable_informational_headers,
                },

                api::proxy_protocol::Kind::Opaque(_) => Protocol::Opaque,
                api::proxy_protocol::Kind::Tls(_) => Protocol::Tls,
            },
            _ => return Err(Error::MissingProxyProtocol),
        };

        let authorizations = to_authorizations(proto.authorizations)?;

        let (kind, name) = kind_name(&proto.labels, "server")?;
        Ok(ServerPolicy {
            protocol,
            authorizations,
            kind,
            name,
        })
    }
}

fn to_authorizations(authzs: Vec<api::Authz>) -> Result<Arc<[Authorization]>, Error> {
    let loopback = Authorization {
        kind: "default".into(),
        name: "localhost".into(),
        authentication: Authentication::Unauthenticated,
        networks: vec![
            Network {
                net: IpAddr::from([127, 0, 0, 1]).into(),
                except: vec![],
            },
            Network {
                net: IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]).into(),
                except: vec![],
            },
        ],
    };
    authzs
        .into_iter()
        .map(to_authorization)
        .chain(Some(Ok(loopback)))
        .collect::<Result<Arc<[_]>, Error>>()
}

fn to_authorization(az: api::Authz) -> Result<Authorization, Error> {
    let api::Authz {
        labels,
        authentication,
        networks,
    } = az;

    let networks = {
        if networks.is_empty() {
            return Err(Error::MissingNetworks);
        }
        networks
            .into_iter()
            .map(|api::Network { net, except }| {
                let net = net.ok_or(Error::MissingNetworks)?.try_into()?;
                let except = except
                    .into_iter()
                    .map(|net| net.try_into())
                    .collect::<Result<Vec<IpNet>, _>>()?;
                Ok(Network { net, except })
            })
            .collect::<Result<Vec<_>, Error>>()?
    };

    let authn = {
        use api::authn::{permit_mesh_tls::Clients, Permit, PermitMeshTls};
        match authentication
            .and_then(|a| a.permit)
            .ok_or(Error::InvalidAuthentication)?
        {
            Permit::Unauthenticated(_) => Authentication::Unauthenticated,
            Permit::MeshTls(PermitMeshTls { clients }) => {
                match clients.ok_or(Error::MissingClients)? {
                    Clients::Unauthenticated(_) => Authentication::TlsUnauthenticated,
                    Clients::Identities(ids) => Authentication::TlsAuthenticated {
                        identities: ids
                            .identities
                            .into_iter()
                            .map(|api::Identity { name }| name)
                            .collect(),
                        suffixes: ids
                            .suffixes
                            .into_iter()
                            .map(|api::IdentitySuffix { parts }| Suffix::from(parts))
                            .collect(),
                    },
                }
            }
        }
    };

    let (kind, name) = kind_name(&labels, "serverauthorization")?;
    Ok(Authorization {
        networks,
        authentication: authn,
        kind,
        name,
    })
}

fn kind_name(
    labels: &std::collections::HashMap<String, String>,
    default_kind: &str,
) -> Result<(Arc<str>, Arc<str>), Error> {
    let name = labels.get("name").ok_or(Error::MissingNameLabel)?.clone();
    let mut parts = name.splitn(2, ':');
    match (parts.next().unwrap(), parts.next()) {
        (kind, Some(name)) => Ok((kind.into(), name.into())),
        (name, None) => {
            let kind = labels
                .get("kind")
                .cloned()
                .unwrap_or_else(|| default_kind.to_string());
            Ok((kind.into(), name.into()))
        }
    }
}

impl HttpConfig {
    fn try_new(disable_info_headers: bool, routes: Vec<api::HttpRoute>) -> Result<Self, Error> {
        let routes = routes
            .into_iter()
            .map(Self::try_route)
            .collect::<Result<HttpRoutes<RoutePolicy>, Error>>()?;
        Ok(HttpConfig {
            disable_info_headers,
            routes,
        })
    }

    fn try_route(proto: api::HttpRoute) -> Result<HttpRoute, Error> {
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

        let authzs = to_authorizations(authorizations)?;
        let labels: Arc<[_]> = {
            let mut ls = labels.into_iter().collect::<Vec<_>>();
            ls.sort_by(|(k0, _), (k1, _)| k0.cmp(k1));
            ls.into()
        };
        let rules = rules
            .into_iter()
            .map(|r| Self::try_rule(authzs.clone(), labels.clone(), r))
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(HttpRoute { hosts, rules })
    }

    fn try_rule(
        authorizations: Arc<[Authorization]>,
        labels: Labels,
        proto: api::http_route::Rule,
    ) -> Result<HttpRule, Error> {
        use api::http_route::rule::filter;

        let matches = proto
            .matches
            .into_iter()
            .map(MatchRequest::try_from)
            .collect::<Result<Vec<_>, RouteMatchError>>()?;

        let policy = {
            let filters = proto
                .filters
                .into_iter()
                .map(|f| match f.kind.ok_or(Error::MissingFilter)? {
                    filter::Kind::RequestHeaderModifier(rhm) => {
                        Ok(RouteFilter::RequestHeaders(rhm.try_into()?))
                    }
                    filter::Kind::RequestRedirect(rr) => Ok(RouteFilter::Redirect(rr.try_into()?)),
                })
                .collect::<Result<Vec<_>, Error>>()?;
            RoutePolicy {
                authorizations,
                filters,
                labels,
            }
        };

        Ok(HttpRule { matches, policy })
    }
}
