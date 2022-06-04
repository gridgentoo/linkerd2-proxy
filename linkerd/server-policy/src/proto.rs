use crate::*;
use ipnet::IpNet;
use linkerd2_proxy_api::{inbound as api, net::InvalidIpNetwork};
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
}

impl TryFrom<api::Server> for ServerPolicy {
    type Error = Error;

    fn try_from(proto: api::Server) -> Result<ServerPolicy, Self::Error> {
        let protocol = match proto.protocol {
            Some(api::ProxyProtocol { kind: Some(k) }) => match k {
                api::proxy_protocol::Kind::Detect(api::proxy_protocol::Detect { timeout }) => {
                    Protocol::Detect {
                        timeout: timeout
                            .ok_or(Error::MissingDetectTimeout)?
                            .try_into()
                            .map_err(Error::NegativeDetectTimeout)?,
                        http: Default::default(),
                    }
                }
                api::proxy_protocol::Kind::Http1(_) => Protocol::Http1(Default::default()),
                api::proxy_protocol::Kind::Http2(_) => Protocol::Http2(Default::default()),
                api::proxy_protocol::Kind::Grpc(_) => Protocol::Grpc {
                    disable_info_headers: false,
                },
                api::proxy_protocol::Kind::Opaque(_) => Protocol::Opaque,
                api::proxy_protocol::Kind::Tls(_) => Protocol::Tls,
            },
            _ => return Err(Error::MissingProxyProtocol),
        };

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

        let authorizations = proto
            .authorizations
            .into_iter()
            .map(|authz| {
                let api::Authz {
                    labels,
                    authentication,
                    networks,
                } = authz;

                if networks.is_empty() {
                    return Err(Error::MissingNetworks);
                }
                let networks = networks
                    .into_iter()
                    .map(|api::Network { net, except }| {
                        let net = net.ok_or(Error::MissingNetworks)?.try_into()?;
                        let except = except
                            .into_iter()
                            .map(|net| net.try_into())
                            .collect::<Result<Vec<IpNet>, _>>()?;
                        Ok(Network { net, except })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                let authn = match authentication.and_then(|api::Authn { permit }| permit) {
                    Some(api::authn::Permit::Unauthenticated(_)) => Authentication::Unauthenticated,
                    Some(api::authn::Permit::MeshTls(api::authn::PermitMeshTls { clients })) => {
                        match clients {
                            Some(api::authn::permit_mesh_tls::Clients::Unauthenticated(_)) => {
                                Authentication::TlsUnauthenticated
                            }
                            Some(api::authn::permit_mesh_tls::Clients::Identities(
                                api::authn::permit_mesh_tls::PermitClientIdentities {
                                    identities,
                                    suffixes,
                                },
                            )) => Authentication::TlsAuthenticated {
                                identities: identities
                                    .into_iter()
                                    .map(|api::Identity { name }| name)
                                    .collect(),
                                suffixes: suffixes
                                    .into_iter()
                                    .map(|api::IdentitySuffix { parts }| Suffix::from(parts))
                                    .collect(),
                            },
                            None => return Err(Error::MissingClients),
                        }
                    }
                    _ => return Err(Error::InvalidAuthentication),
                };

                let (kind, name) = kind_name(&labels, "serverauthorization")?;
                Ok(Authorization {
                    networks,
                    authentication: authn,
                    kind,
                    name,
                })
            })
            .chain(Some(Ok(loopback)))
            .collect::<Result<Vec<_>, Error>>()?;

        let (kind, name) = kind_name(&proto.labels, "server")?;
        Ok(ServerPolicy {
            protocol,
            authorizations,
            kind,
            name,
        })
    }
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
