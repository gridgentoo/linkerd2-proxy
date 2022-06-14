pub use linkerd_http_route::grpc::{filter, r#match};
use linkerd_http_route::{grpc, http};

pub type Policy = crate::RoutePolicy<Filter>;
pub type Route = grpc::Route<Policy>;
pub type Rule = grpc::Rule<Policy>;

#[inline]
pub fn find<'r, B>(
    routes: impl IntoIterator<Item = &'r Route>,
    req: &::http::Request<B>,
) -> Option<(grpc::RouteMatch, &'r Policy)> {
    grpc::find(routes, req)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Filter {
    Error(grpc::filter::RespondWithError),

    RequestHeaders(http::filter::ModifyRequestHeader),

    /// Indicates that the filter kind is unknown to the proxy (e.g., because
    /// the controller is on a new version of the protobuf).
    ///
    /// Route handlers must be careful about this situation, as it may not be
    /// appropriate for a proxy to skip filtering logic.
    Unknown,
}

#[cfg(feature = "proto")]
pub mod proto {
    use super::*;
    use crate::{
        authz::{self, proto::InvalidAuthz},
        proto::InvalidMeta,
        Meta,
    };
    use linkerd2_proxy_api::inbound as api;
    use linkerd_http_route::{
        grpc::{
            filter::error_respond::proto::ErrorResponderError, r#match::proto::InvalidRouteMatch,
        },
        http::{
            filter::modify_request_header::proto::RequestHeaderModifierError,
            r#match::host::proto::HostMatchError,
        },
    };
    use std::sync::Arc;

    #[derive(Debug, thiserror::Error)]
    pub enum InvalidGrpcRoute {
        #[error("invalid host match: {0}")]
        HostMatch(#[from] HostMatchError),

        #[error("invalid route match: {0}")]
        RouteMatch(#[from] InvalidRouteMatch),

        #[error("invalid request header modifier: {0}")]
        RequestHeaderModifier(#[from] RequestHeaderModifierError),

        #[error("invalid error responder: {0}")]
        ErrorRespnder(#[from] ErrorResponderError),

        #[error("invalid authorization: {0}")]
        Authz(#[from] InvalidAuthz),

        #[error("invalid metadata: {0}")]
        Meta(#[from] InvalidMeta),
    }

    pub fn try_route(proto: api::GrpcRoute) -> Result<Route, InvalidGrpcRoute> {
        let api::GrpcRoute {
            hosts,
            authorizations,
            rules,
            metadata,
        } = proto;

        let hosts = hosts
            .into_iter()
            .map(http::r#match::MatchHost::try_from)
            .collect::<Result<Vec<_>, HostMatchError>>()?;

        let authzs = authz::proto::mk_authorizations(authorizations)?;
        let meta = Arc::new(Meta::try_from(metadata.ok_or(InvalidMeta::Missing)?)?);
        let rules = rules
            .into_iter()
            .map(|r| try_rule(authzs.clone(), meta.clone(), r))
            .collect::<Result<Vec<_>, InvalidGrpcRoute>>()?;

        Ok(Route { hosts, rules })
    }

    fn try_rule(
        authorizations: Arc<[authz::Authorization]>,
        meta: Arc<Meta>,
        proto: api::grpc_route::Rule,
    ) -> Result<Rule, InvalidGrpcRoute> {
        let matches = proto
            .matches
            .into_iter()
            .map(r#match::MatchRoute::try_from)
            .collect::<Result<Vec<_>, InvalidRouteMatch>>()?;

        let policy = {
            use api::grpc_route::filter;

            let filters = proto
                .filters
                .into_iter()
                .map(|f| match f.kind {
                    Some(filter::Kind::Error(rsp)) => Ok(Filter::Error(rsp.try_into()?)),
                    Some(filter::Kind::RequestHeaderModifier(rhm)) => {
                        Ok(Filter::RequestHeaders(rhm.try_into()?))
                    }
                    None => Ok(Filter::Unknown),
                })
                .collect::<Result<Vec<_>, InvalidGrpcRoute>>()?;

            crate::RoutePolicy {
                authorizations,
                filters,
                meta,
            }
        };

        Ok(Rule { matches, policy })
    }
}
