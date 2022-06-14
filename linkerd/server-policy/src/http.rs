use linkerd_http_route::http;
pub use linkerd_http_route::http::{filter, r#match};

pub type Policy = crate::RoutePolicy<Filter>;
pub type Route = http::Route<Policy>;
pub type Rule = http::Rule<Policy>;

#[inline]
pub fn find<'r, B>(
    routes: impl IntoIterator<Item = &'r Route>,
    req: &::http::Request<B>,
) -> Option<(http::RouteMatch, &'r Policy)> {
    http::find(routes, req)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Filter {
    Error(http::filter::RespondWithError),

    RequestHeaders(http::filter::ModifyRequestHeader),

    Redirect(http::filter::RedirectRequest),

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
    use linkerd_http_route::http::{
        filter::{
            error_respond::proto::ErrorResponderError,
            modify_request_header::proto::RequestHeaderModifierError,
            redirect::proto::RequestRedirectError,
        },
        r#match::{host::proto::HostMatchError, proto::RouteMatchError},
    };
    use std::sync::Arc;

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

    pub fn try_route(proto: api::HttpRoute) -> Result<Route, InvalidHttpRoute> {
        let api::HttpRoute {
            hosts,
            authorizations,
            rules,
            metadata,
        } = proto;

        let hosts = hosts
            .into_iter()
            .map(r#match::MatchHost::try_from)
            .collect::<Result<Vec<_>, HostMatchError>>()?;

        let authzs = authz::proto::mk_authorizations(authorizations)?;
        let meta = Arc::new(Meta::try_from(metadata.ok_or(InvalidMeta::Missing)?)?);
        let rules = rules
            .into_iter()
            .map(|r| try_rule(authzs.clone(), meta.clone(), r))
            .collect::<Result<Vec<_>, InvalidHttpRoute>>()?;

        Ok(Route { hosts, rules })
    }

    fn try_rule(
        authorizations: Arc<[authz::Authorization]>,
        meta: Arc<Meta>,
        proto: api::http_route::Rule,
    ) -> Result<Rule, InvalidHttpRoute> {
        let matches = proto
            .matches
            .into_iter()
            .map(r#match::MatchRequest::try_from)
            .collect::<Result<Vec<_>, RouteMatchError>>()?;

        let policy = {
            use api::http_route::filter;

            let filters = proto
                .filters
                .into_iter()
                .map(|f| match f.kind {
                    Some(filter::Kind::RequestHeaderModifier(rhm)) => {
                        Ok(Filter::RequestHeaders(rhm.try_into()?))
                    }
                    Some(filter::Kind::Redirect(rr)) => Ok(Filter::Redirect(rr.try_into()?)),
                    Some(filter::Kind::Error(rsp)) => Ok(Filter::Error(rsp.try_into()?)),
                    None => Ok(Filter::Unknown),
                })
                .collect::<Result<Vec<_>, InvalidHttpRoute>>()?;

            crate::RoutePolicy {
                authorizations,
                filters,
                meta,
            }
        };

        Ok(Rule { matches, policy })
    }
}
