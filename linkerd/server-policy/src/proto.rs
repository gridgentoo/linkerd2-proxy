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
