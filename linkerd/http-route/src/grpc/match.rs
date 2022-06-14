use crate::http::MatchHeader;

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct MatchRoute {
    pub(crate) rpc: MatchRpc,
    pub(crate) headers: Vec<MatchHeader>,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct RouteMatch {
    rpc: RpcMatch,
    headers: usize,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MatchRpc {
    pub(crate) service: Option<String>,
    pub(crate) method: Option<String>,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RpcMatch {
    service: usize,
    method: usize,
}

// === impl MatchRoute ===

impl crate::Match for MatchRoute {
    type Summary = RouteMatch;

    fn r#match<B>(&self, req: &http::Request<B>) -> Option<RouteMatch> {
        if req.method() != http::Method::POST {
            return None;
        }

        let rpc = self.rpc.match_length(req.uri().path())?;

        let headers = {
            if !self.headers.iter().all(|h| h.is_match(req.headers())) {
                return None;
            }
            self.headers.len()
        };

        Some(RouteMatch { rpc, headers })
    }
}

// === impl RouteMatch ===

impl std::cmp::PartialOrd for RouteMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for RouteMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self.rpc.cmp(&other.rpc) {
            Ordering::Equal => self.headers.cmp(&other.headers),
            ord => ord,
        }
    }
}

// === impl MatchRpc ===

impl MatchRpc {
    fn match_length(&self, path: &str) -> Option<RpcMatch> {
        let mut summary = RpcMatch::default();

        let mut parts = path.split('/');
        if !parts.next()?.is_empty() {
            return None;
        }

        let service = parts.next()?;
        if let Some(s) = &self.service {
            if s != service {
                return None;
            }
            summary.service = s.len();
        }

        let method = parts.next()?;
        if let Some(m) = &self.method {
            if m != method {
                return None;
            }
            summary.method = m.len();
        }

        Some(summary)
    }
}

#[cfg(feature = "proto")]
pub mod proto {
    use crate::http::r#match::header::proto::HeaderMatchError;

    use super::*;
    use linkerd2_proxy_api::grpc_route as api;

    #[derive(Debug, thiserror::Error)]
    pub enum InvalidRouteMatch {
        #[error("invalid RPC match: {0}")]
        Rpc(#[from] InvalidRpcMatch),

        #[error("invalid header match: {0}")]
        Header(#[from] HeaderMatchError),

        #[error("missing RPC match")]
        MissingRpc,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum InvalidRpcMatch {}

    impl TryFrom<api::GrpcRouteMatch> for MatchRoute {
        type Error = InvalidRouteMatch;

        fn try_from(pb: api::GrpcRouteMatch) -> Result<Self, Self::Error> {
            Ok(MatchRoute {
                rpc: pb.rpc.ok_or(InvalidRouteMatch::MissingRpc)?.try_into()?,
                headers: pb
                    .headers
                    .into_iter()
                    .map(MatchHeader::try_from)
                    .collect::<Result<Vec<_>, HeaderMatchError>>()?,
            })
        }
    }
    impl TryFrom<api::GrpcRpcMatch> for MatchRpc {
        type Error = InvalidRpcMatch;

        fn try_from(pb: api::GrpcRpcMatch) -> Result<Self, Self::Error> {
            Ok(MatchRpc {
                service: if pb.service.is_empty() {
                    None
                } else {
                    Some(pb.service)
                },
                method: if pb.method.is_empty() {
                    None
                } else {
                    Some(pb.method)
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Match;
    use http::header::{HeaderName, HeaderValue};

    // Empty matches apply to all requests.
    #[test]
    fn empty_match() {
        let m = MatchRoute::default();

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo/bar")
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), Some(RouteMatch::default()));

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo")
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), None);
    }

    #[test]
    fn method() {
        let m = MatchRoute {
            rpc: MatchRpc {
                service: None,
                method: Some("bar".to_string()),
            },
            ..MatchRoute::default()
        };

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo/bar")
            .body(())
            .unwrap();
        assert_eq!(
            m.r#match(&req),
            Some(RouteMatch {
                rpc: RpcMatch {
                    service: 0,
                    method: 3
                },
                ..Default::default()
            })
        );

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/foo/bah")
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), None);
    }

    #[test]
    fn headers() {
        let m = MatchRoute {
            headers: vec![
                MatchHeader::Exact(
                    HeaderName::from_static("x-foo"),
                    HeaderValue::from_static("bar"),
                ),
                MatchHeader::Regex(HeaderName::from_static("x-baz"), "qu+x".parse().unwrap()),
            ],
            ..MatchRoute::default()
        };

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo")
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), None);

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/")
            .header("x-foo", "bar")
            .header("x-baz", "zab") // invalid header value
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), None);

        // Regex matches apply
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/foo/bar")
            .header("x-foo", "bar")
            .header("x-baz", "quuuux")
            .body(())
            .unwrap();
        assert_eq!(
            m.r#match(&req),
            Some(RouteMatch {
                headers: 2,
                ..RouteMatch::default()
            })
        );

        // Regex must be anchored.
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/foo/bar")
            .header("x-foo", "bar")
            .header("x-baz", "quxa")
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), None);
    }

    #[test]
    fn http_method() {
        let m = MatchRoute {
            rpc: MatchRpc {
                service: Some("foo".to_string()),
                method: Some("bar".to_string()),
            },
            headers: vec![],
        };

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo/bar")
            .body(())
            .unwrap();
        assert_eq!(
            m.r#match(&req),
            Some(RouteMatch {
                rpc: RpcMatch {
                    service: 3,
                    method: 3,
                },
                headers: 0,
            })
        );

        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri("http://example.com/foo/bar")
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), None);
    }

    #[test]
    fn multiple() {
        let m = MatchRoute {
            rpc: MatchRpc {
                service: Some("foo".to_string()),
                method: Some("bar".to_string()),
            },
            headers: vec![MatchHeader::Exact(
                HeaderName::from_static("x-foo"),
                HeaderValue::from_static("bar"),
            )],
        };

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/foo/bar")
            .header("x-foo", "bar")
            .body(())
            .unwrap();
        assert_eq!(
            m.r#match(&req),
            Some(RouteMatch {
                rpc: RpcMatch {
                    service: 3,
                    method: 3
                },
                headers: 1
            })
        );

        // One invalid field (header) invalidates the match.
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/foo/bar")
            .header("x-foo", "bah")
            .body(())
            .unwrap();
        assert_eq!(m.r#match(&req), None);
    }
}
