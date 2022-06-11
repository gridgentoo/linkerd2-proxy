#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

pub mod filter;
mod r#match;
#[cfg(feature = "proto")]
pub mod proto;

pub use self::r#match::MatchRequest;
use self::r#match::RequestMatch;
pub use linkerd_http_route::{HostMatch, MatchHost};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct GrpcRoute<T> {
    pub hosts: Vec<MatchHost>,
    pub rules: Vec<GrpcRule<T>>,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct GrpcRule<T> {
    pub matches: Vec<MatchRequest>,
    pub policy: T,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrpcRouteMatch {
    host: Option<HostMatch>,
    request: RequestMatch,
}

pub fn find<'t, T, B>(
    routes: impl IntoIterator<Item = &'t GrpcRoute<T>>,
    req: &http::Request<B>,
) -> Option<(GrpcRouteMatch, &'t T)> {
    routes
        .into_iter()
        .filter_map(|rt| rt.find(req))
        // This is roughly equivalent to `max_by(...)` but we want to ensure
        // that the first match wins.
        .reduce(|(m0, t0), (m, t)| if m0 < m { (m, t) } else { (m0, t0) })
}

// === impl GrpcRoute ===

impl<T> GrpcRoute<T> {
    fn find<B>(&self, req: &http::Request<B>) -> Option<(GrpcRouteMatch, &T)> {
        let host = if self.hosts.is_empty() {
            None
        } else {
            let uri = req.uri();
            let hm = self
                .hosts
                .iter()
                .filter_map(|a| a.summarize_match(uri))
                .max()?;
            Some(hm)
        };

        let (request, policy) = self
            .rules
            .iter()
            .filter_map(|rule| {
                // If there are no matches in the list, then the rule has an
                // implicit default match.
                if rule.matches.is_empty() {
                    return Some((RequestMatch::default(), &rule.policy));
                }
                // Find the best match to compare against other rules/routes (if
                // any apply). The order/precedence of matche is not relevant.
                let m = rule
                    .matches
                    .iter()
                    .filter_map(|m| m.summarize_match(req))
                    .max()?;
                Some((m, &rule.policy))
            })
            // This is roughly equivalent to `max_by(...)` but we want to ensure
            // that the first match wins.
            .reduce(|(m0, p0), (m, p)| if m0 < m { (m, p) } else { (m0, p0) })?;

        Some((GrpcRouteMatch { host, request }, policy))
    }
}

#[cfg(test)]
mod tests {
    use super::{r#match::*, *};
    use linkerd_http_route::MatchHeader;

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum Policy {
        Expected,
        Unexpected,
    }

    impl Default for Policy {
        fn default() -> Self {
            Self::Unexpected
        }
    }

    /// Given two equivalent routes, choose the explicit hostname match and not
    /// the wildcard.
    #[test]
    fn hostname_precedence() {
        let rts = vec![
            GrpcRoute {
                hosts: vec!["*.example.com".parse().unwrap()],
                rules: vec![GrpcRule {
                    matches: vec![MatchRequest {
                        rpc: MatchRpc {
                            service: Some("foo".to_string()),
                            method: Some("bar".to_string()),
                        },
                        ..MatchRequest::default()
                    }],
                    ..GrpcRule::default()
                }],
            },
            GrpcRoute {
                hosts: vec!["foo.example.com".parse().unwrap()],
                rules: vec![GrpcRule {
                    matches: vec![MatchRequest {
                        rpc: MatchRpc {
                            service: Some("foo".to_string()),
                            method: Some("bar".to_string()),
                        },
                        ..MatchRequest::default()
                    }],
                    policy: Policy::Expected,
                }],
            },
        ];

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://foo.example.com/foo/bar")
            .body(())
            .unwrap();
        let (_, policy) = find(&rts, &req).expect("must match");
        assert_eq!(*policy, Policy::Expected, "incorrect rule matched");
    }

    #[test]
    fn method_precedence() {
        // Given two equivalent routes, choose the longer path match.
        let rts = vec![
            GrpcRoute {
                rules: vec![GrpcRule {
                    matches: vec![MatchRequest {
                        rpc: MatchRpc {
                            service: Some("foo".to_string()),
                            method: None,
                        },
                        ..MatchRequest::default()
                    }],
                    ..GrpcRule::default()
                }],
                hosts: vec![],
            },
            GrpcRoute {
                rules: vec![GrpcRule {
                    matches: vec![MatchRequest {
                        rpc: MatchRpc {
                            service: Some("foo".to_string()),
                            method: Some("bar".to_string()),
                        },
                        ..MatchRequest::default()
                    }],
                    policy: Policy::Expected,
                }],
                hosts: vec![],
            },
        ];

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://foo.example.com/foo/bar")
            .body(())
            .unwrap();
        let (_, policy) = find(&rts, &req).expect("must match");
        assert_eq!(*policy, Policy::Expected, "incorrect rule matched");
    }

    /// Given two routes with header matches, use the one that matches more
    /// headers.
    #[test]
    fn header_count_precedence() {
        let rts = vec![
            GrpcRoute {
                rules: vec![GrpcRule {
                    matches: vec![MatchRequest {
                        headers: vec![
                            MatchHeader::Exact("x-foo".parse().unwrap(), "bar".parse().unwrap()),
                            MatchHeader::Exact("x-baz".parse().unwrap(), "qux".parse().unwrap()),
                        ],
                        ..MatchRequest::default()
                    }],
                    ..GrpcRule::default()
                }],
                hosts: vec![],
            },
            GrpcRoute {
                rules: vec![GrpcRule {
                    matches: vec![MatchRequest {
                        headers: vec![
                            MatchHeader::Exact("x-foo".parse().unwrap(), "bar".parse().unwrap()),
                            MatchHeader::Exact("x-baz".parse().unwrap(), "qux".parse().unwrap()),
                            MatchHeader::Exact("x-biz".parse().unwrap(), "qyx".parse().unwrap()),
                        ],
                        ..MatchRequest::default()
                    }],
                    policy: Policy::Expected,
                }],
                hosts: vec![],
            },
        ];

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://www.example.com/foo/bar")
            .header("x-foo", "bar")
            .header("x-baz", "qux")
            .header("x-biz", "qyx")
            .body(())
            .unwrap();
        let (_, policy) = find(&rts, &req).expect("must match");
        assert_eq!(*policy, Policy::Expected, "incorrect rule matched");
    }

    /// Given two routes with header matches, use the one that matches more
    /// headers.
    #[test]
    fn first_identical_wins() {
        let rts = vec![
            GrpcRoute {
                rules: vec![
                    GrpcRule {
                        policy: Policy::Expected,
                        ..GrpcRule::default()
                    },
                    // Redundant rule.
                    GrpcRule::default(),
                ],
                hosts: vec![],
            },
            // Redundant route.
            GrpcRoute {
                rules: vec![GrpcRule::default()],
                hosts: vec![],
            },
        ];

        let req = http::Request::builder().body(()).unwrap();
        let (_, policy) = find(&rts, &req).expect("must match");
        assert_eq!(*policy, Policy::Expected, "incorrect rule matched");
    }
}
