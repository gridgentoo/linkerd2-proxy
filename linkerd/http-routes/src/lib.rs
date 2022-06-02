pub mod filter;
pub mod r#match;
pub mod service;

use self::r#match::{HostMatch, PathMatch, RequestMatch};
pub use self::{
    filter::Filter,
    r#match::{MatchHost, MatchRequest},
};
use std::{collections::BTreeMap, sync::Arc};

#[cfg(feature = "inbound")]
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct InboundRoutes(pub Vec<InboundRoute>);

#[cfg(feature = "outbound")]
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct OutboundRoutes(pub Vec<OutboundRoute>);

#[cfg(feature = "inbound")]
#[derive(Clone, Debug, Default, Hash, PartialEq)]
pub struct InboundRoute {
    pub hosts: Vec<MatchHost>,
    pub rules: Vec<InboundRule>,
    pub labels: RouteLabels,
    // TODO Authorizations (inbound)
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct InboundAuthorization {
    pub kind: String,
    pub name: String,
    pub required_authentications: Vec<RequiredAuthentication>,
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub enum RequiredAuthentication {
    Networks(Vec<Network>),
    MeshTLSIdentities(Vec<MeshTLSIdentity>),
    MeshTLS,
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Network {
    // pub network: IpNet,
// pub except: IpNet,
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub enum MeshTLSIdentity {
    Exact(String),
    Suffix(Vec<String>),
}

#[cfg(feature = "inbound")]
#[derive(Clone, Debug, Default, Hash, PartialEq)]
pub struct InboundRule {
    pub matches: Vec<MatchRequest>,
    pub filters: Vec<Filter>,
}

#[cfg(feature = "outbound")]
#[derive(Clone, Debug, Default, Hash, PartialEq)]
pub struct OutboundRoute {
    pub hosts: Vec<MatchHost>,
    pub rules: Vec<OutboundRule>,
    pub labels: RouteLabels,
}

#[derive(Clone, Debug, Default, Hash, PartialEq)]
pub struct RouteLabels(Arc<BTreeMap<String, String>>);

#[cfg(feature = "outbound")]
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct OutboundRule {
    pub matches: Vec<MatchRequest>,
    pub filters: Vec<Filter>,
    pub backends: Vec<Backend>,
}

#[cfg(feature = "outbound")]
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct Backend {
    pub filters: Vec<Filter>,
    pub coordinate: BackendCoordinate,
}

#[cfg(feature = "outbound")]
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct BackendCoordinate(String);

#[cfg(feature = "inbound")]
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct InboundRouteMatch<'r> {
    r#match: RouteMatch,
    route: &'r InboundRoute,
    rule: &'r InboundRule,
}

#[cfg(feature = "outbound")]
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct OutboundRouteMatch<'r> {
    r#match: RouteMatch,
    route: &'r OutboundRoute,
    rule: &'r OutboundRule,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RouteMatch {
    host: Option<HostMatch>,
    rule: RequestMatch,
}

// === impl InboundRoutes ===

#[cfg(feature = "inbound")]
impl InboundRoutes {
    pub(crate) fn find_route<B>(&self, req: &http::Request<B>) -> Option<InboundRouteMatch<'_>> {
        self.0
            .iter()
            .filter_map(|rt| rt.find_rule(req))
            // This is roughly equivalent to `max_by(...)` but we want to ensure
            // that the first match wins.
            .reduce(|l, r| if l.r#match < r.r#match { r } else { l })
    }
}

// === impl InboundRoute ===

#[cfg(feature = "inbound")]
impl InboundRoute {
    pub(crate) fn find_rule<B>(&self, req: &http::Request<B>) -> Option<InboundRouteMatch<'_>> {
        RouteMatch::find(req, &*self.hosts, self.rules.iter().map(|r| &*r.matches)).map(
            |(idx, r#match)| InboundRouteMatch {
                r#match,
                route: self,
                rule: &self.rules[idx],
            },
        )
    }
}

// === impl OutboundRoutes ===

#[cfg(feature = "outbound")]
impl OutboundRoutes {
    pub fn find_route<B>(&self, req: &http::Request<B>) -> Option<OutboundRouteMatch<'_>> {
        self.0
            .iter()
            .filter_map(|rt| rt.find_rule(req))
            // This is roughly equivalent to `max_by(...)` but we want to ensure
            // that the first match wins.
            .reduce(|l, r| if l.r#match < r.r#match { r } else { l })
    }
}

// === impl OutboundRoute ===

#[cfg(feature = "outbound")]
impl OutboundRoute {
    pub fn find_rule<B>(&self, req: &http::Request<B>) -> Option<OutboundRouteMatch<'_>> {
        RouteMatch::find(req, &*self.hosts, self.rules.iter().map(|r| &*r.matches)).map(
            |(idx, r#match)| OutboundRouteMatch {
                r#match,
                route: self,
                rule: &self.rules[idx],
            },
        )
    }
}

// === impl RouteMatch ===

impl AsRef<RouteMatch> for InboundRouteMatch<'_> {
    fn as_ref(&self) -> &RouteMatch {
        &self.r#match
    }
}

impl AsRef<RouteMatch> for OutboundRouteMatch<'_> {
    fn as_ref(&self) -> &RouteMatch {
        &self.r#match
    }
}

impl RouteMatch {
    fn find<'r, B>(
        req: &http::Request<B>,
        hosts: &[MatchHost],
        rules: impl Iterator<Item = &'r [MatchRequest]>,
    ) -> Option<(usize, Self)> {
        let host = if hosts.is_empty() {
            None
        } else {
            let uri = req.uri();
            let hm = hosts.iter().filter_map(|a| a.summarize_match(uri)).max()?;
            Some(hm)
        };

        rules
            .enumerate()
            .filter_map(|(idx, matches)| {
                // If there are no matches in the list, then the rule has an
                // implicit default match.
                if matches.is_empty() {
                    return Some((idx, RequestMatch::default()));
                }
                // The order of request matches doesn't matter but we need to
                // find the best match to compare against other rules/routes.
                let summaries = matches.iter().filter_map(|m| m.summarize_match(req));
                summaries.max().map(|s| (idx, s))
            })
            // This is roughly equivalent to `max_by(...)` but we want to ensure
            // that the first match wins.
            .reduce(|(i0, r0), (i, r)| if r0 < r { (i, r) } else { (i0, r0) })
            .map(move |(i, rule)| (i, RouteMatch { host, rule }))
    }
}

impl std::cmp::PartialOrd for RouteMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for RouteMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self.host.cmp(&other.host) {
            Ordering::Equal => self.rule.cmp(&other.rule),
            ord => ord,
        }
    }
}

// === impl RouteLabels ===

impl From<BTreeMap<String, String>> for RouteLabels {
    fn from(labels: BTreeMap<String, String>) -> Self {
        RouteLabels(Arc::new(labels))
    }
}

#[cfg(test)]
mod tests {
    use super::{r#match::*, *};

    #[test]
    fn inbound_find_route_hostname_precedence() {
        // Given two equivalent routes, choose the explicit hostname match and
        // not the wildcard.
        let rts = InboundRoutes(vec![
            InboundRoute {
                hosts: vec!["*.example.com".parse().unwrap()],
                rules: vec![InboundRule {
                    matches: vec![MatchRequest {
                        path: Some(MatchPath::Exact("/foo".to_string())),
                        ..MatchRequest::default()
                    }],
                    ..InboundRule::default()
                }],
                ..InboundRoute::default()
            },
            InboundRoute {
                hosts: vec!["foo.example.com".parse().unwrap()],
                rules: vec![InboundRule {
                    matches: vec![MatchRequest {
                        path: Some(MatchPath::Exact("/foo".to_string())),
                        ..MatchRequest::default()
                    }],
                    ..InboundRule::default()
                }],
                labels: RouteLabels::from(maplit::btreemap! {
                    "expected".to_string() => "".to_string(),
                }),
            },
        ]);

        let req = http::Request::builder()
            .uri("http://foo.example.com/foo")
            .body(())
            .unwrap();
        let m = rts.find_route(&req).expect("must match");
        assert!(
            m.route.labels.0.contains_key("expected"),
            "incorrect rule matched"
        );
    }

    #[test]
    fn inbound_find_route_path_length_precedence() {
        // Given two equivalent routes, choose the longer path match.
        let rts = InboundRoutes(vec![
            InboundRoute {
                rules: vec![InboundRule {
                    matches: vec![MatchRequest {
                        path: Some(MatchPath::Prefix("/foo".to_string())),
                        ..MatchRequest::default()
                    }],
                    ..InboundRule::default()
                }],
                ..InboundRoute::default()
            },
            InboundRoute {
                rules: vec![InboundRule {
                    matches: vec![MatchRequest {
                        path: Some(MatchPath::Exact("/foo/bar".to_string())),
                        ..MatchRequest::default()
                    }],
                    ..InboundRule::default()
                }],
                labels: RouteLabels::from(maplit::btreemap! {
                    "expected".to_string() => "".to_string(),
                }),
                ..InboundRoute::default()
            },
        ]);

        let req = http::Request::builder()
            .uri("http://foo.example.com/foo/bar")
            .body(())
            .unwrap();
        let m = rts.find_route(&req).expect("must match");
        assert!(
            m.route.labels.0.contains_key("expected"),
            "incorrect rule matched"
        );
    }

    #[test]
    fn inbound_find_route_header_count_precedence() {
        // Given two routes with header matches, use the one that matches more
        // headers.
        let rts = InboundRoutes(vec![
            InboundRoute {
                rules: vec![InboundRule {
                    matches: vec![MatchRequest {
                        headers: vec![
                            MatchHeader::Exact("x-foo".parse().unwrap(), "bar".parse().unwrap()),
                            MatchHeader::Exact("x-baz".parse().unwrap(), "qux".parse().unwrap()),
                        ],
                        ..MatchRequest::default()
                    }],
                    ..InboundRule::default()
                }],
                ..InboundRoute::default()
            },
            InboundRoute {
                rules: vec![InboundRule {
                    matches: vec![MatchRequest {
                        headers: vec![
                            MatchHeader::Exact("x-foo".parse().unwrap(), "bar".parse().unwrap()),
                            MatchHeader::Exact("x-baz".parse().unwrap(), "qux".parse().unwrap()),
                            MatchHeader::Exact("x-biz".parse().unwrap(), "qyx".parse().unwrap()),
                        ],
                        ..MatchRequest::default()
                    }],
                    ..InboundRule::default()
                }],
                labels: RouteLabels::from(maplit::btreemap! {
                    "expected".to_string() => "".to_string(),
                }),
                ..InboundRoute::default()
            },
        ]);

        let req = http::Request::builder()
            .uri("http://www.example.com")
            .header("x-foo", "bar")
            .header("x-baz", "qux")
            .header("x-biz", "qyx")
            .body(())
            .unwrap();
        let m = rts.find_route(&req).expect("must match");
        assert!(
            m.route.labels.0.contains_key("expected"),
            "incorrect rule matched"
        );
    }

    #[test]
    fn inbound_find_route_first_identical_wins() {
        // Given two routes with header matches, use the one that matches more
        // headers.
        let rts = InboundRoutes(vec![
            InboundRoute {
                rules: vec![
                    InboundRule {
                        filters: vec![Filter::ModifyRequestHeader(
                            filter::ModifyRequestHeader::default(),
                        )],
                        ..InboundRule::default()
                    },
                    // Redundant unlabeled rule.
                    InboundRule::default(),
                ],
                ..InboundRoute::default()
            },
            // Redundant unlabeled route.
            InboundRoute {
                rules: vec![InboundRule::default()],
                ..InboundRoute::default()
            },
        ]);

        let m = rts
            .find_route(&http::Request::builder().body(()).unwrap())
            .expect("must match");
        assert!(!m.rule.filters.is_empty(), "incorrect rule matched");
    }
}
