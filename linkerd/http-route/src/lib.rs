#![deny(rust_2018_idioms, clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]

pub mod grpc;
pub mod http;

pub use self::http::{HostMatch, MatchHeader, MatchHost};

pub trait Match {
    type Summary: Default + Ord;

    fn r#match<B>(&self, req: &::http::Request<B>) -> Option<Self::Summary>;
}

/*
pub trait Policy {
    type Error;

    fn apply<B>(&self, req: &mut ::http::Request<B>) -> Result<(), Self::Error>;
}
 */

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Route<M, P> {
    pub hosts: Vec<http::MatchHost>,
    pub rules: Vec<Rule<M, P>>,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct Rule<M, P> {
    pub matches: Vec<M>,
    pub policy: P,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteMatch<T> {
    host: Option<http::HostMatch>,
    route: T,
}

fn find<'r, M: Match + 'r, P, B>(
    routes: impl IntoIterator<Item = &'r Route<M, P>>,
    req: &::http::Request<B>,
) -> Option<(RouteMatch<M::Summary>, &'r P)> {
    routes
        .into_iter()
        .filter_map(|rt| {
            let host = if rt.hosts.is_empty() {
                None
            } else {
                let uri = req.uri();
                let hm = rt
                    .hosts
                    .iter()
                    .filter_map(|a| a.summarize_match(uri))
                    .max()?;
                Some(hm)
            };

            let (route, policy) = rt
                .rules
                .iter()
                .filter_map(|rule| {
                    // If there are no matches in the list, then the rule has an
                    // implicit default match.
                    if rule.matches.is_empty() {
                        return Some((M::Summary::default(), &rule.policy));
                    }
                    // Find the best match to compare against other rules/routes
                    // (if any apply). The order/precedence of matche is not
                    // relevant.
                    let summary = rule.matches.iter().filter_map(|m| m.r#match(req)).max()?;
                    Some((summary, &rule.policy))
                })
                // This is roughly equivalent to `max_by(...)` but we want to
                // ensure that the first match wins.
                .reduce(|(m0, p0), (m, p)| if m0 < m { (m, p) } else { (m0, p0) })?;

            Some((RouteMatch { host, route }, policy))
        })
        // This is roughly equivalent to `max_by(...)` but we want to ensure
        // that the first match wins.
        .reduce(|(m0, t0), (m, t)| if m0 < m { (m, t) } else { (m0, t0) })
}
