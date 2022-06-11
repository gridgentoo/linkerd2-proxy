use linkerd_http_route::MatchHeader;

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct MatchRequest {
    pub(crate) rpc: MatchRpc,
    pub(crate) headers: Vec<MatchHeader>,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub(crate) struct RequestMatch {
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

// === impl MatchRequest ===

impl MatchRequest {
    pub(crate) fn summarize_match<B>(&self, req: &http::Request<B>) -> Option<RequestMatch> {
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

        Some(RequestMatch { rpc, headers })
    }
}

// === impl RequestMatch ===

impl std::cmp::PartialOrd for RequestMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for RequestMatch {
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderName, HeaderValue};

    // Empty matches apply to all requests.
    #[test]
    fn empty_match() {
        let m = MatchRequest::default();

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo/bar")
            .body(())
            .unwrap();
        assert_eq!(m.summarize_match(&req), Some(RequestMatch::default()));

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo")
            .body(())
            .unwrap();
        assert_eq!(m.summarize_match(&req), None);
    }

    #[test]
    fn method() {
        let m = MatchRequest {
            rpc: MatchRpc {
                service: None,
                method: Some("bar".to_string()),
            },
            ..MatchRequest::default()
        };

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo/bar")
            .body(())
            .unwrap();
        assert_eq!(
            m.summarize_match(&req),
            Some(RequestMatch {
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
        assert_eq!(m.summarize_match(&req), None);
    }

    #[test]
    fn headers() {
        let m = MatchRequest {
            headers: vec![
                MatchHeader::Exact(
                    HeaderName::from_static("x-foo"),
                    HeaderValue::from_static("bar"),
                ),
                MatchHeader::Regex(HeaderName::from_static("x-baz"), "qu+x".parse().unwrap()),
            ],
            ..MatchRequest::default()
        };

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://example.com/foo")
            .body(())
            .unwrap();
        assert_eq!(m.summarize_match(&req), None);

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/")
            .header("x-foo", "bar")
            .header("x-baz", "zab") // invalid header value
            .body(())
            .unwrap();
        assert_eq!(m.summarize_match(&req), None);

        // Regex matches apply
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.org/foo/bar")
            .header("x-foo", "bar")
            .header("x-baz", "quuuux")
            .body(())
            .unwrap();
        assert_eq!(
            m.summarize_match(&req),
            Some(RequestMatch {
                headers: 2,
                ..RequestMatch::default()
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
        assert_eq!(m.summarize_match(&req), None);
    }

    #[test]
    fn http_method() {
        let m = MatchRequest {
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
            m.summarize_match(&req),
            Some(RequestMatch {
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
        assert_eq!(m.summarize_match(&req), None);
    }

    #[test]
    fn multiple() {
        let m = MatchRequest {
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
            m.summarize_match(&req),
            Some(RequestMatch {
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
        assert_eq!(m.summarize_match(&req), None);
    }
}
