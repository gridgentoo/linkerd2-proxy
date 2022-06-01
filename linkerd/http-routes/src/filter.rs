use crate::{PathMatch, RouteMatch};
use http::header::{HeaderName, HeaderValue};

#[derive(Clone, Debug, Hash, PartialEq)]
pub enum Filter {
    ModifyRequestHeader(ModifyRequestHeader),
    RedirectRequest(RedirectRequest),
}

#[derive(Clone, Debug, Default, Hash, PartialEq)]
pub struct ModifyRequestHeader {
    pub add: Vec<(HeaderName, HeaderValue)>,
    pub set: Vec<(HeaderName, HeaderValue)>,
    pub remove: Vec<HeaderName>,
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct RedirectRequest {
    pub scheme: Option<http::uri::Scheme>,
    pub authority: Option<http::uri::Authority>,
    pub path: Option<PathModifier>,
    pub status_code: http::StatusCode,
}

#[derive(Clone, Debug, Hash, PartialEq)]
pub enum PathModifier {
    ReplaceFullPath(String),
    ReplacePrefixMatch(String),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidRedirect {
    #[error("redirects may only replace the path prefix when a path prefix match applied")]
    InvalidReplacePrefix,

    #[error("redirect produced an invalid location: {0}")]
    InvalidLocation(#[from] http::Error),

    #[error("no authority to redirect to")]
    MissingAuthority,
}

#[derive(Clone, Debug)]
pub struct Redirection {
    pub status: http::StatusCode,
    pub location: http::Uri,
}

// === impl ModifyRequestHeader ===

impl ModifyRequestHeader {
    pub(crate) fn apply(&self, headers: &mut http::HeaderMap) {
        for (hdr, val) in &self.set {
            headers.insert(hdr, val.clone());
        }
        for (hdr, val) in &self.add {
            headers.append(hdr, val.clone());
        }
        for hdr in &self.remove {
            headers.remove(hdr);
        }
    }
}

// === impl RedirectRequest ===

impl RedirectRequest {
    pub(crate) fn apply(
        &self,
        orig_uri: &http::Uri,
        rm: &RouteMatch,
    ) -> Result<Redirection, InvalidRedirect> {
        let location = {
            let scheme = self
                .scheme
                .clone()
                .or_else(|| orig_uri.scheme().cloned())
                .unwrap_or(http::uri::Scheme::HTTP);
            let authority = self
                .authority
                .clone()
                .or_else(|| orig_uri.authority().cloned())
                .ok_or(InvalidRedirect::MissingAuthority)?;
            let path = {
                let path = orig_uri.path();
                match &self.path {
                    None => path.to_string(),
                    Some(PathModifier::ReplaceFullPath(p)) => p.clone(),
                    Some(PathModifier::ReplacePrefixMatch(new_pfx)) => match rm.rule.path() {
                        PathMatch::Prefix(pfx_len) if *pfx_len <= path.len() => {
                            let (_, rest) = path.split_at(*pfx_len);
                            format!("{}{}", new_pfx, rest)
                        }
                        _ => return Err(InvalidRedirect::InvalidReplacePrefix),
                    },
                }
            };
            http::Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(path)
                .build()
                .map_err(InvalidRedirect::InvalidLocation)?
        };

        Ok(Redirection {
            status: self.status_code,
            location,
        })
    }
}
