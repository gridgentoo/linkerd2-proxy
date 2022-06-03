use crate::{PathMatch, RouteMatch};
use http::{
    header::{HeaderName, HeaderValue},
    uri::{Authority, InvalidUri},
};

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct ModifyRequestHeader {
    pub add: Vec<(HeaderName, HeaderValue)>,
    pub set: Vec<(HeaderName, HeaderValue)>,
    pub remove: Vec<HeaderName>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RedirectRequest {
    pub scheme: Option<http::uri::Scheme>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: Option<PathModifier>,
    pub status_code: http::StatusCode,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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

    #[error("redirect produced an invalid authority: {0}")]
    InvalidAuthority(#[from] InvalidUri),

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
    pub fn apply(&self, headers: &mut http::HeaderMap) {
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
    pub fn apply<T>(
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

            let authority = {
                let host = self
                    .host
                    .clone()
                    .or_else(|| orig_uri.host().map(|s| s.to_owned()))
                    .ok_or(InvalidRedirect::MissingAuthority)?;
                let port = self.port.or_else(|| orig_uri.port_u16());
                let hp = match port {
                    Some(p) => format!("{}:{}", host, p),
                    None => host,
                };
                hp.parse::<Authority>()?
            };

            let path = {
                let path = orig_uri.path();
                match &self.path {
                    None => path.to_string(),
                    Some(PathModifier::ReplaceFullPath(p)) => p.clone(),
                    Some(PathModifier::ReplacePrefixMatch(new_pfx)) => match rm.request.path() {
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
