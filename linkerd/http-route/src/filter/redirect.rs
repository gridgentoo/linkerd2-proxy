use super::ModifyPath;
use crate::HttpRouteMatch;
use http::uri::{Authority, InvalidUri, Scheme, Uri};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RedirectRequest {
    pub scheme: Option<Scheme>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: Option<ModifyPath>,
    pub status: Option<http::StatusCode>,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidRedirect {
    #[error("redirect would loop")]
    Loop,

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
    pub location: Uri,
}

// === impl RedirectRequest ===

impl RedirectRequest {
    pub fn apply(
        &self,
        orig_uri: &http::Uri,
        rm: &HttpRouteMatch,
    ) -> Result<Redirection, InvalidRedirect> {
        let location = {
            let scheme = self
                .scheme
                .clone()
                .or_else(|| orig_uri.scheme().cloned())
                .unwrap_or(Scheme::HTTP);

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
                use crate::PathMatch;

                let path = orig_uri.path();
                match &self.path {
                    None => path.to_string(),
                    Some(ModifyPath::ReplaceFullPath(p)) => p.clone(),
                    Some(ModifyPath::ReplacePrefixMatch(new_pfx)) => match rm.request.path() {
                        PathMatch::Prefix(pfx_len) if *pfx_len <= path.len() => {
                            let (_, rest) = path.split_at(*pfx_len);
                            format!("{}{}", new_pfx, rest)
                        }
                        _ => return Err(InvalidRedirect::InvalidReplacePrefix),
                    },
                }
            };

            Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(path)
                .build()
                .map_err(InvalidRedirect::InvalidLocation)?
        };
        if &location == orig_uri {
            return Err(InvalidRedirect::Loop);
        }

        let status = self.status.unwrap_or(http::StatusCode::MOVED_PERMANENTLY);

        Ok(Redirection { status, location })
    }
}
