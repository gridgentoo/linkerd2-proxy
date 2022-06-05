use crate::{
    filter::{ModifyPath, ModifyRequestHeader, RedirectRequest},
    r#match::{MatchHeader, MatchPath, MatchQueryParam, MatchRequest},
    MatchHost,
};
use linkerd2_proxy_api::{http_route as api, http_types};

// === impl MatchHost ===

#[derive(Debug, thiserror::Error)]
#[error("host match must contain a match")]
pub struct HostMatchError;

impl TryFrom<api::HostMatch> for MatchHost {
    type Error = HostMatchError;

    fn try_from(hm: api::HostMatch) -> Result<Self, Self::Error> {
        match hm.r#match.ok_or(HostMatchError)? {
            api::host_match::Match::Exact(h) => Ok(MatchHost::Exact(h)),
            api::host_match::Match::Suffix(sfx) => Ok(MatchHost::Suffix(sfx.reverse_labels)),
        }
    }
}

// === impl MatchRequest ===

#[derive(Debug, thiserror::Error)]
pub enum RouteMatchError {
    #[error("invalid path match: {0}")]
    Path(#[from] PathMatchError),

    #[error("invalid header match: {0}")]
    Header(#[from] HeaderMatchError),

    #[error("invalid query param match: {0}")]
    QueryParam(#[from] QueryParamMatchError),
}

impl TryFrom<api::RouteMatch> for MatchRequest {
    type Error = RouteMatchError;

    fn try_from(rm: api::RouteMatch) -> Result<Self, Self::Error> {
        let path = match rm.path {
            None => None,
            Some(pm) => Some(pm.try_into()?),
        };
        Ok(MatchRequest {
            path,
            ..MatchRequest::default()
        })
    }
}

// === impl MatchPath ===

#[derive(Debug, thiserror::Error)]
pub enum PathMatchError {
    #[error("missing match")]
    MissingMatch,

    #[error("invalid regular expression: {0}")]
    InvalidRegex(#[from] regex::Error),
}

impl TryFrom<api::PathMatch> for MatchPath {
    type Error = PathMatchError;

    fn try_from(rm: api::PathMatch) -> Result<Self, Self::Error> {
        // TODO parse paths to validate they're valid.
        match rm.kind.ok_or(PathMatchError::MissingMatch)? {
            api::path_match::Kind::Exact(p) => Ok(MatchPath::Exact(p)),
            api::path_match::Kind::Prefix(p) => Ok(MatchPath::Prefix(p)),
            api::path_match::Kind::Regex(re) => Ok(MatchPath::Regex(re.parse()?)),
        }
    }
}

// === impl MatchHeader ===

#[derive(Debug, thiserror::Error)]
pub enum HeaderMatchError {
    #[error("{0}")]
    InvalidName(#[from] http::header::InvalidHeaderName),

    #[error("missing a header value match")]
    MissingValueMatch,

    #[error("{0}")]
    InvalidValue(#[from] http::header::InvalidHeaderValue),

    #[error("invalid regular expression: {0}")]
    InvalidRegex(#[from] regex::Error),
}

impl TryFrom<api::HeaderMatch> for MatchHeader {
    type Error = HeaderMatchError;

    fn try_from(hm: api::HeaderMatch) -> Result<Self, Self::Error> {
        let name = http::header::HeaderName::from_bytes(hm.name.as_bytes())?;
        match hm.value.ok_or(HeaderMatchError::MissingValueMatch)? {
            api::header_match::Value::Exact(h) => Ok(MatchHeader::Exact(name, h.parse()?)),
            api::header_match::Value::Regex(re) => Ok(MatchHeader::Regex(name, re.parse()?)),
        }
    }
}

// === impl MatchQueryParam ===

#[derive(Debug, thiserror::Error)]
pub enum QueryParamMatchError {
    #[error("missing a query param name")]
    MissingName,

    #[error("missing a query param value")]
    MissingValue,

    #[error("invalid regular expression: {0}")]
    InvalidRegex(#[from] regex::Error),
}

impl TryFrom<api::QueryParamMatch> for MatchQueryParam {
    type Error = QueryParamMatchError;

    fn try_from(qpm: api::QueryParamMatch) -> Result<Self, Self::Error> {
        if qpm.name.is_empty() {
            return Err(QueryParamMatchError::MissingName);
        }
        match qpm.value.ok_or(QueryParamMatchError::MissingValue)? {
            api::query_param_match::Value::Exact(v) => Ok(MatchQueryParam::Exact(qpm.name, v)),
            api::query_param_match::Value::Regex(re) => {
                Ok(MatchQueryParam::Regex(qpm.name, re.parse()?))
            }
        }
    }
}

// === impl ModifyRequestHeader ===

#[derive(Debug, thiserror::Error)]
pub enum RequestHeaderModifierError {
    #[error("{0}")]
    InvalidName(#[from] http::header::InvalidHeaderName),

    #[error("{0}")]
    InvalidValue(#[from] http::header::InvalidHeaderValue),
}

impl TryFrom<api::RequestHeaderModifier> for ModifyRequestHeader {
    type Error = RequestHeaderModifierError;

    fn try_from(rhm: api::RequestHeaderModifier) -> Result<Self, Self::Error> {
        use http::header::{HeaderName, HeaderValue, InvalidHeaderName};

        let to_pairs = |hs: Option<http_types::Headers>| {
            hs.into_iter()
                .flat_map(|a| a.headers.into_iter())
                .map(|h| {
                    let name = h.name.parse::<HeaderName>()?;
                    let value = HeaderValue::from_bytes(&h.value)?;
                    Ok((name, value))
                })
                .collect::<Result<Vec<(HeaderName, HeaderValue)>, Self::Error>>()
        };

        let add = to_pairs(rhm.add)?;
        let set = to_pairs(rhm.set)?;
        let remove = rhm
            .remove
            .into_iter()
            .map(|n| n.parse::<HeaderName>())
            .collect::<Result<Vec<HeaderName>, InvalidHeaderName>>()?;
        Ok(ModifyRequestHeader { add, set, remove })
    }
}

// === impl RedirectRequest ===

#[derive(Debug, thiserror::Error)]
pub enum RequestRedirectError {
    #[error("invalid location scheme: {0}")]
    InvalidScheme(#[from] http_types::InvalidScheme),

    #[error("invalid HTTP status code: {0}")]
    InvalidStatus(#[from] http::status::InvalidStatusCode),

    #[error("invalid HTTP status code: {0}")]
    InvalidStatusNonU16(u32),

    #[error("invalid port number: {0}")]
    InvalidPort(u32),

    #[error("{0}")]
    InvalidValue(#[from] http::header::InvalidHeaderValue),
}

impl TryFrom<api::RequestRedirect> for RedirectRequest {
    type Error = RequestRedirectError;

    fn try_from(rr: api::RequestRedirect) -> Result<Self, Self::Error> {
        let scheme = match rr.scheme {
            None => None,
            Some(s) => Some(s.try_into()?),
        };

        let host = if rr.host.is_empty() {
            None
        } else {
            // TODO ensure hostname is valid.
            Some(rr.host)
        };

        let path = rr.path.and_then(|p| p.replace).map(|p| match p {
            api::path_modifier::Replace::Full(path) => {
                // TODO ensure path is valid.
                ModifyPath::ReplaceFullPath(path)
            }
            api::path_modifier::Replace::Prefix(prefix) => {
                // TODO ensure prefix is valid.
                ModifyPath::ReplacePrefixMatch(prefix)
            }
        });

        let port = {
            if rr.port > (u16::MAX as u32) {
                return Err(RequestRedirectError::InvalidPort(rr.port));
            }
            if rr.port == 0 {
                None
            } else {
                Some(rr.port as u16)
            }
        };

        let status = match rr.status {
            0 => None,
            s if 100 >= s || s < 600 => Some(http::StatusCode::from_u16(s as u16)?),
            s => return Err(RequestRedirectError::InvalidStatusNonU16(s)),
        };

        Ok(RedirectRequest {
            scheme,
            host,
            path,
            port,
            status,
        })
    }
}
