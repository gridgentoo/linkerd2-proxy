use http::header::{HeaderMap, HeaderName, HeaderValue};

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct ModifyRequestHeader {
    pub add: Vec<(HeaderName, HeaderValue)>,
    pub set: Vec<(HeaderName, HeaderValue)>,
    pub remove: Vec<HeaderName>,
}

// === impl ModifyRequestHeader ===

impl ModifyRequestHeader {
    pub fn apply(&self, headers: &mut HeaderMap) {
        for (hdr, val) in &self.add {
            headers.append(hdr, val.clone());
        }
        for (hdr, val) in &self.set {
            headers.insert(hdr, val.clone());
        }
        for hdr in &self.remove {
            headers.remove(hdr);
        }
    }
}

#[cfg(feature = "proto")]
mod proto {
    use super::*;
    use linkerd2_proxy_api::{http_route as api, http_types};

    #[derive(Debug, thiserror::Error)]
    pub enum RequestHeaderModifierError {
        #[error("{0}")]
        InvalidName(#[from] http::header::InvalidHeaderName),

        #[error("{0}")]
        InvalidValue(#[from] http::header::InvalidHeaderValue),
    }

    // === impl ModifyRequestHeader ===

    impl TryFrom<api::RequestHeaderModifier> for ModifyRequestHeader {
        type Error = RequestHeaderModifierError;

        fn try_from(rhm: api::RequestHeaderModifier) -> Result<Self, Self::Error> {
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
                .map(|n| n.parse())
                .collect::<Result<Vec<HeaderName>, http::header::InvalidHeaderName>>()?;
            Ok(ModifyRequestHeader { add, set, remove })
        }
    }
}
