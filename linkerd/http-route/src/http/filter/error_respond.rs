#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RespondWithError {
    pub status: http::StatusCode,
    pub message: std::sync::Arc<str>,
}

#[cfg(feature = "proto")]
pub mod proto {
    use super::*;
    use linkerd2_proxy_api::http_route as api;

    #[derive(Debug, thiserror::Error)]
    pub enum ErrorResponderError {
        #[error("invalid HTTP status code: {0}")]
        InvalidStatus(#[from] http::status::InvalidStatusCode),

        #[error("invalid HTTP status code: {0}")]
        InvalidStatusNonU16(u32),
    }

    // === impl RespondWithError ===

    impl TryFrom<api::HttpErrorResponder> for RespondWithError {
        type Error = ErrorResponderError;

        fn try_from(proto: api::HttpErrorResponder) -> Result<Self, Self::Error> {
            if proto.status > u16::MAX as u32 {
                return Err(ErrorResponderError::InvalidStatusNonU16(proto.status));
            }
            let status = http::StatusCode::from_u16(proto.status as u16)?;

            Ok(RespondWithError {
                status,
                message: proto.message.into(),
            })
        }
    }
}
