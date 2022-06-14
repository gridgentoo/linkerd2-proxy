#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RespondWithError {
    pub code: u16,
    pub message: std::sync::Arc<str>,
}

#[cfg(feature = "proto")]
pub mod proto {
    use super::*;
    use linkerd2_proxy_api::grpc_route as api;

    #[derive(Debug, thiserror::Error)]
    pub enum ErrorResponderError {
        #[error("invalid HTTP status code: {0}")]
        InvalidStatusNonU16(u32),
    }

    // === impl RespondWithError ===

    impl TryFrom<api::GrpcErrorResponder> for RespondWithError {
        type Error = ErrorResponderError;

        fn try_from(proto: api::GrpcErrorResponder) -> Result<Self, Self::Error> {
            if proto.code > u16::MAX as u32 {
                return Err(ErrorResponderError::InvalidStatusNonU16(proto.code));
            }

            Ok(RespondWithError {
                code: proto.code as u16,
                message: proto.message.into(),
            })
        }
    }
}
