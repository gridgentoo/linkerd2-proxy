use http::StatusCode;
use std::sync::Arc;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RespondWithError {
    pub status: StatusCode,
    pub message: Arc<str>,
}
