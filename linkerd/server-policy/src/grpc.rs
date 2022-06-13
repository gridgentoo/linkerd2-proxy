pub use linkerd_http_route::grpc::filter;
use linkerd_http_route::{grpc, http};

pub type Policy = crate::RoutePolicy<Filter>;
pub type Route = grpc::Route<Policy>;
pub type Rule = grpc::Rule<Policy>;

#[inline]
pub fn find<'r, B>(
    routes: impl IntoIterator<Item = &'r Route>,
    req: &::http::Request<B>,
) -> Option<(grpc::RouteMatch, &'r Policy)> {
    grpc::find(routes, req)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Filter {
    Error(grpc::filter::RespondWithError),

    RequestHeaders(http::filter::ModifyRequestHeader),

    /// Indicates that the filter kind is unknown to the proxy (e.g., because
    /// the controller is on a new version of the protobuf).
    ///
    /// Route handlers must be careful about this situation, as it may not be
    /// appropriate for a proxy to skip filtering logic.
    Unknown,
}
