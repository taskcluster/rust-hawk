use crate::{Credentials, RequestBuilder, RequestState};
use http;

pub trait SignRequest {
    /// Sign a request using the given credentials.  The `build` callable can add any additional
    /// desired attributes to the hawk::RequestBuilder, such as `ext` or a hash.
    fn sign_hawk<F>(&mut self, credentials: &Credentials, rs: &RequestState, build: F) -> &mut Self
    where
        F: FnOnce(RequestBuilder) -> RequestBuilder;
}

// TODO: find some way to output a ResponseBuilder here, too; maybe stick it in RequestState?
// TODO: SignRequestRequest
impl SignRequest for http::request::Builder {
    fn sign_hawk<F>(&mut self, credentials: &Credentials, rs: &RequestState, build: F) -> &mut Self
    where
        F: FnOnce(RequestBuilder) -> RequestBuilder,
    {
        let method = self
            .method_ref()
            .expect("request does not have a method")
            .as_str();
        let uri = self.uri_ref().expect("request does not have uri");
        let host = uri.host().expect("request uri does not have a host");
        let port = uri.port_u16().expect("request uri does not have a port");
        let path = uri
            .path_and_query()
            .expect("request uri does not have a path")
            .as_str();

        let bldr = build(RequestBuilder::new(method, host, port, path));
        let req_header = bldr.request().make_header_full(credentials, &rs).unwrap();
        self.header(http::header::AUTHORIZATION, format!("Hawk {}", req_header))
    }
}

// TODO: ValidateHawkRequest?
// TODO: SignRequestResponse?
// TODO: ValidateHawkResponse for http::response::Response?
