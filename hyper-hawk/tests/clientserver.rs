extern crate time;
extern crate hawk;
extern crate hyper;
extern crate hyper_hawk;
extern crate url;
extern crate futures;
extern crate tokio_core;

use hawk::{RequestBuilder, Credentials, Key, SHA256, PayloadHasher};
use hyper_hawk::{HawkScheme, ServerAuthorization};
use hyper::{Client, Method, Body, Request, Response};
use hyper::header::{ContentLength, Authorization};
use hyper::server::{Http, Service};
use futures::{Future, Stream, Async, Poll};
use futures::stream::Concat2;
use url::Url;

// It's impossible to have Service::Future be a Map type with a closure, because it is unsigned. Or
// looked at another way, async Rust is still in its infancy.  So we define a custom Future which
// can gather the request body and validate the request.

struct ServerValidatorFuture {
    header: Authorization<HawkScheme>,
    require_hash: bool,
    send_hash: bool,
    body_stream: Concat2<Body>,
}

impl Future for ServerValidatorFuture {
    type Item = Response;
    type Error = hyper::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.body_stream.poll() {
            Ok(Async::Ready(body)) => {
                println!("{:?}", self.header);
                println!("req body {:?}", body);

                // build a request object based on what we know
                let payload_hash;
                let mut req_builder = RequestBuilder::new("POST", "127.0.0.1", 9999, "/resource");

                // add a body hash, if we require such a thing
                if self.require_hash {
                    payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_ref());
                    req_builder = req_builder.hash(&payload_hash[..]);
                }

                let request = req_builder.request();

                assert_eq!(self.header.id, Some("test-client".to_string()));
                assert_eq!(self.header.ext, None);
                let key = Key::new(vec![1u8; 32], &SHA256);
                if !request.validate_header(&self.header, &key, time::Duration::minutes(1)) {
                    panic!("header validation failed");
                }

                let body = b"OK";
                let payload_hash;
                let mut resp_builder = request.make_response_builder(&self.header)
                    .ext("server-ext");
                if self.send_hash {
                    payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body);
                    resp_builder = resp_builder.hash(&payload_hash[..]);
                }
                let server_hdr = resp_builder.response().make_header(&key).unwrap();

                Ok(Async::Ready(Response::new()
                    .with_header(ContentLength(body.len() as u64))
                    .with_header(ServerAuthorization(HawkScheme(server_hdr)))
                    .with_body(body.as_ref())))
            }

            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(err) => Err(err),
        }
    }
}

struct TestService {
    require_hash: bool,
    send_hash: bool,
}

impl Service for TestService {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;

    type Future = ServerValidatorFuture;

    fn call(&self, req: Request) -> Self::Future {
        // get the Authorization header the client sent
        ServerValidatorFuture {
            header: req.headers().get::<Authorization<HawkScheme>>().unwrap().clone(),
            require_hash: self.require_hash,
            send_hash: self.send_hash,
            body_stream: req.body().concat2(),
        }
    }
}

fn run_client_server(client_send_hash: bool,
                     server_require_hash: bool,
                     server_send_hash: bool,
                     client_require_hash: bool) {

    // Hyper, really Tokio, bizarrely creates a new Service for each connection
    let service_factory = move || {
        Ok(TestService {
            require_hash: server_require_hash,
            send_hash: server_send_hash,
        })
    };
    let addr = "127.0.0.1:0".parse().unwrap();
    let server = Http::new().bind(&addr, service_factory).unwrap();
    let local_address = server.local_addr().unwrap();
    println!("{:?}", local_address);

    // call the server using a Hyper client; this must all be in the same function
    // body to avoid lots of async lifetime issues
    let credentials = Credentials {
        id: "test-client".to_string(),
        key: Key::new(vec![1u8; 32], &SHA256),
    };
    let body = "foo=bar";
    let url = Url::parse("http://127.0.0.1:9999/resource").unwrap();

    // build a hawk::Request for this request
    let payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_bytes());
    let mut req_builder = RequestBuilder::from_url("POST", &url).unwrap();
    if client_send_hash {
        req_builder = req_builder.hash(&payload_hash[..]);
    }
    let hawk_req = req_builder.request();

    // build a hyper::Request for this request (using the real port)
    let mut req =
        Request::new(Method::Post,
                     format!("http://127.0.0.1:{}", local_address.port()).parse().unwrap());
    let req_header = hawk_req.make_header(&credentials).unwrap();
    req.headers_mut().set(Authorization(HawkScheme(req_header.clone())));
    req.set_body(body);
    println!("{:?}", req);

    // use the server's tokio Core, since each server creates its own (?!)
    // https://github.com/hyperium/hyper/issues/1075
    let handle = server.handle();
    let client = Client::new(&handle);
    let client_fut = client.request(req)
        .and_then(|res| {
            println!("{:?}", res);
            assert_eq!(res.status(), hyper::Ok);
            let server_hdr =
                res.headers().get::<ServerAuthorization<HawkScheme>>().unwrap().clone();
            res.body().concat2().map(|body| (body, server_hdr))
        })
        .map(|(body, server_hdr)| {
            println!("{:?}", server_hdr);
            println!("res body {:?}", body);

            assert_eq!(body.as_ref(), b"OK");

            // most fields in `Server-Authorization: Hawk` are omitted
            assert_eq!(server_hdr.id, None);
            assert_eq!(server_hdr.ts, None);
            assert_eq!(server_hdr.nonce, None);
            assert_eq!(server_hdr.ext, Some("server-ext".to_string()));
            assert_eq!(server_hdr.app, None);
            assert_eq!(server_hdr.dlg, None);

            let resp_payload_hash;
            let mut resp_builder = hawk_req.make_response_builder(&req_header);
            if client_require_hash {
                resp_payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_ref());
                resp_builder = resp_builder.hash(&resp_payload_hash[..]);
            }

            let response = resp_builder.response();
            if !response.validate_header(&server_hdr, &credentials.key) {
                panic!("authentication of response header failed");
            }
        })
        .map_err(|e| {
            panic!("{:?}", e);
        });
    server.run_until(client_fut).unwrap();

    drop(client);
    drop(handle);
}

#[test]
fn no_hashes() {
    run_client_server(false, false, false, false);
}

#[test]
fn client_sends() {
    run_client_server(true, false, false, false);
}

#[test]
fn server_requires() {
    run_client_server(true, true, false, false);
}

#[test]
fn server_sends() {
    run_client_server(true, true, true, false);
}

#[test]
fn client_requires() {
    run_client_server(true, true, true, true);
}

#[test]
fn response_hash_only() {
    run_client_server(false, false, true, true);
}
