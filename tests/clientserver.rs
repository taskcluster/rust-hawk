#![allow(unused_variables)]
#![allow(unused_imports)]
use failure::Fail;
use futures::stream::Concat2;
use futures::{future, Async, Future, Poll, Stream};
use hawk::{Credentials, Key, PayloadHasher, RequestBuilder, SHA256};
use hawk::{Header, RequestState, ResponseBuilder, SignRequest};
use hyper;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Body, Chunk, Client, HeaderMap, Request, Response, Server, StatusCode};
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

#[derive(Clone)]
struct TestParams {
    client_send_hash: bool,
    server_require_hash: bool,
    server_send_hash: bool,
    client_require_hash: bool,
}

#[derive(Fail, Debug)]
pub enum TestError {
    #[fail(display = "Test failure: {}", _0)]
    Failure(String),

    #[fail(display = "{}", _0)]
    HawkError(hawk::Error),

    #[fail(display = "{}", _0)]
    Hyper(#[fail(cause)] hyper::Error),

    #[fail(display = "{}", _0)]
    Http(#[fail(cause)] http::Error),

    #[fail(display = "{}", _0)]
    HttpToStr(#[fail(cause)] http::header::ToStrError),
}

impl From<hawk::Error> for TestError {
    fn from(e: hawk::Error) -> Self {
        TestError::HawkError(e)
    }
}

impl From<hyper::Error> for TestError {
    fn from(e: hyper::Error) -> Self {
        TestError::Hyper(e)
    }
}

impl From<http::Error> for TestError {
    fn from(e: http::Error) -> Self {
        TestError::Http(e)
    }
}

impl From<http::header::ToStrError> for TestError {
    fn from(e: http::header::ToStrError) -> Self {
        TestError::HttpToStr(e)
    }
}

struct TestServer {
    shutdown_tx: futures::sync::oneshot::Sender<()>,
    local_address: std::net::SocketAddr,
}

type BoxFut = Box<dyn Future<Item = Response<Body>, Error = hyper::Error> + Send>;

impl TestServer {
    fn new(tp: &TestParams) -> Self {
        let service_factory = match *tp {
            TestParams {
                client_send_hash,
                server_require_hash,
                server_send_hash,
                client_require_hash,
            } => {
                move || {
                    service_fn(move |req: Request<Body>| -> BoxFut {
                        // Hyper doesn't allow you to look at a request and its body
                        // at the same time without a clone.. so we clone..
                        let headers = req.headers().clone();

                        Box::new(req.into_body().concat2().and_then(move |chunk| {
                            let res = match TestServer::handle(
                                server_require_hash,
                                server_send_hash,
                                headers,
                                &chunk,
                            ) {
                                Ok(res) => res,
                                Err(e) => Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from(format!("{}", e)))
                                    .unwrap(),
                            };
                            future::ok(res)
                        }))
                    })
                }
            }
        };

        let addr = "127.0.0.1:0".parse().unwrap();
        let server = Server::bind(&addr).serve(service_factory);
        let local_address = server.local_addr();

        // set up a channel to signal the server to stop
        let (shutdown_tx, shutdown_rx) = futures::sync::oneshot::channel::<()>();
        hyper::rt::spawn(server.with_graceful_shutdown(shutdown_rx).map_err(|e| {
            // an error here is a failure to shut down, unlikely in a test context
            eprintln!("server error: {}", e);
        }));

        Self {
            shutdown_tx,
            local_address,
        }
    }

    fn handle(
        server_require_hash: bool,
        server_send_hash: bool,
        headers: HeaderMap,
        body: &Chunk,
    ) -> Result<Response<Body>, TestError> {
        if !headers.contains_key(AUTHORIZATION) {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from(""))?);
        }

        let header: Header = headers
            .get(AUTHORIZATION)
            .ok_or(TestError::Failure(String::from("No Authorization header")))?
            .try_into()?;

        // verify request
        if header.id != Some(String::from("dh37fgj492je")) {
            return Err(TestError::Failure(format!(
                "id is {:?}, not dh37fgj492je",
                header.id
            )));
        }

        if !header.ext.is_none() {
            return Err(TestError::Failure(String::from("ext is not None")));
        }

        let mut req_builder = RequestBuilder::new("POST", "127.0.0.1", 80, "/resource");

        // if requested, calculate hash, add to builder
        if server_require_hash {
            let hash = PayloadHasher::hash(b"text/plain", SHA256, body)?;
            req_builder = req_builder.hash(hash);
        }

        let request = req_builder.request();
        let key = Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", SHA256).unwrap();
        if !request.validate_header(&header, &key, Duration::from_secs(60)) {
            return Err(TestError::Failure(String::from("header validation failed")));
        }

        let body = "Hello world";

        let reqstate = RequestState {
            nonce: header
                .nonce
                .ok_or_else(|| TestError::Failure(String::from("did not get nonce")))?,
            ts: header
                .ts
                .ok_or_else(|| TestError::Failure(String::from("did not get ts")))?,
        };
        let mut res_builder = request.make_response_builder(&reqstate);

        if server_send_hash {
            let hash = PayloadHasher::hash(b"text/plain", SHA256, body)?;
            res_builder = res_builder.hash(hash);
        }

        let res_header = res_builder.response().make_header(&key)?;

        // sign response
        let mut resp = Response::builder();
        resp.header("Server-Authorization", res_header.header_value()?);
        Ok(resp.body(Body::from(body))?)
    }

    fn stop(self) {
        self.shutdown_tx.send(()).unwrap();
    }
}

fn run_client(
    tp: &TestParams,
    credentials: Credentials,
    local_address: &std::net::SocketAddr,
) -> impl Future<Item = (), Error = TestError> {
    let url = Url::parse(&format!("http://{}/resource", local_address)).unwrap();
    let reqstate = RequestState::new().unwrap();

    match *tp {
        TestParams {
            client_send_hash,
            server_require_hash,
            server_send_hash,
            client_require_hash,
        } => {
            let body = "foo=bar";
            let payload_hash = match client_send_hash {
                true => Some(PayloadHasher::hash(b"text/plain", SHA256, body.as_bytes()).unwrap()),
                false => None,
            };

            let req = Request::builder()
                .method("POST")
                .uri(url.as_str())
                .sign_hawk(&credentials, &reqstate, |b| {
                    b.hash(payload_hash)
                        // we'll be using a dynamic port, but let's pretend it was 80 for
                        // stability of the MAC
                        .port(80)
                })
                .body(Body::from(body))
                .unwrap();

            let client = Client::new();
            client
                .request(req)
                .map_err(|err| err.into())
                .and_then(move |res| {
                    if res.status() != StatusCode::OK {
                        // returning an error from here is difficult, so just assert..
                        assert!(false, "Got bad status");
                    }

                    let header: Header = res
                        .headers()
                        .get("Server-Authorization")
                        .ok_or(TestError::Failure(String::from("No Authorization header")))
                        .unwrap()
                        .try_into()
                        .unwrap();

                    // get the body, tack on the header
                    res.into_body().concat2().join(future::ok(header))
                })
                .map_err(|err| err.into())
                .and_then(move |(body, header)| {
                    let mut hawk_res_builder = ResponseBuilder::from_request_state(
                        &reqstate,
                        "POST",
                        "127.0.0.1",
                        80,
                        "/resource",
                    );

                    if client_require_hash {
                        let hash = PayloadHasher::hash(b"text/plain", SHA256, body)?;
                        hawk_res_builder = hawk_res_builder.hash(hash);
                    }

                    let hawk_res = hawk_res_builder.response();

                    if !hawk_res.validate_header(&header, &credentials.key) {
                        return Err(TestError::Failure(format!(
                            "Invalid server-authentication header {:?}",
                            header
                        )));
                    }

                    Ok(())
                })
        }
    }
}

fn run_client_server(tp: &'static TestParams) {
    // the async run doesn't allow returning anything, so we stuff the result of the
    // client call here and check it on return.  There's probably an easier way!
    let result: Arc<Mutex<Result<(), TestError>>> = Arc::new(Mutex::new(Err(TestError::Failure(
        "client did not finish".to_string(),
    ))));
    let async_result = result.clone();

    hyper::rt::run(hyper::rt::lazy(move || {
        let test_server = TestServer::new(tp);
        let credentials = Credentials {
            id: "dh37fgj492je".to_string(),
            key: Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", SHA256).unwrap(),
        };

        hyper::rt::spawn(
            run_client(tp, credentials, &test_server.local_address).then(move |r| {
                test_server.stop();
                *async_result.lock().unwrap() = r;
                Ok(())
            }),
        );

        futures::future::ok(())
    }));

    let r = result.lock().unwrap();
    match *r {
        Ok(_) => {}
        Err(ref e) => {
            panic!("{:?}", e);
        }
    }
}

#[test]
fn no_hashes() {
    run_client_server(&TestParams {
        client_send_hash: false,
        server_require_hash: false,
        server_send_hash: false,
        client_require_hash: false,
    });
}

#[test]
fn client_send() {
    run_client_server(&TestParams {
        client_send_hash: true,
        server_require_hash: false,
        server_send_hash: false,
        client_require_hash: false,
    });
}

#[test]
fn server_require() {
    run_client_server(&TestParams {
        client_send_hash: true,
        server_require_hash: true,
        server_send_hash: false,
        client_require_hash: false,
    });
}

#[test]
fn server_send() {
    run_client_server(&TestParams {
        client_send_hash: true,
        server_require_hash: true,
        server_send_hash: true,
        client_require_hash: false,
    });
}

#[test]
fn client_require() {
    run_client_server(&TestParams {
        client_send_hash: true,
        server_require_hash: true,
        server_send_hash: true,
        client_require_hash: true,
    });
}

#[test]
fn response_hash_only() {
    run_client_server(&TestParams {
        client_send_hash: false,
        server_require_hash: false,
        server_send_hash: true,
        client_require_hash: true,
    });
}
