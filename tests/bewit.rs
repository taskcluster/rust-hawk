#![allow(unused_variables)]
#![allow(unused_imports)]
use failure::Fail;
use futures::stream::Concat2;
use futures::{future, Async, Future, Poll, Stream};
use hawk::{Credentials, Key, PayloadHasher, RequestBuilder, SHA256};
use hawk::{Header, RequestState, ResponseBuilder, SignRequest};
use hyper;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::service::service_fn_ok;
use hyper::{Body, Chunk, Client, HeaderMap, Request, Response, Server, StatusCode};
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

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

impl TestServer {
    fn new() -> Self {
        let service_factory = move || {
            service_fn_ok(move |req: Request<Body>| match TestServer::handle(req) {
                Ok(res) => res,
                Err(e) => Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("{}", e)))
                    .unwrap(),
            })
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

    fn handle(req: Request<Body>) -> Result<Response<Body>, TestError> {
        let path_and_query = req.uri().path_and_query().unwrap().as_str();
        let mut maybe_bewit = None;
        let server_req = RequestBuilder::new("GET", "127.0.0.1", 80, path_and_query)
            .extract_bewit(&mut maybe_bewit)?
            .request();
        let bewit = match maybe_bewit {
            None => return Err(TestError::Failure(String::from("did not get bewit"))),
            Some(bewit) => bewit,
        };
        if bewit.id() != "dh37fgj492je" {
            return Err(TestError::Failure(String::from("invalid bewit id")));
        }
        let key = Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", SHA256).unwrap();
        if !server_req.validate_bewit(&bewit, &key) {
            return Err(TestError::Failure(String::from("bewit did not validate")));
        }
        let body = "Hello world";
        Ok(Response::builder().body(Body::from(body))?)
    }

    fn stop(self) {
        self.shutdown_tx.send(()).unwrap();
    }
}

fn run_client(
    credentials: &Credentials,
    local_address: &std::net::SocketAddr,
) -> impl Future<Item = (), Error = TestError> {
    let mut url = Url::parse(&format!("http://{}/resource", local_address)).unwrap();

    let hawk_req = RequestBuilder::new("GET", "127.0.0.1", 80, "/resource").request();
    let bewit = hawk_req
        .make_bewit_with_ttl(credentials, Duration::from_secs(30))
        .unwrap();
    url.set_query(Some(&format!("bewit={}", bewit.to_str())));

    let req = Request::builder()
        .method("GET")
        .uri(url.as_str())
        .body(Body::empty())
        .unwrap();

    let client = Client::new();
    client
        .request(req)
        .map_err(|err| err.into())
        .and_then(move |res| {
            if res.status() != StatusCode::OK {
                return Err(TestError::Failure(format!("Got status {}", res.status())).into());
            }
            Ok(())
        })
}

fn run_client_server() {
    let credentials = Credentials {
        id: "dh37fgj492je".to_string(),
        key: Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", SHA256).unwrap(),
    };

    // the async run doesn't allow returning anything, so we stuff the result of the
    // client call here and check it on return.  There's probably an easier way!
    let result: Arc<Mutex<Result<(), TestError>>> = Arc::new(Mutex::new(Err(TestError::Failure(
        "client did not finish".to_string(),
    ))));
    let async_result = result.clone();

    hyper::rt::run(hyper::rt::lazy(move || {
        let test_server = TestServer::new();
        hyper::rt::spawn(
            run_client(&credentials, &test_server.local_address).then(move |r| {
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
fn bewit() {
    run_client_server();
}
