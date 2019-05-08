use hawk::{
    Credentials, Header, Key, PayloadHasher, RequestBuilder, RequestState, ResponseBuilder,
    SignRequest, SHA256,
};
use hyper;
use hyper::rt::{self, Future, Stream};
use hyper::{header, Body, Client, Request, StatusCode};
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command};
use std::str::FromStr;
use std::time;
use tokio::runtime::current_thread::Runtime;
use url::Url;

fn start_node_server() -> (Child, u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", 0)).unwrap();
    let callback_port = listener.local_addr().unwrap().port();

    // check for `node_modules' first
    let path = Path::new("tests/node/node_modules");
    if !path.is_dir() {
        panic!(
            "Run `yarn` or `npm install` in tests/node, or test with --features \
             no-interoperability"
        );
    }

    let child = Command::new("node")
        .arg("serve-one.js")
        .arg(format!("{}", callback_port))
        .current_dir("tests/node")
        .spawn()
        .expect("node command failed to start");

    // wait until the process is ready, signalled by a connect to the callback port, and then
    // return the port it provides. We know this will only get one connection, but iteration
    // is easier anyway
    #[cfg_attr(feature = "cargo-clippy", allow(never_loop))]
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        let mut data: Vec<u8> = vec![];
        stream.read_to_end(&mut data).unwrap();
        let port = u16::from_str(std::str::from_utf8(&data).unwrap()).unwrap();

        drop(stream);
        return (child, port);
    }
    unreachable!();
}

fn make_credentials() -> Credentials {
    Credentials {
        id: "dh37fgj492je".to_string(),
        key: Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", SHA256).unwrap(),
    }
}

/// Run the given function with a node child process, in a dedicated tokio current_thread runtime.
/// The current_thread means that it's safe to use `assert!` in the function implementation.
fn with_node_server<FN>(test_fn: FN)
where
    FN: FnOnce(u16) -> Box<dyn Future<Item = (), Error = ()>>,
{
    let (mut child, port) = start_node_server();

    let mut runtime = Runtime::new().unwrap();
    runtime
        .block_on(rt::lazy(move || test_fn(port)))
        .expect("error running test function");

    // The Node server won't stop until we close the kept-alive HTTP connection, so this must be
    // dropped before waiting for the child.
    drop(runtime);

    child.wait().expect("Failure waiting for child");
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_header() {
    with_node_server(|port| {
        let credentials = make_credentials();
        let url = Url::parse(&format!("http://localhost:{}/no-body", port)).unwrap();
        let reqstate = RequestState::new().unwrap();

        let req = Request::builder()
            .method("GET")
            .uri(url.as_str())
            .sign_hawk(&credentials, &reqstate, |b| b)
            .body(Body::empty())
            .unwrap();

        let client = Client::new();
        Box::new(
            client
                .request(req)
                .and_then(move |res| {
                    // the `no-body` endpoint does not return server-authorization,
                    // so there's nothing to verify here but the body content
                    println!("Response: {}", res.status());
                    println!("Headers: {:#?}", res.headers());
                    assert_eq!(res.status(), StatusCode::OK);
                    res.into_body().concat2().map(move |body| {
                        assert_eq!(body.into_bytes(), "Hello Steve");
                    })
                })
                .map_err(|err| {
                    panic!("panic {}", err);
                }),
        )
    });
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_header_ext() {
    with_node_server(|port| {
        let credentials = make_credentials();
        let url = Url::parse(&format!("http://localhost:{}/no-body", port)).unwrap();
        let reqstate = RequestState::new().unwrap();

        let req = Request::builder()
            .method("GET")
            .uri(url.as_str())
            .sign_hawk(&credentials, &reqstate, |b| b.ext("extra!"))
            .body(Body::empty())
            .unwrap();

        let client = Client::new();
        Box::new(
            client
                .request(req)
                .and_then(move |res| {
                    // the `no-body` endpoint does not return server-authorization,
                    // so there's nothing to verify here but the body content
                    println!("Response: {}", res.status());
                    println!("Headers: {:#?}", res.headers());
                    assert_eq!(res.status(), StatusCode::OK);
                    res.into_body().concat2().map(move |body| {
                        assert_eq!(body.into_bytes(), "Hello Steve ext=extra!");
                    })
                })
                .map_err(|err| {
                    panic!("panic {}", err);
                }),
        )
    });
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_header_and_bodies() {
    with_node_server(|port| {
        let credentials = make_credentials();
        let url = Url::parse(&format!("http://localhost:{}/resource", port)).unwrap();
        let body = "foo=bar";
        let hash = PayloadHasher::hash(b"text/plain", SHA256, body).unwrap();
        let reqstate = RequestState::new().unwrap();

        let req = Request::builder()
            .method("POST")
            .uri(url.as_str())
            .header(header::CONTENT_TYPE, "text/plain")
            .sign_hawk(&credentials, &reqstate, |b| b.hash(hash))
            .body(Body::from(body))
            .unwrap();
        println!("Request: {:?}", req);

        let client = Client::new();
        Box::new(
            client
                .request(req)
                .and_then(move |res| {
                    println!("Response: {}", res.status());
                    println!("Headers: {:#?}", res.headers());
                    assert_eq!(res.status(), StatusCode::OK);
                    let sa_header = res
                        .headers()
                        .get("server-authorization")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();
                    let hasher = PayloadHasher::new(b"text/plain", SHA256).unwrap();
                    res.into_body()
                        .fold(
                            hasher,
                            |mut hasher, chunk| -> Result<PayloadHasher, hyper::Error> {
                                hasher.update(&chunk).unwrap();
                                Ok(hasher)
                            },
                        )
                        .map(move |hasher| {
                            let hash = hasher.finish().unwrap();
                            println!("hash: {:?}", hash);
                            println!("s-a header: {}", sa_header);
                            let response = ResponseBuilder::from_request_state(
                                &reqstate,
                                "POST",
                                "localhost",
                                port,
                                "/resource",
                            )
                            .hash(hash)
                            .response();
                            let server_header = Header::from_str(&sa_header[5..]).unwrap();
                            assert!(response.validate_header(&server_header, &credentials.key));
                        })
                })
                .map_err(|err| {
                    panic!("Error {}", err);
                }),
        )
    });
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_bewit() {
    with_node_server(|port| {
        let credentials = make_credentials();
        let url = Url::parse(&format!("http://localhost:{}/resource", port)).unwrap();
        let hawk_req = RequestBuilder::from_url("GET", &url)
            .unwrap()
            .ext("ext-content")
            .request();
        let bewit = hawk_req
            .make_bewit(
                &credentials,
                time::SystemTime::now() + time::Duration::from_secs(60),
            )
            .unwrap();
        let mut url = url.clone();
        url.set_query(Some(&format!("bewit={}", bewit.to_str())));

        let req = Request::builder()
            .method("GET")
            .uri(url.as_str())
            .body(Body::empty())
            .unwrap();

        let client = Client::new();
        Box::new(
            client
                .request(req)
                .and_then(move |res| {
                    println!("Response: {}", res.status());
                    println!("Headers: {:#?}", res.headers());
                    assert_eq!(res.status(), StatusCode::OK);
                    res.into_body().concat2().map(move |body| {
                        println!("{:?}", body);
                        assert_eq!(body.into_bytes(), "Hello Steve ext-content");
                    })
                })
                .map_err(|err| {
                    panic!("Error {}", err);
                }),
        )
    })
}
