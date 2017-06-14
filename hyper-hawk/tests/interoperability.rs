extern crate time;
extern crate hawk;
extern crate hyper;
extern crate hyper_hawk;
extern crate url;

use std::process::{Command, Child};
use hawk::{RequestBuilder, Credentials, Key, SHA256, PayloadHasher};
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use hyper_hawk::{HawkScheme, ServerAuthorization};
use hyper::Client;
use hyper::header;
use url::Url;

// the port the JS side uses
const PORT: u16 = 62835;
const CALLBACK_PORT: u16 = PORT + 1;

fn start_node_script(script: &str) -> Child {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", CALLBACK_PORT)).unwrap();

    // check for `node_modules' first
    let path = Path::new("tests/node/node_modules");
    if !path.is_dir() {
        panic!("Run `yarn` or `npm install` in tests/node");
    }

    let child = Command::new("node")
        .arg(script)
        .arg(format!("{}", PORT))
        .arg(format!("{}", CALLBACK_PORT))
        .current_dir("tests/node")
        .spawn()
        .expect("node command failed to start");

    // wait until the process is ready, signalled by a connect to the callback port
    for stream in listener.incoming() {
        drop(stream);
        break;
    }
    child
}

#[test]
fn client_with_header() {
    let mut child = start_node_script("serve-one.js");

    let credentials = Credentials {
        id: "dh37fgj492je".to_string(),
        key: Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", &SHA256),
    };
    let url = Url::parse(&format!("http://localhost:{}/resource", PORT)).unwrap();
    let body = "foo=bar";

    let payload_hash = PayloadHasher::hash("text/plain".as_bytes(), &SHA256, body.as_bytes());
    let request = RequestBuilder::from_url("POST", &url)
        .unwrap()
        .hash(Some(&payload_hash))
        .ext(Some("ext-content"))
        .request();
    let mut headers = hyper::header::Headers::new();
    let header = request.make_header(&credentials).unwrap();
    headers.set(header::Authorization(HawkScheme(header.clone())));
    headers.set(header::ContentType::plaintext());

    let client = Client::new();
    let mut res = client
        .post(url.as_str())
        .headers(headers)
        .body(body)
        .send()
        .unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    assert!(res.status == hyper::Ok);
    assert!(body == "Hello Steve ext-content");

    // validate server's signature
    {
        let server_hdr: &ServerAuthorization<HawkScheme> = res.headers.get().unwrap();
        let payload_hash = PayloadHasher::hash("text/plain".as_bytes(), &SHA256, body.as_bytes());
        let response = request
            .make_response_builder(&header)
            .hash(&payload_hash)
            .response();
        if !response.validate_header(&server_hdr, &credentials.key) {
            panic!("authentication of response header failed");
        }
    }

    drop(res);
    drop(client); // close the kept-alive connection

    child.wait().expect("Failure waiting for child");
}
