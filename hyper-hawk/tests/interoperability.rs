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
use std::str::FromStr;
use url::Url;

fn start_node_server() -> (Child, u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", 0)).unwrap();
    let callback_port = listener.local_addr().unwrap().port();

    // check for `node_modules' first
    let path = Path::new("tests/node/node_modules");
    if !path.is_dir() {
        panic!("Run `yarn` or `npm install` in tests/node, or test with --feautures \
                no-interoperability");
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
    #[allow(never_loop)]
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
        key: Key::new("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", &SHA256),
    }
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_header() {
    let (mut child, port) = start_node_server();

    let credentials = make_credentials();
    let url = Url::parse(&format!("http://localhost:{}/resource", port)).unwrap();
    let body = "foo=bar";

    let payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_bytes());
    let request = RequestBuilder::from_url("POST", &url)
        .unwrap()
        .hash(&payload_hash[..])
        .ext("ext-content")
        .request();
    let mut headers = hyper::header::Headers::new();
    let header = request.make_header(&credentials).unwrap();
    headers.set(header::Authorization(HawkScheme(header.clone())));
    headers.set(header::ContentType::plaintext());

    let client = Client::new();
    let mut res = client.post(url.as_str())
        .headers(headers)
        .body(body)
        .send()
        .unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    assert_eq!(res.status, hyper::Ok);
    assert_eq!(body, "Hello Steve ext-content");

    // validate server's signature
    {
        let server_hdr: &ServerAuthorization<HawkScheme> = res.headers.get().unwrap();
        let payload_hash = PayloadHasher::hash(b"text/plain", &SHA256, body.as_bytes());
        let response = request.make_response_builder(&header)
            .hash(&payload_hash[..])
            .response();
        if !response.validate_header(server_hdr, &credentials.key) {
            panic!("authentication of response header failed");
        }
    }

    drop(res);
    drop(client); // close the kept-alive connection

    child.wait().expect("Failure waiting for child");
}

#[cfg_attr(feature = "no-interoperability", ignore)]
#[test]
fn client_with_bewit() {
    let (mut child, port) = start_node_server();

    let credentials = make_credentials();
    let url = Url::parse(&format!("http://localhost:{}/resource", port)).unwrap();
    let request = RequestBuilder::from_url("GET", &url)
        .unwrap()
        .ext("ext-content")
        .request();

    let bewit = request.make_bewit(&credentials, time::Duration::minutes(1))
        .unwrap();
    let mut url = url.clone();
    url.set_query(Some(&format!("bewit={}", bewit.to_str())));

    let client = Client::new();
    let mut res = client.get(url.as_str()).send().unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    assert_eq!(res.status, hyper::Ok);
    assert_eq!(body, "Hello Steve ext-content");

    drop(res);
    drop(client); // close the kept-alive connection

    child.wait().expect("Failure waiting for child");
}
