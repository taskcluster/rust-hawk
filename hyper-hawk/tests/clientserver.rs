extern crate time;
extern crate hawk;
extern crate hyper;
extern crate hyper_hawk;
extern crate url;

use hawk::{Request, Header, Credentials, Key, SHA256};
use std::io::{Read, Write};
use hyper_hawk::{HawkScheme, ServerAuthorization};
use hyper::Client;
use hyper::header;
use hyper::server;
use url::Url;

const PORT: u16 = 9981;

struct TestHandler {}

impl server::Handler for TestHandler {
    fn handle(&self, req: server::Request, mut res: server::Response) {
        let hdr: &header::Authorization<HawkScheme> = req.headers.get().unwrap();

        let key = Key::new(vec![1u8; 32], &SHA256);
        hdr.validate(&key,
                      "GET",
                      "localhost",
                      PORT,
                      "/resource",
                      time::Duration::minutes(1))
            .unwrap();

        let server_hdr = Header::new(hdr.id.clone(),
                                     None,
                                     hdr.nonce.clone(),
                                     None,
                                     None,
                                     None,
                                     None,
                                     None);
        res.headers_mut()
            .set(ServerAuthorization(HawkScheme(server_hdr)));

        let body = b"OK";
        res.headers_mut()
            .set(header::ContentLength(body.len() as u64));

        let mut res = res.start().unwrap();
        res.write_all(body).unwrap();
    }
}

fn client() {
    let credentials = Credentials {
        id: "test-client".to_string(),
        key: Key::new(vec![1u8; 32], &SHA256),
    };
    let url = Url::parse(&format!("http://localhost:{}/resource", PORT)).unwrap();
    let request = Request::new().method("GET").url(&url).unwrap();
    let mut headers = hyper::header::Headers::new();
    let header = request.generate_header(&credentials).unwrap();
    let nonce = header.nonce.clone();
    headers.set(header::Authorization(HawkScheme(header)));

    let client = Client::new();
    let mut res = client
        .get(url.as_str())
        .headers(headers)
        .send()
        .unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    assert!(res.status == hyper::Ok);
    assert!(body == "OK");

    let server_hdr: &ServerAuthorization<HawkScheme> = res.headers.get().unwrap();
    assert_eq!(server_hdr.id, Some("test-client".to_string()));
    assert_eq!(server_hdr.nonce, nonce);
}

#[test]
/// Set up a client and a server and authenticate a request from one to the other.
fn clientserver() {
    let handler = TestHandler {};
    let server = server::Server::http(("127.0.0.1", PORT)).unwrap();
    let mut listening = server.handle_threads(handler, 1).unwrap();
    client();

    listening.close().unwrap();
}
