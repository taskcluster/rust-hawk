extern crate time;
extern crate hawk;
extern crate hyper;
extern crate hyper_hawk;
extern crate url;

use hawk::{Request, Credentials, Key, SHA256, PayloadHasher};
use std::io::{Read, Write};
use hyper_hawk::{HawkScheme, ServerAuthorization};
use hyper::Client;
use hyper::header;
use hyper::server;
use url::Url;
use std::thread;

fn client(send_hash: bool, require_hash: bool, port: u16) {
    let credentials = Credentials {
        id: "test-client".to_string(),
        key: Key::new(vec![1u8; 32], &SHA256),
    };
    let url = Url::parse(&format!("http://localhost:{}/resource", port)).unwrap();
    let body = "foo=bar";

    let payload_hash;
    let mut request = Request::from_url("POST", &url).unwrap();
    // for purposes of the test, we pretend we're using port 9999
    request = request.port(9999);

    if send_hash {
        payload_hash = PayloadHasher::hash("text/plain".as_bytes(), &SHA256, body.as_bytes());
        request = request.hash(Some(&payload_hash));
    }

    let mut headers = hyper::header::Headers::new();
    let header = request.make_header(&credentials).unwrap();
    headers.set(header::Authorization(HawkScheme(header.clone())));

    let client = Client::new();
    let mut res = client.post(url.as_str())
        .headers(headers)
        .body(body)
        .send()
        .unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    assert_eq!(res.status, hyper::Ok);
    assert_eq!(body, "OK");

    let server_hdr: &ServerAuthorization<HawkScheme> = res.headers.get().unwrap();

    // most fields in `Server-Authorization: Hawk` are omitted
    assert_eq!(server_hdr.id, None);
    assert_eq!(server_hdr.ts, None);
    assert_eq!(server_hdr.nonce, None);
    assert_eq!(server_hdr.ext, Some("server-ext".to_string()));
    assert_eq!(server_hdr.app, None);
    assert_eq!(server_hdr.dlg, None);

    let payload_hash;
    let mut response = request.make_response(&header);
    if require_hash {
        payload_hash = PayloadHasher::hash("text/plain".as_bytes(), &SHA256, body.as_bytes());
        response = response.hash(&payload_hash);
    }

    if !response.validate_header(&server_hdr, &credentials.key) {
        panic!("authentication of response header failed");
    }
}

struct TestHandler {
    require_hash: bool,
    send_hash: bool,
}

impl server::Handler for TestHandler {
    fn handle(&self, mut req: server::Request, mut res: server::Response) {
        // get the body
        let mut body = String::new();
        req.read_to_string(&mut body).unwrap();

        // get the Authorization header the client sent
        let hdr: &header::Authorization<HawkScheme> = req.headers.get().unwrap();

        // build a request object based on what we know
        let payload_hash;
        let mut request = Request::new("POST", "localhost", 9999, "/resource");

        // add a body hash, if we require such a thing
        if self.require_hash {
            payload_hash = PayloadHasher::hash("text/plain".as_bytes(), &SHA256, body.as_bytes());
            request = request.hash(Some(&payload_hash));
        }

        assert_eq!(hdr.id, Some("test-client".to_string()));
        assert_eq!(hdr.ext, None);
        let key = Key::new(vec![1u8; 32], &SHA256);
        if !request.validate_header(&hdr, &key, time::Duration::minutes(1)) {
            panic!("header validation failed");
        }

        let body = "OK".as_bytes();
        let payload_hash;
        let mut response = request.make_response(&hdr).ext("server-ext");
        if self.send_hash {
            payload_hash = PayloadHasher::hash("text/plain".as_bytes(), &SHA256, body);
            response = response.hash(&payload_hash);
        }
        let server_hdr = response.make_header(&key).unwrap();
        res.headers_mut()
            .set(ServerAuthorization(HawkScheme(server_hdr)));

        res.headers_mut()
            .set(header::ContentLength(body.len() as u64));

        let mut res = res.start().unwrap();
        res.write_all(body).unwrap();
    }
}

fn run_client_server(client_send_hash: bool,
                     server_require_hash: bool,
                     server_send_hash: bool,
                     client_require_hash: bool) {
    let handler = TestHandler {
        require_hash: server_require_hash,
        send_hash: server_send_hash,
    };
    let mut server = server::Server::http(("127.0.0.1", 0)).unwrap();
    let local_address = server.local_addr().unwrap();
    let mut listening = server.handle_threads(handler, 1).unwrap();
    let client_thread = thread::spawn(move || {
        client(client_send_hash, client_require_hash, local_address.port());
    });

    // finish both threads
    let client_res = client_thread.join();
    listening.close().unwrap();

    // *then* evaluate client_res
    if let Err(_) = client_res {
        panic!("client failed");
    }
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
