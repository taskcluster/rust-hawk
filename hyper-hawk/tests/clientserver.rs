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
    let request = Request::new().method("POST").url(&url).unwrap();
    let mut headers = hyper::header::Headers::new();
    let header = request.make_header(&credentials).unwrap();
    headers.set(header::Authorization(HawkScheme(header.clone())));

    // TODO: how to send a body here?
    let client = Client::new();
    let mut res = client
        .post(url.as_str())
        .headers(headers)
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
    if require_hash {
        assert!(server_hdr.hash.is_some());
    }
    assert_eq!(server_hdr.app, None);
    assert_eq!(server_hdr.dlg, None);

    let payload_hash;
    let mut response = request.make_response(&header);
    if (require_hash) {
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
    port: u16,
}

impl server::Handler for TestHandler {
    fn handle(&self, req: server::Request, mut res: server::Response) {
        // get the Authorization header the client sent
        let hdr: &header::Authorization<HawkScheme> = req.headers.get().unwrap();

        // build a request object based on what we know (note: this would include a body
        // hash if one was given)
        let request = Request::new()
            .method("POST")
            .host("localhost")
            .port(self.port)
            .path("/resource");

        assert_eq!(hdr.id, Some("test-client".to_string()));
        assert_eq!(hdr.ext, None);
        let key = Key::new(vec![1u8; 32], &SHA256);
        if !request.validate_header(&hdr, &key, time::Duration::minutes(1)) {
            panic!("header validation failed");
        }

        let body = "OK".as_bytes();
        let payload_hash;
        let mut response = request.make_response(&hdr).ext("server-ext");
        if (self.send_hash) {
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

// TODO: actually send/require
fn run_client_server(client_send_hash: bool,
                     server_require_hash: bool,
                     server_send_hash: bool,
                     client_require_hash: bool,
                     port: u16) {
    let handler = TestHandler {
        require_hash: server_require_hash,
        send_hash: server_send_hash,
        port: port,
    };
    let server = server::Server::http(("127.0.0.1", port)).unwrap();
    let mut listening = server.handle_threads(handler, 1).unwrap();
    let client_thread =
        thread::spawn(move || { client(client_send_hash, client_require_hash, port); });

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
    run_client_server(false, false, false, false, 9001);
}

#[test]
fn client_sends() {
    run_client_server(true, false, false, false, 9002);
}

#[test]
fn server_requires() {
    run_client_server(true, true, false, false, 9003);
}

#[test]
fn server_sends() {
    run_client_server(true, true, true, false, 9004);
}

#[test]
fn client_requires() {
    run_client_server(true, true, true, true, 9005);
}

#[test]
fn response_hash_only() {
    run_client_server(false, false, true, true, 9006);
}
