extern crate time;
extern crate hawk;
extern crate hyper;
extern crate hyper_hawk;
extern crate ring;

use hawk::{Request, Credentials, Context, Header};
use std::io::{Read, Write};
use ring::digest::SHA256;
use hyper_hawk::Scheme;
use hyper::Client;
use hyper::header;
use hyper::server;

const PORT: u16 = 9981;

struct TestHandler {}

impl server::Handler for TestHandler {
    fn handle(&self, req: server::Request, mut res: server::Response) {
        let raw = String::from_utf8(req.headers.get_raw("Authorization").unwrap()[0].clone()).unwrap();
        println!("Raw Authorization header: {:?}", raw);
        let hdr: Option<&header::Authorization<Scheme>> = req.headers.get();
        println!("Parsed Authorization header: {:?}", hdr);

        let credentials = Credentials::new("test-client", "no-secret", &SHA256);
        hdr.unwrap().validate(&credentials, "localhost", PORT, "/resource", "GET").unwrap();

        let body = b"OK";
        res.headers_mut().set(header::ContentLength(body.len() as u64));
        let mut res = res.start().unwrap();
        res.write_all(body).unwrap();
    }
}

fn client() {
    let rng = ring::rand::SystemRandom::new();
    let credentials = Credentials::new("test-client", "no-secret", &SHA256);
    let context = Context{
        credentials: &credentials,
        rng: &rng,
        app: None,
        dlg: None,
    };
    let mut headers = hyper::header::Headers::new();
    let url =format!("http://localhost:{}/resource", PORT); 
    let request = Request{
        context: &context,
        url: &url,
        method: "GET",
        ext: None,
        hash: None};
    headers.set(header::Authorization(
            Scheme(Header::for_request(&request).unwrap())));

    let client = Client::new();
    let mut res = client.get(&url)
        .headers(headers)
        .send()
        .unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    assert!(res.status == hyper::Ok);
    assert!(body == "OK");
}

#[test]
fn clientserver() {
    let handler = TestHandler{};
    let server = server::Server::http(("127.0.0.1", PORT)).unwrap();
    let mut listening = server.handle_threads(handler, 1).unwrap();
    client();

    listening.close().unwrap();
}
