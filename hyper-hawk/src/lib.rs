//! Library for authenticating HTTP requests and responses with Hawk.
//!
//! # Examples
//!
//! ```
//! # extern crate time;
//! # extern crate hawk;
//! # extern crate hyper;
//! # extern crate hyper_hawk;
//! # extern crate url;
//! use hawk::{Request, Credentials, Key, SHA256};
//! use std::io::{Read, Write};
//! use hyper_hawk::{HawkScheme, ServerAuthorization};
//! use hyper::Client;
//! use hyper::header;
//! use hyper::server;
//! use url::Url;
//! use std::thread;
//!
//! const PORT: u16 = 9981;
//!
//! fn client() {
//!     let credentials = Credentials {
//!         id: "test-client".to_string(),
//!         key: Key::new(vec![1u8; 32], &SHA256),
//!     };
//!     let url = Url::parse(&format!("http://localhost:{}/resource", PORT)).unwrap();
//!     let request = Request::new().method("GET").url(&url).unwrap();
//!     let mut headers = hyper::header::Headers::new();
//!     let header = request.generate_header(&credentials).unwrap();
//!     // note that HawkScheme must own its header, with no embedded references, because
//!     // it is passed to headers.set, which uses Any, which forbids non-'static references.
//!     headers.set(header::Authorization(HawkScheme(header.clone())));
//!
//!     let client = Client::new();
//!     let mut res = client
//!         .get(url.as_str())
//!         .headers(headers)
//!         .send()
//!         .unwrap();
//!
//!     let mut body = String::new();
//!     res.read_to_string(&mut body).unwrap();
//!     assert!(res.status == hyper::Ok);
//!     assert!(body == "OK");
//!
//!     let server_hdr: &ServerAuthorization<HawkScheme> = res.headers.get().unwrap();
//!
//!     let hash = match server_hdr.hash {
//!         Some(ref h) => Some(&h[..]),
//!         None => None,
//!     };
//!     let ext = match server_hdr.ext {
//!         Some(ref e) => Some(&e[..]),
//!         None => None,
//!     };
//!     let response = request.make_response(&header, hash, ext);
//!
//!     if !response.validate_header(&server_hdr, &credentials.key) {
//!         panic!("authentication of response header failed");
//!     }
//! }
//!
//! struct TestHandler {}
//!
//! impl server::Handler for TestHandler {
//!     fn handle(&self, req: server::Request, mut res: server::Response) {
//!         // get the Authorization header the client sent
//!         let hdr: &header::Authorization<HawkScheme> = req.headers.get().unwrap();
//!
//!         // build a request object based on what we know (note: this would include a body
//!         // hash if one was given)
//!         let request = Request::new()
//!             .method("GET")
//!             .host("localhost")
//!             .port(PORT)
//!             .path("/resource");
//!
//!         let key = Key::new(vec![1u8; 32], &SHA256);
//!         if !request.validate_header(&hdr, &key, time::Duration::minutes(1)) {
//!             panic!("header validation failed");
//!         }
//!
//!         let response = request.make_response(&hdr, None, Some("my-ext"));
//!         let server_hdr = response.generate_header(&key).unwrap();
//!         res.headers_mut()
//!             .set(ServerAuthorization(HawkScheme(server_hdr)));
//!
//!         let body = b"OK";
//!         res.headers_mut()
//!             .set(header::ContentLength(body.len() as u64));
//!
//!         let mut res = res.start().unwrap();
//!         res.write_all(body).unwrap();
//!     }
//! }
//! #
//! # /// Set up a client and a server and authenticate a request from one to the other. #
//! # fn main() {
//! #     let handler = TestHandler {};
//! #     let server = server::Server::http(("127.0.0.1", PORT)).unwrap();
//! #     let mut listening = server.handle_threads(handler, 1).unwrap();
//! #     let client_thread = thread::spawn(client);
//! #
//! #     // finish both threads
//! #     let client_res = client_thread.join();
//! #     listening.close().unwrap();
//! #
//! #     // *then* evaluate client_res
//! #     if let Err(_) = client_res {
//! #         panic!("client failed");
//! #     }
//! # }
//! ```
extern crate hyper;
extern crate hawk;
extern crate rustc_serialize;
extern crate time;
extern crate url;

mod serverauth;
pub use serverauth::ServerAuthorization;

mod authscheme;
pub use authscheme::HawkScheme;
