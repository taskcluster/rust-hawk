//! Library for authenticating HTTP requests and responses with Hawk.
//!
//! # Examples
//!
//! Note that this example requires a working Hawk server on port 8000, which can be
//! provided by ./node-server/server.js.
//!
//! ```
//! extern crate time;
//! extern crate hawk;
//! extern crate hyper;
//! extern crate hyper_hawk;
//! extern crate ring;
//!
//! use hawk::Request;
//! use hawk::Credentials;
//! use hawk::Context;
//! use hawk::Header;
//! use ring::digest::SHA256;
//! use hyper_hawk::Scheme;
//! use hyper::Client;
//!
//! fn main() {
//!     let rng = ring::rand::SystemRandom::new();
//!     let credentials = Credentials::new("test-client", "no-secret", &SHA256);
//!     let context = Context{
//!         credentials: &credentials,
//!         rng: &rng,
//!         app: None,
//!         dlg: None,
//!     };
//!     let mut headers = hyper::header::Headers::new();
//!     let request = Request{
//!         context: &context,
//!         url: "http://localhost:8000/resource",
//!         method: "GET",
//!         ext: None,
//!         hash: None};
//!     headers.set(hyper::header::Authorization(Scheme(Header::for_request(&request).unwrap())));
//!
//!     let client = Client::new();
//!     let res = client.get("http://localhost:8000/resource")
//!         .headers(headers)
//!         .send()
//!         .unwrap();
//!
//!     println!("GET -> {}; {}", res.status, res.headers);
//!     assert!(res.status == hyper::Ok);
//! }
//! ```

extern crate hyper;
extern crate hawk;
extern crate rustc_serialize;
extern crate time;
extern crate ring;
extern crate url;

mod scheme;
pub use scheme::Scheme;
