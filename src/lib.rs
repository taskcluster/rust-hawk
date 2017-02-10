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
//! extern crate ring;
//!
//! use hawk::Request;
//! use hawk::SHA256;
//! use hawk::Credentials;
//! use hyper::Client;
//! use hyper::client::IntoUrl;
//!
//! fn main() {
//!     let mut headers = hyper::header::Headers::new();
//!     let credentials = Credentials::new("test-client", "no-secret", &SHA256);
//!     let request = Request::new("http://localhost:8000/resource".into_url().unwrap(),
//!                                hyper::Get,
//!                                credentials,
//!                                None,
//!                                None,
//!                                None,
//!                                None);
//!     headers.set(hyper::header::Authorization(request.hyper_scheme().unwrap()));
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
extern crate rustc_serialize;
extern crate time;
extern crate ring;

mod scheme;
pub use scheme::Scheme;

mod request;
pub use request::{Credentials, Request};

// Hawk does not specify the set of allowable digest algorithsm; this set represents the algorithms
// currently available from ring.
pub use ring::digest::{SHA1, SHA256, SHA384, SHA512};
