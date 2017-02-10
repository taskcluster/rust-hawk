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
//!
//! use hawk::Request;
//! use hawk::Credentials;
//! use hyper::Client;
//! use hyper::client::IntoUrl;
//!
//! fn main() {
//!     let mut headers = hyper::header::Headers::new();
//!     let credentials = Credentials::new("test-client", "no-secret", "sha256");
//!     let request = Request::new("http://localhost:8000/resource".into_url().unwrap(),
//!                                hyper::Get,
//!                                credentials,
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
//! }
//! ```

extern crate hyper;
extern crate rustc_serialize;
extern crate time;
extern crate crypto;

mod scheme;
pub use scheme::HawkScheme;

mod request;
pub use request::{Credentials, Request};
