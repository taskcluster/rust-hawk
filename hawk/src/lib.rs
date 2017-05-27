//! The `hawk` crate provides support for (Hawk)[https://github.com/hueniverse/hawk]
//! authentictation. It is a low-level crate, used by higher-level crates to integrate with various
//! Rust HTTP libraries.  For example `hyper-hawk` integrates Hawk with Hyper.
//!
//! # Examples
//!
//! ## Hawk Client
//!
//! A client can attach a Hawk Authorization header to requests by providing credentials to a
//! Request instance, which will generate the header.
//!
//! ```
//! #[macro_use] extern crate pretty_assertions;
//! extern crate time;
//! extern crate hawk;
//!
//! use hawk::{Request, Credentials, Key, SHA256};
//!
//! fn main() {
//!     // provide the Hawk id and key
//!     let credentials = Credentials {
//!         id: "test-client".to_string(),
//!         key: Key::new(vec![99u8; 32], &SHA256),
//!     };
//!
//!     // provide the details of the request to be authorized
//!     let request = Request::new()
//!         .method("GET")
//!         .host("example.com")
//!         .port(80)
//!         .path("/v1/users");
//!
//!     // Get the resulting header, including the calculated MAC; this involves a random nonce,
//!     // so the MAC will be different on every request.
//!     let header = request.generate_header(&credentials).unwrap();
//!
//!     // the header would the be attached to the request
//!     assert_eq!(header.id.unwrap(), "test-client");
//!     assert_eq!(header.mac.unwrap().len(), 32);
//! }
//! ```
//!
//! ## Hawk Server
//!
//! To act as a server, parse the Hawk Authorization header from the request, generate a new
//! Request instance, and use the request to validate the header.
//!
//! ```
//! extern crate time;
//! extern crate hawk;
//!
//! use hawk::{Request, Header, Key, SHA256};
//! use hawk::mac::Mac;
//!
//! fn main() {
//!    // get the header (usually from the received request; constructed directly here)
//!    let hdr = Header::new(Some("dh37fgj492je"),
//!                          Some(time::Timespec::new(1353832234, 0)),
//!                          Some("j4h3g2"),
//!                          Some(Mac::from(vec![3, 102, 145, 192, 59, 2, 81, 152, 71, 105, 85,
//!                             211, 41, 150, 137, 209, 136, 84, 123, 115, 50, 221, 18, 76, 101,
//!                             247, 54, 46, 10, 236, 193, 52])),
//!                          Some("my-ext-value"),
//!                          Some(vec![1, 2, 3, 4]),
//!                          Some("my-app"),
//!                          Some("my-dlg"));
//!
//!    // build a request object based on what we know
//!    let hash = vec![1, 2, 3, 4];
//!    let request = Request::new()
//!        .method("GET")
//!        .host("localhost")
//!        .port(443)
//!        .path("/resource")
//!        .hash(Some(&hash));
//!
//!    let key = Key::new(vec![99u8; 32], &SHA256);
//!    if !request.validate_header(&hdr, &key, time::Duration::weeks(5200)) {
//!        panic!("header validation failed. Is it 2117 already?");
//!    }
//! }
extern crate rustc_serialize;
extern crate time;
extern crate ring;
extern crate url;
extern crate rand;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

mod header;
pub use header::Header;

mod credentials;
pub use credentials::{Credentials, Key};

mod request;
pub use request::Request;

mod error;
pub use error::HawkError;

pub mod mac;

// convenience imports
pub use ring::digest::{SHA256, SHA384, SHA512};
