//! The `hawk` crate provides support for [Hawk](https://github.com/hueniverse/hawk)
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
//! use hawk::{RequestBuilder, Credentials, Key, SHA256, PayloadHasher};
//!
//! fn main() {
//!     // provide the Hawk id and key
//!     let credentials = Credentials {
//!         id: "test-client".to_string(),
//!         key: Key::new(vec![99u8; 32], &SHA256),
//!     };
//!
//!     let payload_hash = PayloadHasher::hash("text/plain", &SHA256, "request-body");
//!
//!     // provide the details of the request to be authorized
//!      let request = RequestBuilder::new("POST", "example.com", 80, "/v1/users")
//!         .hash(&payload_hash[..])
//!         .request();
//!
//!     // Get the resulting header, including the calculated MAC; this involves a random
//!     // nonce, so the MAC will be different on every request.
//!     let header = request.make_header(&credentials).unwrap();
//!
//!     // the header would the be attached to the request
//!     assert_eq!(header.id.unwrap(), "test-client");
//!     assert_eq!(header.mac.unwrap().len(), 32);
//!     assert_eq!(header.hash.unwrap().len(), 32);
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
//! use hawk::{RequestBuilder, Header, Key, SHA256};
//! use hawk::mac::Mac;
//!
//! fn main() {
//!    let mac = Mac::from(vec![7, 22, 226, 240, 84, 78, 49, 75, 115, 144, 70,
//!                             106, 102, 134, 144, 128, 225, 239, 95, 132, 202,
//!                             154, 213, 118, 19, 63, 183, 108, 215, 134, 118, 115]);
//!    // get the header (usually from the received request; constructed directly here)
//!    let hdr = Header::new(Some("dh37fgj492je"),
//!                          Some(time::Timespec::new(1353832234, 0)),
//!                          Some("j4h3g2"),
//!                          Some(mac),
//!                          Some("my-ext-value"),
//!                          Some(vec![1, 2, 3, 4]),
//!                          Some("my-app"),
//!                          Some("my-dlg")).unwrap();
//!
//!    // build a request object based on what we know
//!    let hash = vec![1, 2, 3, 4];
//!    let request = RequestBuilder::new("GET", "localhost", 443, "/resource")
//!        .hash(&hash[..])
//!        .request();
//!
//!    let key = Key::new(vec![99u8; 32], &SHA256);
//!    if !request.validate_header(&hdr, &key, time::Duration::weeks(5200)) {
//!        panic!("header validation failed. Is it 2117 already?");
//!    }
//! }
extern crate base64;
extern crate time;
extern crate ring;
extern crate url;
extern crate rand;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[macro_use]
extern crate error_chain;

mod header;
pub use header::Header;

mod credentials;
pub use credentials::{Credentials, Key};

mod request;
pub use request::{Request, RequestBuilder};

mod response;
pub use response::{Response, ResponseBuilder};

mod error;
pub use error::*;

mod payload;
pub use payload::PayloadHasher;

mod bewit;
pub use bewit::Bewit;

pub mod mac;

// convenience imports
pub use ring::digest::{SHA256, SHA384, SHA512};
