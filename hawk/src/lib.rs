//! This create provides general support for Hawk authentictation.
//!
//! # Examples
//!
//! ## Hawk Client
//!
//! ```
//! #[macro_use] extern crate pretty_assertions;
//! extern crate time;
//! extern crate hawk;
//! extern crate ring;
//!
//! use hawk::{Request, Credentials, SHA256};
//! use ring::rand;
//!
//! fn main() {
//!     let rng = rand::SystemRandom::new();
//!     // provide the Hawk id and key
//!     let credentials = Credentials::new("test-client", vec![99u8; 32], &SHA256);
//!
//!     // and finally, provide the details of the request to be authorized
//!     let request = Request::new()
//!         .method("GET")
//!         .host("example.com")
//!         .port(80)
//!         .path("/v1/users");
//!
//!     // Get the resulting header, including the calculated MAC; this involves a random
//!     // nonce, so the MAC will be different on every request.
//!     let header = request.generate_header(&rng, &credentials).unwrap();
//!     assert_eq!(header.id, "test-client");
//!     assert_eq!(header.mac.len(), 32);
//! }
//!
//! ```
extern crate rustc_serialize;
extern crate time;
extern crate ring;
extern crate url;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

mod header;
pub use header::Header;

mod credentials;
pub use credentials::Credentials;

mod request;
pub use request::Request;

mod mac;

// convenience imports
pub use ring::digest::{SHA256, SHA384, SHA512};
