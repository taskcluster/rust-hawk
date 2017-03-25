//! This create provides general support for Hawk authentictation.
//!
//! # Examples
//!
//! ## Hawk Client
//!
//! ```
//! extern crate time;
//! extern crate hawk;
//! extern crate ring;
//!
//! use hawk::Request;
//! use hawk::Credentials;
//! use hawk::Context;
//! use hawk::Header;
//! use ring::digest::SHA256;
//! use ring::rand;
//!
//! fn main() {
//!     let rng = rand::SystemRandom::new();
//!     // provide the Hawk id and key
//!     let credentials = Credentials::new("test-client", "no-secret", &SHA256);
//!     // provide some context that might span multple requests
//!     let context = Context{
//!         credentials: &credentials,
//!         rng: &rng,
//!         app: None,
//!         dlg: None,
//!     };
//!     // and finally, provide the details of the request to be authorized
//!     let request = Request{
//!         context: &context,
//!         url: "http://localhost:8000/resource",
//!         method: "GET",
//!         ext: None,
//!         hash: None};
//!
//!     // get the resulting header, including the calculated MAC
//!     let header = Header::for_request(&request).unwrap();
//!     let header = format!("{}", header);
//!     println!("{}", header);
//!     assert!(header.starts_with("id="));
//!     assert!(header.contains("mac="));
//! }
//!
//! ```
extern crate rustc_serialize;
extern crate time;
extern crate ring;
extern crate url;

mod header;
pub use header::Header;

mod context;
pub use context::{Credentials, Context};

mod request;
pub use request::Request;
