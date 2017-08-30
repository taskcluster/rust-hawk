//! Library for authenticating HTTP requests and responses with Hawk.
//!
//! Most functionality comes directly from the `hawk` crate; this merely adds support for the
//! [HawkScheme] [Authorization](hyper::header::Authorization) scheme and a new (nonstandard)
//! [ServerAuthorization] header.

extern crate hyper;
extern crate hawk;
extern crate rustc_serialize;
extern crate time;
extern crate url;

mod serverauth;
pub use serverauth::ServerAuthorization;

mod authscheme;
pub use authscheme::HawkScheme;
