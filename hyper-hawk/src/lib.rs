//! Library for authenticating HTTP requests and responses with Hawk.
//!
//! # Examples

extern crate hyper;
extern crate hawk;
extern crate rustc_serialize;
extern crate time;
extern crate url;

mod serverauth;
pub use serverauth::ServerAuthorization;

mod authscheme;
pub use authscheme::HawkScheme;
