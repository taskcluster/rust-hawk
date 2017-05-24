use hyper::header::Scheme;
use std::str::FromStr;
use std::fmt;
use hawk::Header;
use std::ops::Deref;

/// HawkScheme is a Hyper Scheme implementation for Hawk Authorization headers.
///
/// The HawkScheme type dereferences to a Hawk Header, allowing access to all members and methods of
/// that type.
#[derive(Clone, PartialEq, Debug)]
pub struct HawkScheme(pub Header);

impl Deref for HawkScheme {
    type Target = Header;

    fn deref(&self) -> &Header {
        &self.0
    }
}

impl FromStr for HawkScheme {
    type Err = String;
    fn from_str(s: &str) -> Result<HawkScheme, String> {
        match Header::from_str(s) {
            Ok(h) => Ok(HawkScheme(h)),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl Scheme for HawkScheme {
    fn scheme() -> Option<&'static str> {
        Some("Hawk")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_header(f)
    }
}
