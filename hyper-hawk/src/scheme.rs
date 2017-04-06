use hyper::header::Scheme as HyperScheme;
use std::str::FromStr;
use std::fmt;
use hawk::{Header, Key};
use std::ops::Deref;
use time;

#[derive(Clone, PartialEq, Debug)]
pub struct Scheme(pub Header);

/// Scheme is a Hyper Scheme implementation for Hawk Authorization headers.
///
/// The Scheme type dereferences to a Hawk Header, allowing access to all members and methods of
/// that type.
impl Scheme {
    /// Validate the header was generated with the given key.  Returns nothing if the header is OK,
    /// otherwise an error message.
    pub fn validate(&self,
                    key: &Key,
                    method: &str,
                    hostname: &str,
                    port: u16,
                    path: &str,
                    ts_skew: time::Duration)
                    -> Result<(), String> {
        if !self.0.validate_mac(key, method, hostname, port, path, ts_skew) {
            // this is deliberately brief, to avoid leaking information that might be useful
            // in attacking the MAC algorithm
            return Err("Bad MAC".to_string());
        }
        Ok(())
    }
}

impl Deref for Scheme {
    type Target = Header;

    fn deref(&self) -> &Header {
        &self.0
    }
}

impl FromStr for Scheme {
    type Err = String;
    fn from_str(s: &str) -> Result<Scheme, String> {
        match Header::from_str(s) {
            Ok(h) => Ok(Scheme(h)),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl HyperScheme for Scheme {
    fn scheme() -> Option<&'static str> {
        Some("Hawk")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_header(f)
    }
}
