use hyper::header::Scheme as HyperScheme;
use std::str::FromStr;
use std::fmt;
use hawk::Header;

#[derive(Clone, PartialEq, Debug)]
pub struct Scheme(pub Header);

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
