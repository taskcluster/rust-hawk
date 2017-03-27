use hyper::header::Scheme as HyperScheme;
use std::str::FromStr;
use std::fmt;
use time;
use ring::{hmac, rand};
use hawk::{Request, Header, Context, Credentials};

#[derive(Clone, PartialEq, Debug)]
pub struct Scheme(pub Header);

impl Scheme {
    fn id(&self) -> &String {
        &self.0.id
    }

    /// Validate the header was generated with the given key.
    pub fn validate(&self, credentials: &Credentials, hostname: &str, port: u16, path: &str, method: &str) -> Result<(), String> {
        // TODO: validate hash against body?
        let rng = rand::SystemRandom::new();
        let context = Context{
            credentials: &credentials,
            rng: &rng,
            app: None,
            dlg: None,
        };
        let req = Request{
            context: &context,
            url: &format!("https://{}:{}{}", hostname, port, path)[..],
            method: method,
            ext: None, // XXX
            hash: None, // XXX
        };
        match req.make_mac(self.0.ts, &self.0.nonce) {
            Err(e) => Err(e),
            Ok(mac) => {
                println!("Server calculated MAC: {:?}", mac);
                if mac == self.0.mac {
                Ok(())
            } else {
                Err("Bad MAC".to_string())
            }
            }
        }
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
