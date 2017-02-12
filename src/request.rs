use ring::{digest, hmac};
use hyper::method::Method;
use hyper::Url;
use std::io;
use std::io::Write;
use super::scheme::Scheme;
use time;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use ring::rand;

// import the digest algorithms here
pub use ring::digest::{SHA1, SHA256, SHA384, SHA512};

pub struct Credentials {
    pub id: String,
    pub key: hmac::SigningKey,
}

impl Credentials {
    pub fn new<S, B>(id: S, key: B, algorithm: &'static digest::Algorithm) -> Credentials
        where S: Into<String>,
              B: Into<Vec<u8>>
    {
        let key = key.into();
        let key = hmac::SigningKey::new(algorithm, key.as_ref());
        Credentials {
            id: id.into(),
            key: key.into(),
        }
    }
}

pub struct Request<'a> {
    url: Url,
    method: Method,
    credentials: &'a Credentials,
    ext: Option<&'a String>,
    hash: Option<&'a Vec<u8>>,
    app: Option<&'a String>,
    dlg: Option<&'a String>,
    rng: &'a rand::SecureRandom,
}

impl<'a> Request<'a> {
    /// Create a new Request with the given details.
    /// TODO: replace with defaults
    pub fn new(url: Url,
               method: Method,
               credentials: &'a Credentials,
               ext: Option<&'a String>,
               hash: Option<&'a Vec<u8>>,
               app: Option<&'a String>,
               dlg: Option<&'a String>,
               rng: &'a rand::SecureRandom)
               -> Request<'a> {
        Request {
            url: url,
            method: method,
            credentials: credentials,
            ext: ext,
            hash: hash,
            app: app,
            dlg: dlg,
            rng: rng,
        }
    }

    /// Create a random string with `bytes` bytes of entropy.  The string
    /// is base64-encoded. so it will be longer than bytes characters.
    fn random_string(&self, bytes: usize) -> Result<String, String> {
        let mut bytes = vec![0u8; bytes];
        if let Err(_) = self.rng.fill(&mut bytes) {
            return Err("Cannot create random string".to_string());
        }
        Ok(bytes.to_base64(base64::Config {
            char_set: base64::CharacterSet::Standard,
            newline: base64::Newline::LF,
            pad: true,
            line_length: None,
        }))
    }

    /// Calculate the MAC for a request
    fn make_request_mac(&self,
                        ts: time::Timespec,
                        nonce: &String,
                        path: &str,
                        host: &str,
                        port: u16)
                        -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = vec![];
        try!(write!(buffer, "hawk.1.header\n"));
        try!(write!(buffer, "{}\n", ts.sec));
        try!(write!(buffer, "{}\n", nonce));
        try!(write!(buffer, "{}\n", self.method));
        try!(write!(buffer, "{}\n", path));
        try!(write!(buffer, "{}\n", host));
        try!(write!(buffer, "{}\n", port));

        if let Some(ref h) = self.hash {
            try!(write!(buffer,
                        "{}\n",
                        h.to_base64(base64::Config {
                            char_set: base64::CharacterSet::Standard,
                            newline: base64::Newline::LF,
                            pad: true,
                            line_length: None,
                        })));
        } else {
            try!(write!(buffer, "\n"));
        }

        if let Some(ref e) = self.ext {
            try!(write!(buffer, "{}\n", e));
        } else {
            try!(write!(buffer, "\n"));
        }

        println!("{:?}", String::from_utf8(buffer.clone()).unwrap());

        let digest = hmac::sign(&self.credentials.key, buffer.as_ref());

        // TODO: store the mac in the header as a Digest
        let mut mac = vec![0; self.credentials.key.digest_algorithm().output_len];
        mac.clone_from_slice(digest.as_ref());
        return Ok(mac);
    }

    pub fn hyper_scheme(&self) -> Result<Scheme, String> {
        let id = self.credentials.id.clone();
        let ts = time::now_utc().to_timespec();
        let nonce = try!(self.random_string(10));
        let path = self.url.path();
        let host = match self.url.host_str() {
            Some(h) => h,
            None => {
                return Err(format!("url {} has no host", self.url));
            }
        };
        let port = match self.url.port() {
            Some(p) => p,
            None => {
                return Err(format!("url {} has no port", self.url));
            }
        };

        let mac = match self.make_request_mac(ts, &nonce, path, host, port) {
            Ok(mac) => mac,
            Err(ioerr) => {
                return Err(ioerr.to_string());
            }
        };

        let ext = match self.ext {
            Some(ext) => Some(ext.clone()),
            None => None,
        };

        let hash = match self.hash {
            Some(hash) => Some(hash.clone()),
            None => None,
        };

        let app = match self.app {
            Some(app) => Some(app.clone()),
            None => None,
        };

        let dlg = match self.dlg {
            Some(dlg) => Some(dlg.clone()),
            None => None,
        };

        return Ok(Scheme::new_extended(id, ts, nonce, mac, ext, hash, app, dlg));
    }
}