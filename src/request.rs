use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use hyper::method::Method;
use hyper::Url;
use std::io;
use std::io::Write;
use super::scheme::Scheme;
use time;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;

#[derive(Debug)]
pub struct Credentials {
    pub id: Vec<u8>,
    pub key: Vec<u8>,
    pub algorithm: String,
}

impl Credentials {
    pub fn new<B, S>(id: B, key: B, algorithm: S) -> Credentials
        where B: Into<Vec<u8>>,
              S: Into<String>
    {
        Credentials {
            id: id.into(),
            key: key.into(),
            algorithm: algorithm.into(),
        }
    }
}

pub struct Request {
    url: Url,
    method: Method,
    credentials: Credentials, // TODO: ref
    ext: Option<String>,
}

impl Request {
    /// Create a new Request with the given details.
    pub fn new(url: Url, method: Method, credentials: Credentials, ext: Option<String>) -> Request {
        Request {
            url: url,
            method: method,
            credentials: credentials,
            ext: ext,
        }
    }

    pub fn hyper_scheme(&self) -> Result<Scheme, io::Error> {
        let id = "id".to_string(); // TODO: random
        let ts = time::now_utc().to_timespec();
        let nonce = "nonce".to_string(); // TODO: random
        let path = self.url.path();
        let host = match self.url.host_str() {
            Some(h) => h,
            None => {
                return Err(io::Error::new(io::ErrorKind::Other, format!("{}", "url has no host")));
            }
        };
        let port = match self.url.port() {
            Some(p) => p,
            None => {
                return Err(io::Error::new(io::ErrorKind::Other, format!("{}", "url has no port")));
            }
        };
        let hash: Option<Vec<u8>> = None; // TODO: allow
        let app = None; // TODO: allow
        let dlg = None; // TODO: allow

        // write the mac's contents, per the Hawk spec
        let mut buffer: Vec<u8> = vec![];
        try!(write!(buffer, "hawk.1.header\n"));
        try!(write!(buffer, "{}\n", ts.sec));
        try!(write!(buffer, "{}\n", nonce));
        try!(write!(buffer, "{}\n", self.method));
        try!(write!(buffer, "{}\n", path));
        try!(write!(buffer, "{}\n", host));
        try!(write!(buffer, "{}\n", port));
        try!(write!(buffer,
                    "{}\n",
                    match hash {
                        Some(ref h) => {
                            h.to_base64(base64::Config {
                                char_set: base64::CharacterSet::Standard,
                                newline: base64::Newline::LF,
                                pad: true,
                                line_length: None,
                            })
                        }
                        None => "".to_string(),
                    }));
        try!(write!(buffer,
                    "{}\n",
                    match self.ext {
                        Some(ref e) => e,
                        None => "",
                    }));

        println!("{:?}", String::from_utf8(buffer.clone()).unwrap());

        assert!(self.credentials.algorithm == "sha256"); // TODO
        let mut hmac = Hmac::new(Sha256::new(), &self.credentials.key);
        println!("{:?}", buffer);
        hmac.input(&buffer);

        let mut mac = vec![0; hmac.output_bytes()];
        hmac.raw_result(&mut mac[..]);

        return Ok(Scheme::new_extended(id, ts, nonce, mac, self.ext.clone(), hash, app, dlg));
    }
}
