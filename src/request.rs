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
    hash: Option<Vec<u8>>,
    app: Option<String>,
    dlg: Option<String>,
}

impl Request {
    /// Create a new Request with the given details.
    pub fn new(url: Url,
               method: Method,
               credentials: Credentials,
               ext: Option<String>,
               hash: Option<Vec<u8>>,
               app: Option<String>,
               dlg: Option<String>)
               -> Request {
        Request {
            url: url,
            method: method,
            credentials: credentials,
            ext: ext,
            hash: hash,
            app: app,
            dlg: dlg,
        }
    }

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
        try!(write!(buffer,
                    "{}\n",
                    match self.hash {
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

        return Ok(mac);
    }

    pub fn hyper_scheme(&self) -> Result<Scheme, String> {
        let id = "id".to_string(); // TODO: random (extern crate rand); move to Request
        let ts = time::now_utc().to_timespec();
        let nonce = "nonce".to_string(); // TODO: random
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
        return Ok(Scheme::new_extended(id,
                                       ts,
                                       nonce,
                                       mac,
                                       self.ext.clone(),
                                       self.hash.clone(),
                                       self.app.clone(),
                                       self.dlg.clone()));
    }
}
