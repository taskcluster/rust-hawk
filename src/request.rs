use ring::hmac;
use std::io;
use std::io::Write;
use super::context::Context;
use time;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use url::Url;

// import the digest algorithms here
pub use ring::digest::{SHA1, SHA256, SHA384, SHA512};

pub struct Request<'a> {
    pub context: &'a Context<'a>,
    pub url: &'a str,
    pub method: &'a str,
    pub ext: Option<&'a String>,
    pub hash: Option<&'a Vec<u8>>,
}

impl<'a> Request<'a> {
    /// Calculate the MAC for a request
    pub fn make_request_mac(&self,
                            ts: time::Timespec,
                            nonce: &String)
                            -> Result<Vec<u8>, io::Error> {
        // TODO: return Result<.., String> use map/map_err
        let url = match Url::parse(self.url) {
            Ok(u) => u,
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };
        let path = url.path();
        let host = match url.host_str() {
            Some(h) => h,
            None => {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          format!("url {} has no host", url)));
            }
        };
        let port = match url.port() {
            Some(p) => p,
            None => {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          format!("url {} has no port", url)));
            }
        };

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

        let digest = hmac::sign(&self.context.credentials.key, buffer.as_ref());

        // TODO: store the mac in the header as a Digest
        let mut mac = vec![0; self.context.credentials.key.digest_algorithm().output_len];
        mac.clone_from_slice(digest.as_ref());
        return Ok(mac);
    }
}
