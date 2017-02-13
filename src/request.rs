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
    /// Calculate the MAC for the request, given the timestamp and nonce
    pub fn make_mac(&self, ts: time::Timespec, nonce: &String) -> Result<Vec<u8>, String> {
        let url = try!(Url::parse(self.url).map_err(|err| err.to_string()));
        let path = url.path();
        let host = try!(url.host_str().ok_or(format!("url {} has no host", url)));
        let port = try!(url.port().ok_or(format!("url {} has no port", url)));

        let mut buffer: Vec<u8> = vec![];
        let fill = |buffer: &mut Vec<u8>| {
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

            match self.ext {
                Some(e) => try!(write!(buffer, "{}\n", e)),
                None => try!(write!(buffer, "\n")),
            };
            Ok(())
        };
        try!(fill(&mut buffer).map_err(|err: io::Error| err.to_string()));

        println!("{:?}", String::from_utf8(buffer.clone()).unwrap());

        let digest = hmac::sign(&self.context.credentials.key, buffer.as_ref());

        // TODO: store the mac in the header as a Digest
        let mut mac = vec![0; self.context.credentials.key.digest_algorithm().output_len];
        mac.clone_from_slice(digest.as_ref());
        return Ok(mac);
    }
}
