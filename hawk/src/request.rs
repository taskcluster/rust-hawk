use ring::hmac;
use std::io;
use std::io::Write;
use super::context::Context;
use time;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use url::Url;

/// Representation of a single HTTP client request
pub struct Request<'a> {
    /// The context in which this request is made
    pub context: &'a Context<'a>,

    /// The full URL of the request, including a port
    pub url: &'a str,

    /// The HTTP method (must be uppercase)
    pub method: &'a str,

    // TODO: allow specifying this in context, too
    /// The extra information about this request
    pub ext: Option<&'a String>,

    /// The content hash, if any
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

        let digest = hmac::sign(&self.context.credentials.key, buffer.as_ref());

        let mut mac = vec![0; self.context.credentials.key.digest_algorithm().output_len];
        mac.clone_from_slice(digest.as_ref());
        return Ok(mac);
    }
}

#[cfg(test)]
mod test {
    use super::Request;
    use time::Timespec;
    use context::{Credentials, Context};
    use ring::{digest, rand};

    fn key() -> Vec<u8> {
        vec![11u8, 19, 228, 209, 79, 189, 200, 59, 166, 47, 86, 254, 235, 184, 120, 197, 75, 152,
             201, 79, 115, 61, 111, 242, 219, 187, 173, 14, 227, 108, 60, 232, 69, 254, 56, 20,
             247, 75, 81, 100, 0, 69, 211, 253, 53, 212, 238, 231, 164, 235, 32, 173, 61, 22, 164,
             178, 247, 4, 74, 154, 165, 197, 224, 52, 192, 222, 77, 3, 171, 135, 120, 66, 108, 231,
             44, 100, 48, 210, 157, 186, 51, 184, 38, 30, 62, 14, 116, 111, 163, 232, 43, 94, 123,
             141, 164, 38, 232, 205, 68, 84, 23, 164, 8, 48, 207, 19, 34, 197, 67, 122, 57, 202,
             229, 204, 90, 23, 236, 190, 232, 244, 41, 32, 26, 46, 116, 165, 35, 46, 80, 103, 64,
             219, 201, 255, 183, 208, 113, 32, 124, 66, 157, 78, 145, 3, 200, 68, 147, 237, 229,
             133, 9, 226, 21, 129, 199, 109, 150, 148, 199, 163, 174, 204, 48, 171, 67, 118, 246,
             248, 80, 174, 38, 106, 239, 166, 11, 222, 27, 46, 77, 200, 65, 163, 8, 137, 166, 88,
             82, 113, 83, 63, 47, 236, 111, 223, 221, 64, 83, 13, 107, 230, 155, 122, 74, 194, 238,
             183, 16, 239, 65, 27, 238, 8, 138, 194, 32, 203, 53, 220, 231, 239, 142, 203, 175,
             110, 163, 186, 191, 195, 88, 170, 154, 116, 229, 241, 142, 18, 37, 245, 59, 127, 177,
             49, 62, 112, 144, 30, 195, 133, 44, 14, 72, 203, 88, 176, 32, 234]
    }

    #[test]
    fn test_make_mac() {
        let key = key();
        let rng = rand::SystemRandom::new();
        let credentials = Credentials::new("req-id", key, &digest::SHA256);
        let context = Context {
            credentials: &credentials,
            rng: &rng,
            app: None,
            dlg: None,
        };
        let req = Request {
            context: &context,
            url: "http://mysite.com:443/v1/api",
            method: "POST",
            ext: None,
            hash: None,
        };

        let mac = req.make_mac(Timespec::new(1000, 100), &"nonny".to_string()).unwrap();
        println!("got {:?}", mac);
        assert!(mac ==
                vec![94, 15, 95, 75, 58, 185, 155, 131, 227, 159, 182, 224, 111, 67, 61, 202, 5,
                     157, 233, 8, 119, 31, 12, 146, 47, 27, 198, 212, 161, 129, 26, 235]);
    }

    #[test]
    fn test_make_mac_hash() {
        let key = key();
        let rng = rand::SystemRandom::new();
        let credentials = Credentials::new("req-id", key, &digest::SHA256);
        let context = Context {
            credentials: &credentials,
            rng: &rng,
            app: None,
            dlg: None,
        };
        let hash = vec![1, 2, 3, 4, 5];
        let req = Request {
            context: &context,
            url: "http://mysite.com:443/v1/api",
            method: "POST",
            ext: None,
            hash: Some(&hash),
        };

        let mac = req.make_mac(Timespec::new(1000, 100), &"nonny".to_string()).unwrap();
        println!("got {:?}", mac);
        assert!(mac ==
                vec![40, 220, 14, 41, 185, 159, 49, 206, 232, 20, 255, 128, 175, 136, 8, 18, 31,
                     177, 143, 71, 198, 23, 42, 101, 26, 22, 204, 56, 104, 247, 83, 162]);
    }

    #[test]
    fn test_make_mac_ext() {
        let key = key();
        let rng = rand::SystemRandom::new();
        let credentials = Credentials::new("req-id", key, &digest::SHA256);
        let context = Context {
            credentials: &credentials,
            rng: &rng,
            app: None,
            dlg: None,
        };
        let ext = "ext-data".to_string();
        let req = Request {
            context: &context,
            url: "http://mysite.com:443/v1/api",
            method: "POST",
            ext: Some(&ext),
            hash: None,
        };

        let mac = req.make_mac(Timespec::new(1000, 100), &"nonny".to_string()).unwrap();
        println!("got {:?}", mac);
        assert!(mac ==
                vec![113, 179, 152, 228, 54, 3, 112, 184, 172, 159, 167, 73, 49, 197, 91, 147,
                     130, 245, 200, 27, 155, 21, 52, 0, 90, 248, 145, 38, 166, 86, 160, 208]);

    }
}
