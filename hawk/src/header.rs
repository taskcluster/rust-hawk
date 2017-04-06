use rustc_serialize::base64;
use rustc_serialize::base64::{FromBase64, ToBase64};
use std::fmt;
use std::str::FromStr;
use ring::constant_time;
use mac::make_mac;
use credentials::Key;
use time;

/// Representation of a Hawk `Authorization` header value.
///
/// Note that this does not include the "`Hawk "` prefix.
#[derive(Clone, PartialEq, Debug)]
pub struct Header {
    pub id: String,
    pub ts: time::Timespec,
    pub nonce: String,
    pub mac: Vec<u8>,
    pub ext: Option<String>,
    pub hash: Option<Vec<u8>>,
    pub app: Option<String>,
    pub dlg: Option<String>,
}

impl Header {
    /// Create a new Header with the full set of Hawk fields.  This is a low-level funtion.
    ///
    /// None of the header components can contain the character `\"`.  This function will panic
    /// if any such characters appear.
    pub fn new<S>(id: S,
                  ts: time::Timespec,
                  nonce: S,
                  mac: Vec<u8>,
                  ext: Option<S>,
                  hash: Option<Vec<u8>>,
                  app: Option<S>,
                  dlg: Option<S>)
                  -> Header
        where S: Into<String>
    {
        Header {
            id: Header::check_component(id),
            ts: ts,
            nonce: Header::check_component(nonce),
            mac: mac,
            ext: match ext {
                Some(ext) => Some(Header::check_component(ext)),
                None => None,
            },
            hash: hash,
            app: match app {
                Some(app) => Some(Header::check_component(app)),
                None => None,
            },
            dlg: match dlg {
                Some(dlg) => Some(Header::check_component(dlg)),
                None => None,
            },
        }
    }

    /// Validate that the header's MAC field matches that calculated using the other header fields
    /// and the given request information.
    ///
    /// It is up to the caller to examine the header's `id` field and supply the corresponding key.
    ///
    /// Note that this is not a complete validation of a request!  It is still up to the caller to
    /// validate the accuracy of the header information.  Notably:
    ///
    ///  * `ts` is within a reasonable skew (the JS implementation suggests +/- one minute)
    ///  * `nonce` has not been used before (optional)
    ///  * `hash` is the correct hash for the content
    pub fn validate_mac(&self, key: &Key, method: &str, host: &str, port: u16, path: &str) -> bool {
        match make_mac(key,
                       self.ts,
                       &self.nonce,
                       method,
                       host,
                       port,
                       path,
                       match self.hash {
                           None => None,
                           Some(ref v) => Some(v),
                       },
                       match self.ext {
                           None => None,
                           Some(ref s) => Some(s),
                       }) {
            Ok(calculated_mac) => {
                match constant_time::verify_slices_are_equal(&calculated_mac[..], &self.mac[..]) {
                    Ok(_) => true,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }

    }

    /// Check a header component for validity.
    fn check_component<S>(value: S) -> String
        where S: Into<String>
    {
        let value = value.into();
        if value.contains("\"") {
            panic!("Hawk header components cannot contain `\"`");
        }
        value
    }

    /// Format the header for transmission in an Authorization header, omitting the `"Hawk "`
    /// prefix.
    pub fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base64_config = base64::Config {
            char_set: base64::CharacterSet::Standard,
            newline: base64::Newline::LF,
            pad: true,
            line_length: None,
        };
        try!(write!(f,
                    "id=\"{}\", ts=\"{}\", nonce=\"{}\", mac=\"{}\"",
                    self.id,
                    self.ts.sec,
                    self.nonce,
                    self.mac.to_base64(base64_config),
                    ));
        if let Some(ref ext) = self.ext {
            try!(write!(f, ", ext=\"{}\"", ext));
        }
        if let Some(ref hash) = self.hash {
            try!(write!(f, ", hash=\"{}\"", hash.to_base64(base64_config)));
        }
        if let Some(ref app) = self.app {
            try!(write!(f, ", app=\"{}\"", app));
        }
        if let Some(ref dlg) = self.dlg {
            try!(write!(f, ", dlg=\"{}\"", dlg));
        }
        Ok(())
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_header(f)
    }
}

impl FromStr for Header {
    type Err = String;
    fn from_str(s: &str) -> Result<Header, String> {
        let mut p = &s[..];

        // Required attributes
        let mut id: Option<&str> = None;
        let mut ts: Option<time::Timespec> = None;
        let mut nonce: Option<&str> = None;
        let mut mac: Option<Vec<u8>> = None;
        // Optional attributes
        let mut hash: Option<Vec<u8>> = None;
        let mut ext: Option<&str> = None;
        let mut app: Option<&str> = None;
        let mut dlg: Option<&str> = None;

        while p.len() > 0 {
            // Skip whitespace and commas used as separators
            p = p.trim_left_matches(|c| {
                return c == ',' || char::is_whitespace(c);
            });
            // Find first '=' which delimits attribute name from value
            match p.find("=") {
                Some(v) => {
                    let attr = &p[..v].trim();
                    if p.len() < v + 1 {
                        return Err("SchemeParseError".to_string());
                    }
                    p = (&p[v + 1..]).trim_left();
                    if !p.starts_with("\"") {
                        return Err("SchemeParseError".to_string());
                    }
                    p = &p[1..];
                    // We have poor RFC 7235 compliance here as we ought to support backslash
                    // escaped characters, but hawk doesn't allow this we won't either.  All
                    // strings must be surrounded by ".." and contain no such characters.
                    let end = p.find("\"");
                    match end {
                        Some(v) => {
                            let val = &p[..v];
                            match *attr {
                                "id" => id = Some(val),
                                "ts" => {
                                    match i64::from_str(val) {
                                        Ok(sec) => ts = Some(time::Timespec::new(sec, 0)),
                                        Err(_) => return Err("InvalidTimestamp".to_string()),
                                    };
                                }
                                "mac" => {
                                    match val.from_base64() {
                                        Ok(v) => mac = Some(v),
                                        Err(_) => return Err("Base64DecodeError".to_string()),
                                    }
                                }
                                "nonce" => nonce = Some(val),
                                "ext" => ext = Some(val),
                                "hash" => {
                                    match val.from_base64() {
                                        Ok(v) => hash = Some(v),
                                        Err(_) => return Err("Base64DecodeError".to_string()),
                                    }
                                }
                                "app" => app = Some(val),
                                "dlg" => dlg = Some(val),
                                _ => return Err("UnknownAttribute".to_string()),
                            };
                            // Break if we are at end of string, otherwise skip separator
                            if p.len() < v + 1 {
                                break;
                            }
                            p = &p[v + 1..].trim_left();
                        }
                        None => return Err("SchemeParseError".to_string()),
                    }
                }
                None => return Err("SchemeParseError".to_string()),
            };
        }

        return match (id, ts, nonce, mac) {
            (Some(id), Some(ts), Some(nonce), Some(mac)) => {
                Ok(Header {
                    id: id.to_string(),
                    ts: ts,
                    nonce: nonce.to_string(),
                    mac: mac,
                    ext: match ext {
                        Some(ext) => Some(ext.to_string()),
                        None => None,
                    },
                    hash: hash,
                    app: match app {
                        Some(app) => Some(app.to_string()),
                        None => None,
                    },
                    dlg: match dlg {
                        Some(dlg) => Some(dlg.to_string()),
                        None => None,
                    },
                })
            }
            _ => Err("MissingAttributes".to_string()),
        };
    }
}

#[cfg(test)]
mod test {
    use super::Header;
    use std::str::FromStr;
    use time::Timespec;
    use request::Request;
    use credentials::{Credentials, Key};
    use ring::digest;

    // this is a header from a real request using the JS Hawk library, to https://pulse.taskcluster.net:443/v1/namespaces
    // with credentials "me" / "tok"
    const REAL_HEADER: &'static str = "id=\"me\", ts=\"1491183061\", nonce=\"RVnYzW\", \
                                       mac=\"1kqRT9EoxiZ9AA/ayOCXB+AcjfK/BoJ+n7z0gfvZotQ=\"";

    #[test]
    #[should_panic]
    fn illegal_id() {
        Header::new("ab\"cdef",
                    Timespec::new(1234, 0),
                    "nonce",
                    vec![],
                    Some("ext"),
                    None,
                    None,
                    None);
    }

    #[test]
    #[should_panic]
    fn illegal_nonce() {
        Header::new("abcdef",
                    Timespec::new(1234, 0),
                    "no\"nce",
                    vec![],
                    Some("ext"),
                    None,
                    None,
                    None);
    }

    #[test]
    #[should_panic]
    fn illegal_ext() {
        Header::new("abcdef",
                    Timespec::new(1234, 0),
                    "nonce",
                    vec![],
                    Some("ex\"t"),
                    None,
                    None,
                    None);
    }

    #[test]
    #[should_panic]
    fn illegal_app() {
        Header::new("abcdef",
                    Timespec::new(1234, 0),
                    "nonce",
                    vec![],
                    None,
                    None,
                    Some("a\"pp"),
                    None);
    }

    #[test]
    #[should_panic]
    fn illegal_dlg() {
        Header::new("abcdef",
                    Timespec::new(1234, 0),
                    "nonce",
                    vec![],
                    None,
                    None,
                    None,
                    Some("d\"lg"));
    }

    #[test]
    fn from_str() {
        let s = Header::from_str("id=\"dh37fgj492je\", ts=\"1353832234\", \
                                      nonce=\"j4h3g2\", ext=\"some-app-ext-data\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
                                      hash=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
                                      app=\"my-app\", dlg=\"my-authority\"")
            .unwrap();
        assert!(s.id == "dh37fgj492je");
        assert!(s.ts == Timespec::new(1353832234, 0));
        assert!(s.nonce == "j4h3g2");
        assert!(s.mac ==
                vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150, 194, 55, 135, 206,
                     48, 6, 93, 75, 75, 52, 140, 102, 163, 91, 233, 50, 135, 233, 44, 1]);
        assert!(s.ext.unwrap() == "some-app-ext-data");
        assert!(s.app == Some("my-app".to_string()));
        assert!(s.dlg == Some("my-authority".to_string()));
    }

    #[test]
    fn from_str_minimal() {
        let s = Header::from_str("id=\"xyz\", ts=\"1353832234\", \
                                      nonce=\"abc\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"")
            .unwrap();
        assert!(s.id == "xyz");
        assert!(s.ts == Timespec::new(1353832234, 0));
        assert!(s.nonce == "abc");
        assert!(s.mac ==
                vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150, 194, 55, 135, 206,
                     48, 6, 93, 75, 75, 52, 140, 102, 163, 91, 233, 50, 135, 233, 44, 1]);
        assert!(s.ext == None);
        assert!(s.app == None);
        assert!(s.dlg == None);
    }

    #[test]
    fn from_str_messy() {
        let s = Header::from_str(", id  =  \"dh37fgj492je\", ts=\"1353832234\", \
                                      nonce=\"j4h3g2\"  , , ext=\"some-app-ext-data\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"")
            .unwrap();
        assert!(s.id == "dh37fgj492je");
        assert!(s.ts == Timespec::new(1353832234, 0));
        assert!(s.nonce == "j4h3g2");
        assert!(s.mac ==
                vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150, 194, 55, 135, 206,
                     48, 6, 93, 75, 75, 52, 140, 102, 163, 91, 233, 50, 135, 233, 44, 1]);
        assert!(s.ext.unwrap() == "some-app-ext-data");
        assert!(s.app == None);
        assert!(s.dlg == None);
    }

    #[test]
    fn to_str_minimal() {
        let s = Header::new("dh37fgj492je",
                            Timespec::new(1353832234, 0),
                            "j4h3g2",
                            vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94, 43, 118, 176, 65,
                                 69, 86, 4, 156, 184, 85, 107, 249, 242, 172, 200, 66, 209, 57,
                                 63, 38, 83],
                            None,
                            None,
                            None,
                            None);
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted ==
                "id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", \
                 mac=\"CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=\"")
    }

    #[test]
    fn to_str_maximal() {
        let s = Header::new("dh37fgj492je",
                            Timespec::new(1353832234, 0),
                            "j4h3g2",
                            vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94, 43, 118, 176, 65,
                                 69, 86, 4, 156, 184, 85, 107, 249, 242, 172, 200, 66, 209, 57,
                                 63, 38, 83],
                            Some("my-ext-value"),
                            Some(vec![1, 2, 3, 4]),
                            Some("my-app"),
                            Some("my-dlg"));
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted ==
                "id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", \
                 mac=\"CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=\", ext=\"my-ext-value\", \
                 hash=\"AQIDBA==\", app=\"my-app\", dlg=\"my-dlg\"")
    }

    #[test]
    fn round_trip() {
        let s = Header::new("dh37fgj492je",
                            Timespec::new(1353832234, 0),
                            "j4h3g2",
                            vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94, 43, 118, 176, 65,
                                 69, 86, 4, 156, 184, 85, 107, 249, 242, 172, 200, 66, 209, 57,
                                 63, 38, 83],
                            Some("my-ext-value"),
                            Some(vec![1, 2, 3, 4]),
                            Some("my-app"),
                            Some("my-dlg"));
        let formatted = format!("{}", s);
        println!("got: {}", s);
        let s2 = Header::from_str(&formatted).unwrap();
        assert!(s2 == s);
    }

    #[test]
    fn test_validate_matches_generated() {
        let req = Request::new()
            .method("GET")
            .path("/foo")
            .host("example.com")
            .port(443);
        let credentials = Credentials {
            id: "me".to_string(),
            key: Key::new(vec![99u8; 32], &digest::SHA256),
        };
        let header =
            req.generate_header_full(&credentials, Timespec::new(1000, 100), "nonny".to_string())
                .unwrap();
        assert!(header.validate_mac(&credentials.key, "GET", "example.com", 443, "/foo"));
    }

    #[test]
    fn test_validate_real_request() {
        let header = Header::from_str(REAL_HEADER).unwrap();
        let credentials = Credentials {
            id: "me".to_string(),
            key: Key::new("tok", &digest::SHA256),
        };
        assert!(header.validate_mac(&credentials.key,
                                    "GET",
                                    "pulse.taskcluster.net",
                                    443,
                                    "/v1/namespaces"));
    }

    #[test]
    fn test_validate_real_request_bad_creds() {
        let header = Header::from_str(REAL_HEADER).unwrap();
        let credentials = Credentials {
            id: "me".to_string(),
            key: Key::new("WRONG", &digest::SHA256),
        };
        assert!(!header.validate_mac(&credentials.key,
                                     "GET",
                                     "pulse.taskcluster.net",
                                     443,
                                     "/v1/namespaces"));
    }

    #[test]
    fn test_validate_real_request_bad_req_info() {
        let header = Header::from_str(REAL_HEADER).unwrap();
        let credentials = Credentials {
            id: "me".to_string(),
            key: Key::new("tok", &digest::SHA256),
        };
        assert!(!header.validate_mac(&credentials.key,
                                     "GET",
                                     "pulse.taskcluster.net",
                                     443,
                                     "/v1/WRONGPATH"));
    }
}
