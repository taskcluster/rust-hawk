use rustc_serialize::base64;
use rustc_serialize::base64::{FromBase64, ToBase64};
use std::fmt;
use std::str::FromStr;
use super::request::Request;
use time;
use ring::rand;

// TODO: use string errors
#[derive(Debug)]
pub enum Error {
    UnsupportedScheme,
    SchemeParseError,
    MissingAttributes,
    UnknownAttribute,
    InvalidTimestamp,
    Base64DecodeError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

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
    /// Create a new Header for the given request, automatically calculating
    /// the MAC and adding fields from the Context.
    pub fn for_request(request: &Request) -> Result<Header, String> {
        let id = request.context.credentials.id.clone();
        let ts = time::now_utc().to_timespec();
        let nonce = try!(random_string(request.context.rng, 10));

        let mac = try!(request.make_mac(ts, &nonce));

        let ext = match request.ext {
            Some(ext) => Some(ext.clone()),
            None => None,
        };

        let hash = match request.hash {
            Some(hash) => Some(hash.clone()),
            None => None,
        };

        let app = match request.context.app {
            Some(app) => Some(app.clone()),
            None => None,
        };

        let dlg = match request.context.dlg {
            Some(dlg) => Some(dlg.clone()),
            None => None,
        };

        return Ok(Header::new_extended(id, ts, nonce, mac, ext, hash, app, dlg));
    }

    /// Check a header component for validity.
    fn check_component<S>(value: S) -> String
        where S: Into<String>
    {
        // TODO: only do this in debug builds?
        let value = value.into();
        if value.contains("\"") {
            panic!("Hawk header components cannot contain `\"`");
        }
        value
    }

    /// Create a new Header with the basic fields.  This is a low-level function.
    ///
    /// None of the header components can contain the character `\"`.  This function will panic
    /// if any such characters appear.
    pub fn new<S>(id: S, ts: time::Timespec, nonce: S, mac: Vec<u8>) -> Header
        where S: Into<String>
    {
        Header::new_extended(id, ts, nonce, mac, None, None, None, None)
    }

    /// Create a new Header with the full set of Hawk fields.  This is a low-level funtion.
    ///
    /// None of the header components can contain the character `\"`.  This function will panic
    /// if any such characters appear.
    pub fn new_extended<S>(id: S,
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

    // TODO: not public
    /// Return a string containing the contents of the Authorization header.
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
    type Err = Error;
    fn from_str(s: &str) -> Result<Header, Error> {
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
                        return Err(Error::SchemeParseError);
                    }
                    p = (&p[v + 1..]).trim_left();
                    if !p.starts_with("\"") {
                        return Err(Error::SchemeParseError);
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
                                        Err(_) => return Err(Error::InvalidTimestamp),
                                    };
                                }
                                "mac" => {
                                    match val.from_base64() {
                                        Ok(v) => mac = Some(v),
                                        Err(_) => return Err(Error::Base64DecodeError),
                                    }
                                }
                                "nonce" => nonce = Some(val),
                                "ext" => ext = Some(val),
                                "hash" => {
                                    match val.from_base64() {
                                        Ok(v) => hash = Some(v),
                                        Err(_) => return Err(Error::Base64DecodeError),
                                    }
                                }
                                "app" => app = Some(val),
                                "dlg" => dlg = Some(val),
                                _ => return Err(Error::UnknownAttribute),
                            };
                            // Break if we are at end of string, otherwise skip separator
                            if p.len() < v + 1 {
                                break;
                            }
                            p = &p[v + 1..].trim_left();
                        }
                        None => return Err(Error::SchemeParseError),
                    }
                }
                None => return Err(Error::SchemeParseError),
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
            _ => Err(Error::MissingAttributes),
        };
    }
}

/// Create a random string with `bytes` bytes of entropy.  The string
/// is base64-encoded. so it will be longer than bytes characters.
fn random_string(rng: &rand::SecureRandom, bytes: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; bytes];
    if let Err(_) = rng.fill(&mut bytes) {
        return Err("Cannot create random string".to_string());
    }
    Ok(bytes.to_base64(base64::Config {
        char_set: base64::CharacterSet::Standard,
        newline: base64::Newline::LF,
        pad: true,
        line_length: None,
    }))
}

#[cfg(test)]
mod test {
    use super::Header;
    use std::str::FromStr;
    use time::Timespec;

    #[test]
    #[should_panic]
    fn illegal_id() {
        Header::new("abc\"def", Timespec::new(1234, 0), "nonce", vec![]);
    }

    #[test]
    #[should_panic]
    fn illegal_nonce() {
        Header::new("abcdef", Timespec::new(1234, 0), "non\"ce", vec![]);
    }

    #[test]
    #[should_panic]
    fn illegal_ext() {
        Header::new_extended("abcdef",
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
        Header::new_extended("abcdef",
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
        Header::new_extended("abcdef",
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
                                 63, 38, 83]);
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted ==
                "id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", \
                 mac=\"CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=\"")
    }

    #[test]
    fn to_str_maximal() {
        let s = Header::new_extended("dh37fgj492je",
                                     Timespec::new(1353832234, 0),
                                     "j4h3g2",
                                     vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94, 43, 118,
                                          176, 65, 69, 86, 4, 156, 184, 85, 107, 249, 242, 172,
                                          200, 66, 209, 57, 63, 38, 83],
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
        let s = Header::new_extended("dh37fgj492je",
                                     Timespec::new(1353832234, 0),
                                     "j4h3g2",
                                     vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94, 43, 118,
                                          176, 65, 69, 86, 4, 156, 184, 85, 107, 249, 242, 172,
                                          200, 66, 209, 57, 63, 38, 83],
                                     Some("my-ext-value"),
                                     Some(vec![1, 2, 3, 4]),
                                     Some("my-app"),
                                     Some("my-dlg"));
        let formatted = format!("{}", s);
        println!("got: {}", s);
        let s2 = Header::from_str(&formatted).unwrap();
        assert!(s2 == s);
    }
}
