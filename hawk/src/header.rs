use rustc_serialize::base64;
use rustc_serialize::base64::{FromBase64, ToBase64};
use std::fmt;
use std::str::FromStr;
use mac::Mac;
use error::HawkError;
use time::Timespec;

/// Representation of a Hawk `Authorization` header value (the part following "Hawk ").
///
/// Headers can be derived froms trings using the `FromStr` trait, and formatted into a
/// string using the `fmt_header` method.
///
/// All fields are optional, although for specific purposes some fields must be present.
#[derive(Clone, PartialEq, Debug)]
pub struct Header {
    pub id: Option<String>,
    pub ts: Option<Timespec>,
    pub nonce: Option<String>,
    pub mac: Option<Mac>,
    pub ext: Option<String>,
    pub hash: Option<Vec<u8>>,
    pub app: Option<String>,
    pub dlg: Option<String>,
}

impl Header {
    /// Create a new Header with the full set of Hawk fields.  This is a low-level funtion.
    ///
    /// None of the string-formatted header components can contain the character `\"`.
    pub fn new<S>(id: Option<S>,
                  ts: Option<Timespec>,
                  nonce: Option<S>,
                  mac: Option<Mac>,
                  ext: Option<S>,
                  hash: Option<Vec<u8>>,
                  app: Option<S>,
                  dlg: Option<S>)
                  -> Result<Header, HawkError>
        where S: Into<String>
    {
        Ok(Header {
            id: Header::check_component(id)?,
            ts: ts,
            nonce: Header::check_component(nonce)?,
            mac: mac,
            ext: Header::check_component(ext)?,
            hash: hash,
            app: Header::check_component(app)?,
            dlg: Header::check_component(dlg)?,
        })
    }

    /// Check a header component for validity.
    fn check_component<S>(value: Option<S>) -> Result<Option<String>, HawkError>
        where S: Into<String>
    {
        if let Some(value) = value {
            let value = value.into();
            if value.contains("\"") {
                return Err(HawkError::InvalidHeaderValue);
            }
            Ok(Some(value))
        } else {
            Ok(None)
        }
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
        let mut sep = "";
        if let Some(ref id) = self.id {
            write!(f, "{}id=\"{}\"", sep, id)?;
            sep = ", ";
        }
        if let Some(ref ts) = self.ts {
            write!(f, "{}ts=\"{}\"", sep, ts.sec)?;
            sep = ", ";
        }
        if let Some(ref nonce) = self.nonce {
            write!(f, "{}nonce=\"{}\"", sep, nonce)?;
            sep = ", ";
        }
        if let Some(ref mac) = self.mac {
            write!(f, "{}mac=\"{}\"", sep, mac.to_base64(base64_config))?;
            sep = ", ";
        }
        if let Some(ref ext) = self.ext {
            write!(f, "{}ext=\"{}\"", sep, ext)?;
            sep = ", ";
        }
        if let Some(ref hash) = self.hash {
            write!(f, "{}hash=\"{}\"", sep, hash.to_base64(base64_config))?;
            sep = ", ";
        }
        if let Some(ref app) = self.app {
            write!(f, "{}app=\"{}\"", sep, app)?;
            sep = ", ";
        }
        if let Some(ref dlg) = self.dlg {
            write!(f, "{}dlg=\"{}\"", sep, dlg)?;
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
    type Err = HawkError;
    fn from_str(s: &str) -> Result<Header, HawkError> {
        let mut p = &s[..];

        // Required attributes
        let mut id: Option<&str> = None;
        let mut ts: Option<Timespec> = None;
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
                        return Err(HawkError::HeaderParseError);
                    }
                    p = (&p[v + 1..]).trim_left();
                    if !p.starts_with("\"") {
                        return Err(HawkError::HeaderParseError);
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
                                        Ok(sec) => ts = Some(Timespec::new(sec, 0)),
                                        Err(_) => return Err(HawkError::InvalidTimestamp),
                                    };
                                }
                                "mac" => {
                                    match val.from_base64() {
                                        Ok(v) => mac = Some(v),
                                        Err(_) => return Err(HawkError::Base64DecodeError),
                                    }
                                }
                                "nonce" => nonce = Some(val),
                                "ext" => ext = Some(val),
                                "hash" => {
                                    match val.from_base64() {
                                        Ok(v) => hash = Some(v),
                                        Err(_) => return Err(HawkError::Base64DecodeError),
                                    }
                                }
                                "app" => app = Some(val),
                                "dlg" => dlg = Some(val),
                                _ => return Err(HawkError::UnknownAttribute),
                            };
                            // Break if we are at end of string, otherwise skip separator
                            if p.len() < v + 1 {
                                break;
                            }
                            p = &p[v + 1..].trim_left();
                        }
                        None => return Err(HawkError::HeaderParseError),
                    }
                }
                None => return Err(HawkError::HeaderParseError),
            };
        }

        Ok(Header {
            id: match id {
                Some(id) => Some(id.to_string()),
                None => None,
            },
            ts: ts,
            nonce: match nonce {
                Some(nonce) => Some(nonce.to_string()),
                None => None,
            },
            mac: match mac {
                Some(mac) => Some(Mac::from(mac)),
                None => None,
            },
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
}

#[cfg(test)]
mod test {
    use super::Header;
    use time::Timespec;
    use std::str::FromStr;
    use mac::Mac;

    #[test]
    fn illegal_id() {
        assert!(Header::new(Some("ab\"cdef"),
                            Some(Timespec::new(1234, 0)),
                            Some("nonce"),
                            Some(Mac::from(vec![])),
                            Some("ext"),
                            None,
                            None,
                            None)
            .is_err());
    }

    #[test]
    fn illegal_nonce() {
        assert!(Header::new(Some("abcdef"),
                            Some(Timespec::new(1234, 0)),
                            Some("no\"nce"),
                            Some(Mac::from(vec![])),
                            Some("ext"),
                            None,
                            None,
                            None)
            .is_err());
    }

    #[test]
    fn illegal_ext() {
        assert!(Header::new(Some("abcdef"),
                            Some(Timespec::new(1234, 0)),
                            Some("nonce"),
                            Some(Mac::from(vec![])),
                            Some("ex\"t"),
                            None,
                            None,
                            None)
            .is_err());
    }

    #[test]
    fn illegal_app() {
        assert!(Header::new(Some("abcdef"),
                            Some(Timespec::new(1234, 0)),
                            Some("nonce"),
                            Some(Mac::from(vec![])),
                            None,
                            None,
                            Some("a\"pp"),
                            None)
            .is_err());
    }

    #[test]
    fn illegal_dlg() {
        assert!(Header::new(Some("abcdef"),
                            Some(Timespec::new(1234, 0)),
                            Some("nonce"),
                            Some(Mac::from(vec![])),
                            None,
                            None,
                            None,
                            Some("d\"lg"))
            .is_err());
    }

    #[test]
    fn from_str() {
        let s = Header::from_str("id=\"dh37fgj492je\", ts=\"1353832234\", \
                                      nonce=\"j4h3g2\", ext=\"some-app-ext-data\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
                                      hash=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
                                      app=\"my-app\", dlg=\"my-authority\"")
            .unwrap();
        assert!(s.id == Some("dh37fgj492je".to_string()));
        assert!(s.ts == Some(Timespec::new(1353832234, 0)));
        assert!(s.nonce == Some("j4h3g2".to_string()));
        assert!(s.mac ==
                Some(Mac::from(vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150,
                                    194, 55, 135, 206, 48, 6, 93, 75, 75, 52, 140, 102, 163,
                                    91, 233, 50, 135, 233, 44, 1])));
        assert!(s.ext == Some("some-app-ext-data".to_string()));
        assert!(s.app == Some("my-app".to_string()));
        assert!(s.dlg == Some("my-authority".to_string()));
    }

    #[test]
    fn from_str_no_field() {
        let s = Header::from_str("").unwrap();
        assert!(s.id == None);
        assert!(s.ts == None);
        assert!(s.nonce == None);
        assert!(s.mac == None);
        assert!(s.ext == None);
        assert!(s.app == None);
        assert!(s.dlg == None);
    }

    #[test]
    fn from_str_few_field() {
        let s = Header::from_str("id=\"xyz\", ts=\"1353832234\", \
                                      nonce=\"abc\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"")
            .unwrap();
        assert!(s.id == Some("xyz".to_string()));
        assert!(s.ts == Some(Timespec::new(1353832234, 0)));
        assert!(s.nonce == Some("abc".to_string()));
        assert!(s.mac ==
                Some(Mac::from(vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150,
                                    194, 55, 135, 206, 48, 6, 93, 75, 75, 52, 140, 102, 163,
                                    91, 233, 50, 135, 233, 44, 1])));
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
        assert!(s.id == Some("dh37fgj492je".to_string()));
        assert!(s.ts == Some(Timespec::new(1353832234, 0)));
        assert!(s.nonce == Some("j4h3g2".to_string()));
        assert!(s.mac ==
                Some(Mac::from(vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150,
                                    194, 55, 135, 206, 48, 6, 93, 75, 75, 52, 140, 102, 163,
                                    91, 233, 50, 135, 233, 44, 1])));
        assert!(s.ext == Some("some-app-ext-data".to_string()));
        assert!(s.app == None);
        assert!(s.dlg == None);
    }

    #[test]
    fn to_str_no_fields() {
        // must supply a type for S, since it is otherwise unused
        let s = Header::new::<String>(None, None, None, None, None, None, None, None).unwrap();
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted == "")
    }

    #[test]
    fn to_str_few_fields() {
        let s = Header::new(Some("dh37fgj492je"),
                            Some(Timespec::new(1353832234, 0)),
                            Some("j4h3g2"),
                            Some(Mac::from(vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94,
                                                43, 118, 176, 65, 69, 86, 4, 156, 184, 85, 107,
                                                249, 242, 172, 200, 66, 209, 57, 63, 38, 83])),
                            None,
                            None,
                            None,
                            None)
            .unwrap();
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted ==
                "id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", \
                 mac=\"CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=\"")
    }

    #[test]
    fn to_str_maximal() {
        let s = Header::new(Some("dh37fgj492je"),
                            Some(Timespec::new(1353832234, 0)),
                            Some("j4h3g2"),
                            Some(Mac::from(vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94,
                                                43, 118, 176, 65, 69, 86, 4, 156, 184, 85, 107,
                                                249, 242, 172, 200, 66, 209, 57, 63, 38, 83])),
                            Some("my-ext-value"),
                            Some(vec![1, 2, 3, 4]),
                            Some("my-app"),
                            Some("my-dlg"))
            .unwrap();
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted ==
                "id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", \
                 mac=\"CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=\", ext=\"my-ext-value\", \
                 hash=\"AQIDBA==\", app=\"my-app\", dlg=\"my-dlg\"")
    }

    #[test]
    fn round_trip() {
        let s = Header::new(Some("dh37fgj492je"),
                            Some(Timespec::new(1353832234, 0)),
                            Some("j4h3g2"),
                            Some(Mac::from(vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94,
                                                43, 118, 176, 65, 69, 86, 4, 156, 184, 85, 107,
                                                249, 242, 172, 200, 66, 209, 57, 63, 38, 83])),
                            Some("my-ext-value"),
                            Some(vec![1, 2, 3, 4]),
                            Some("my-app"),
                            Some("my-dlg"))
            .unwrap();
        let formatted = format!("{}", s);
        println!("got: {}", s);
        let s2 = Header::from_str(&formatted).unwrap();
        assert!(s2 == s);
    }
}
