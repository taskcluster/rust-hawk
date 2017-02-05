extern crate hyper;
extern crate rustc_serialize;
extern crate time;

use std::str::FromStr;
use std::fmt;
use rustc_serialize::base64::FromBase64;
use time::Timespec;
use std::ascii::AsciiExt;

#[derive(Debug)]
pub enum Error {
    UnsupportedScheme,
    SchemeParseError,
    MissingAttributes,
    UnknownAttribute,
    InvalidTimestamp,
    Base64DecodeError,
}

#[derive(Clone, PartialEq, Debug)]
pub struct HawkScheme {
    pub id: String,
    pub ts: Timespec,
    pub nonce: String,
    pub mac: Vec<u8>,
    pub ext: Option<String>,
    pub hash: Option<Vec<u8>>,
    pub app: Option<String>,
    pub dlg: Option<String>,
}

impl hyper::header::Scheme for HawkScheme {
    fn scheme() -> Option<&'static str> {
        Some("Hawk")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Hello word")
    }
}

// Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
//
// Hawk id="test-client", ts="1430002620", nonce="DG2EzX", ext="some-app-data", mac="CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=", hash="", app="", dlg=""

// Hawk id="test-client", // string
// ts="1430002620", // date
// nonce="DG2EzX", // string
// mac="CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=", // bytes
// ext="some-app-data", (optional) // string
// hash="", (optional) // bytes
// app="", (optional) // string
// dlg="" (optional)  // string
//

impl FromStr for HawkScheme {
    type Err = Error;
    fn from_str(s: &str) -> Result<HawkScheme, Error> {
        // Check that it starts with "HAWK " (Space not optional)
        if s.len() < 5 || !s[..5].eq_ignore_ascii_case("hawk ") {
            return Err(Error::UnsupportedScheme);
        }

        let mut p = &s[4..];
        println!("");
        println!("AUTH: '{}'", &p);
        println!("Length: {}", p.len());

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
                        return Err(Error::SchemeParseError);
                    }
                    p = (&p[v + 1..]).trim_left();
                    let mut end: Option<usize>;
                    if p.starts_with("\"") {
                        p = &p[1..];
                        // We have poor RFC 7235 compliance here as we ought to
                        // support backslash escaped characters, but hawk doesn't allow this
                        // we won't either.
                        end = p.find("\"");
                    } else {
                        // Parse tokens for better RFC 7235 compliance, not allowed by hawk
                        // and we shall not serialize to this format
                        end = p.find(|c| {
                            return match c {
                                '!' => false,
                                '#' => false,
                                '$' => false,
                                '%' => false,
                                '&' => false,
                                '\'' => false,
                                '*' => false,
                                '+' => false,
                                '-' => false,
                                '.' => false,
                                '^' => false,
                                '_' => false,
                                '`' => false,
                                '|' => false,
                                '~' => false,
                                _ => !char::is_alphanumeric(c) && !char::is_numeric(c),
                            };
                        });
                        end = match end {
                            Some(v) => Some(v),
                            None => Some(p.len()),
                        };
                    }
                    match end {
                        Some(v) => {
                            let val = &p[..v];
                            match *attr {
                                "id" => id = Some(val),
                                "ts" => {
                                    match i64::from_str(val) {
                                        Ok(sec) => ts = Some(Timespec::new(sec, 0)),
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
                Ok(HawkScheme {
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

#[test]
fn scheme_from_string() {
    let s = HawkScheme::from_str("Hawk , id  =  \"dh37fgj492je\", ts=\"1353832234\", \
                                  nonce=\"j4h3g2\"  , , ext=\"some-app-ext-data\", \
                                  mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"");
    assert!(s.is_ok(), "Parse failed!");
}

// #[test]
// fn scheme_from_string_again() {
// let s = HawkScheme::from_str(
// "Hawk \
// id=\"dh37fgj492je\", \
// ts=\"1353832234\", \
// nonce=\"j4h3g2\", \
// ext=\"some-app-ext-data\", \
// mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
// hash=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
// app=\"my-app\", \
// dlg=\"my-authority\""
// );
// assert!(s.is_ok(), "Parse failed!");
// }
//
//
