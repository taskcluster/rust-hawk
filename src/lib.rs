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
  SchemeParseError
}

#[derive(Clone, PartialEq, Debug)]
pub struct Scheme {
  pub id: String,
  pub ts: Timespec,
  pub nonce: String,
  pub mac: Vec<u8>,
  pub ext: Option<String>,
  pub hash: Option<Vec<u8>>,
  pub app: Option<String>,
  pub dlg: Option<String>
}

impl hyper::header::Scheme for Scheme {
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

/*
  Hawk id="test-client", // string
       ts="1430002620", // date
       nonce="DG2EzX", // string
       mac="CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=", // bytes
       ext="some-app-data", (optional) // string
       hash="", (optional) // bytes
       app="", (optional) // string
       dlg="" (optional)  // string
*/

impl FromStr for Scheme {
  type Err = Error;
  fn from_str(s: &str) -> Result<Scheme, Error> {
    println!("Scheme  : {}", s[..4].eq_ignore_ascii_case("hawk"));
    println!("AUTH: {}", &s[4..]);


    let id: Option<&str>;
    let ts: Option<Timespec>;
    let nonce: Option<&str>;
    let mac: Option<Vec<u8>>;



/*    if (s == "my-string") {
      Ok(Scheme {
          username: "test",
          password: "test2"
      })
*/
      Err(Error::SchemeParseError)
  }
}

#[test]
fn scheme_from_string() {
  let s = Scheme::from_str(
    "Hawk \
      id=\"dh37fgj492je\", \
      ts=\"1353832234\", \
      nonce=\"j4h3g2\", \
      ext=\"some-app-ext-data\", \
      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\""
  );
  assert!(s.is_ok(), "Parse failed!");
}


#[test]
fn scheme_from_string_again() {
  let s = Scheme::from_str(
    "Hawk \
      id=\"dh37fgj492je\", \
      ts=\"1353832234\", \
      nonce=\"j4h3g2\", \
      ext=\"some-app-ext-data\", \
      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
      hash=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
      app=\"my-app\", \
      dlg=\"my-authority\""
  );
  assert!(s.is_ok(), "Parse failed!");
}

