use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use time;
use url::Url;
use mac::make_mac;
use header::Header;
use credentials::Credentials;
use rand;
use rand::Rng;

static EMPTY_STRING: &'static str = "";

/// Request represents a single HTTP request.
///
/// The structure is created using the builder idiom.  Most uses of this library will hold
/// several of the fields in this structure fixed.  Cloning the structure with these fields
/// applied is a convenient way to avoid repeating those fields.
///
/// # Examples
///
/// ```
/// use hawk::Request;
/// let baseRequest = Request::new().method("GET").host("mysite.com").port(443);
/// let request1 = baseRequest.clone().method("POST").path("/api/user");
/// let request2 = baseRequest.clone().path("/api/users");
/// ```
#[derive(Debug, Clone)]
pub struct Request<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    port: u16,
    hash: Option<&'a [u8]>,
    ext: Option<&'a str>,
    app: Option<&'a str>,
    dlg: Option<&'a str>,
}

impl<'a> Request<'a> {
    /// Create a new, empty request. The method, path, host, and port properties must be set before
    /// use.
    pub fn new() -> Self {
        Request {
            method: EMPTY_STRING,
            path: EMPTY_STRING,
            host: EMPTY_STRING,
            port: 0,
            hash: None,
            ext: None,
            app: None,
            dlg: None,
        }
    }

    /// Set the request method. This should be a capitalized string.
    pub fn method(mut self, method: &'a str) -> Self {
        self.method = method;
        self
    }

    /// Set the URL path for the request.
    pub fn path(mut self, path: &'a str) -> Self {
        self.path = path;
        self
    }

    /// Set the URL hostname for the request
    pub fn host(mut self, host: &'a str) -> Self {
        self.host = host;
        self
    }

    /// Set the URL port for the request
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the hostname, port, and path for the request, from a string URL.
    pub fn url(self, url: &'a Url) -> Result<Self, String> {
        let path = url.path();
        let host = try!(url.host_str().ok_or(format!("url {} has no host", url)));
        let port = try!(url.port_or_known_default().ok_or(format!("url {} has no port", url)));
        Ok(self.path(path).host(host).port(port))
    }

    /// Set the content hash for the request
    pub fn hash(mut self, hash: Option<&'a [u8]>) -> Self {
        self.hash = hash;
        self
    }

    /// Set the `ext` Hawk property for the request
    pub fn ext(mut self, ext: Option<&'a str>) -> Self {
        self.ext = ext;
        self
    }

    /// Set the `app` Hawk property for the request
    pub fn app(mut self, app: Option<&'a str>) -> Self {
        self.app = app;
        self
    }

    /// Set the `dlg` Hawk property for the request
    pub fn dlg(mut self, dlg: Option<&'a str>) -> Self {
        self.dlg = dlg;
        self
    }

    /// Create a new Header for this request, inventing a new nonce and setting the
    /// timestamp to the current time.
    pub fn generate_header(&self, credentials: &Credentials) -> Result<Header, String> {
        let nonce = random_string(10);
        self.generate_header_full(credentials, time::now().to_timespec(), nonce)
    }

    /// Similar to `generate_header`, but allowing specification of the timestamp
    /// and nonce.
    pub fn generate_header_full(&self,
                                credentials: &Credentials,
                                ts: time::Timespec,
                                nonce: String)
                                -> Result<Header, String> {
        let hash_vec;
        let hash = match self.hash {
            None => None,
            Some(v) => {
                hash_vec = v.to_vec();
                Some(&hash_vec)
            }
        };
        let mac = try!(make_mac(&credentials.key,
                                ts,
                                &nonce,
                                self.method,
                                self.path,
                                self.host,
                                self.port,
                                hash,
                                self.ext));
        Ok(Header::new(credentials.id.clone(),
                       ts,
                       nonce,
                       mac,
                       match self.ext {
                           None => None,
                           Some(v) => Some(v.to_string()),
                       },
                       match self.hash {
                           None => None,
                           Some(v) => Some(v.to_vec()),
                       },
                       match self.app {
                           None => None,
                           Some(v) => Some(v.to_string()),
                       },
                       match self.dlg {
                           None => None,
                           Some(v) => Some(v.to_string()),
                       }))
    }
}

/// Create a random string with `bytes` bytes of entropy.  The string
/// is base64-encoded. so it will be longer than bytes characters.
fn random_string(bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; bytes];
    rng.fill_bytes(&mut bytes);
    bytes.to_base64(base64::Config {
        char_set: base64::CharacterSet::Standard,
        newline: base64::Newline::LF,
        pad: true,
        line_length: None,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use time::Timespec;
    use credentials::Credentials;
    use header::Header;
    use url::Url;
    use ring::digest;

    #[test]
    fn test_empty() {
        let req = Request::new();
        assert_eq!(req.method, "");
        assert_eq!(req.path, "");
        assert_eq!(req.host, "");
        assert_eq!(req.port, 0);
        assert_eq!(req.hash, None);
        assert_eq!(req.ext, None);
        assert_eq!(req.app, None);
        assert_eq!(req.dlg, None);
    }

    #[test]
    fn test_builder() {
        let hash = vec![0u8];
        let req = Request::new()
            .method("GET")
            .path("/foo")
            .host("example.com")
            .port(443)
            .hash(Some(&hash[..]))
            .ext(Some("ext"))
            .app(Some("app"))
            .dlg(Some("dlg"));

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/foo");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert_eq!(req.hash, Some(&hash[..]));
        assert_eq!(req.ext, Some("ext"));
        assert_eq!(req.app, Some("app"));
        assert_eq!(req.dlg, Some("dlg"));
    }

    #[test]
    fn test_builder_clone() {
        let req = Request::new()
            .method("GET")
            .path("/foo");
        let req2 = req.clone().path("/bar");

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/foo");
        assert_eq!(req2.method, "GET");
        assert_eq!(req2.path, "/bar");
    }

    #[test]
    fn test_url_builder() {
        let url = Url::parse("https://example.com/foo").unwrap();
        let req = Request::new()
            .url(&url)
            .unwrap();

        assert_eq!(req.path, "/foo");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443); // default for https
    }

    #[test]
    fn test_generate_header_full() {
        let req = Request::new()
            .method("GET")
            .path("/foo")
            .host("example.com")
            .port(443);
        let credentials = Credentials::new("me", vec![99u8; 32], &digest::SHA256);
        let header =
            req.generate_header_full(&credentials, Timespec::new(1000, 100), "nonny".to_string())
                .unwrap();
        assert_eq!(header,
                   Header {
                       id: "me".to_string(),
                       ts: Timespec::new(1000, 100),
                       nonce: "nonny".to_string(),
                       mac: vec![122, 47, 2, 53, 195, 247, 185, 107, 133, 250, 61, 134, 200, 35,
                                 118, 94, 48, 175, 237, 108, 60, 71, 4, 2, 244, 66, 41, 172, 91,
                                 7, 233, 140],
                       ext: None,
                       hash: None,
                       app: None,
                       dlg: None,
                   });
    }

    #[test]
    fn test_generate_header_full_with_optional_fields() {
        let hash = vec![0u8];
        let req = Request::new()
            .method("GET")
            .path("/foo")
            .host("example.com")
            .port(443)
            .hash(Some(&hash[..]))
            .ext(Some("ext"))
            .app(Some("app"))
            .dlg(Some("dlg"));
        let credentials = Credentials::new("me", vec![99u8; 32], &digest::SHA256);
        let header =
            req.generate_header_full(&credentials, Timespec::new(1000, 100), "nonny".to_string())
                .unwrap();
        assert_eq!(header,
                   Header {
                       id: "me".to_string(),
                       ts: Timespec::new(1000, 100),
                       nonce: "nonny".to_string(),
                       mac: vec![72, 123, 243, 214, 145, 81, 129, 54, 183, 90, 22, 136, 192, 146,
                                 208, 53, 216, 138, 145, 94, 175, 204, 217, 8, 77, 16, 202, 50,
                                 10, 144, 133, 162],
                       ext: Some("ext".to_string()),
                       hash: Some(hash.clone()),
                       app: Some("app".to_string()),
                       dlg: Some("dlg".to_string()),
                   });
    }
}
