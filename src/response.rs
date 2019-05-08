use crate::credentials::Key;
use crate::error::*;
use crate::header::Header;
use crate::mac::{Mac, MacType};
use crate::RequestState;

/// A Response represents a response from an HTTP server.
///
/// The structure is created from a request and then used to either create (server) or validate
/// (client) a `Server-Authentication` header.
///
/// Like `Request`, Responses are built with `ResponseBuilders`.
///
/// # Examples
///
/// See the documentation in the crate root for examples.
#[derive(Debug, Clone)]
pub struct Response<'a> {
    method: &'a str,
    host: &'a str,
    port: u16,
    path: &'a str,
    reqstate: &'a RequestState,
    hash: Option<Vec<u8>>,
    ext: Option<&'a str>,
}

impl<'a> Response<'a> {
    /// Create a new Header for this response, based on the given request and request header
    pub fn make_header(&self, key: &Key) -> Result<Header> {
        let mac;
        mac = Mac::new(
            MacType::Response,
            key,
            self.reqstate.ts,
            &self.reqstate.nonce,
            self.method,
            self.host,
            self.port,
            self.path,
            match self.hash {
                Some(ref v) => Some(v),
                None => None,
            },
            self.ext,
        )?;

        // Per JS implementation, the Server-Authorization header includes only mac, hash, and ext
        Header::new(
            None,
            None,
            None,
            Some(mac),
            match self.ext {
                None => None,
                Some(v) => Some(v.to_string()),
            },
            match self.hash {
                None => None,
                Some(ref h) => Some(h.clone()),
            },
            None,
            None,
        )
    }

    /// Validate a Server-Authorization header.
    ///
    /// This checks that the MAC matches and, if a hash has been supplied locally,
    /// checks that one was provided from the server and that it, too, matches.
    pub fn validate_header(&self, response_header: &Header, key: &Key) -> bool {
        // extract required fields, returning early if they are not present
        let ts = self.reqstate.ts;
        let nonce = &self.reqstate.nonce;
        let header_mac = match response_header.mac {
            Some(ref mac) => mac,
            None => {
                return false;
            }
        };
        let header_ext = match response_header.ext {
            Some(ref ext) => Some(&ext[..]),
            None => None,
        };
        let header_hash = match response_header.hash {
            Some(ref hash) => Some(&hash[..]),
            None => None,
        };

        // first verify the MAC
        match Mac::new(
            MacType::Response,
            key,
            ts,
            nonce,
            self.method,
            self.host,
            self.port,
            self.path,
            header_hash,
            header_ext,
        ) {
            Ok(calculated_mac) => {
                if &calculated_mac != header_mac {
                    return false;
                }
            }
            Err(_) => {
                return false;
            }
        };

        // ..then the hashes
        if let Some(ref local_hash) = self.hash {
            if let Some(ref server_hash) = response_header.hash {
                if local_hash != server_hash {
                    return false;
                }
            } else {
                return false;
            }
        }

        // NOTE: the timestamp self.reqstate.ts was generated locally, so
        // there is no need to verify it

        true
    }
}

#[derive(Debug, Clone)]
pub struct ResponseBuilder<'a>(Response<'a>);

impl<'a> ResponseBuilder<'a> {
    /// Generate a new Response from a request header.
    ///
    /// This is more commonly accessed through `Request::make_response`.
    pub fn from_request_state(
        reqstate: &'a RequestState,
        method: &'a str,
        host: &'a str,
        port: u16,
        path: &'a str,
    ) -> Self {
        ResponseBuilder(Response {
            method,
            host,
            port,
            path,
            reqstate,
            hash: None,
            ext: None,
        })
    }

    /// Set the content hash for the response.
    ///
    /// This should always be calculated from the response payload, not copied from a header.
    pub fn hash<H: Into<Option<Vec<u8>>>>(mut self, hash: H) -> Self {
        self.0.hash = hash.into();
        self
    }

    /// Set the `ext` Hawk property for the response.
    ///
    /// This need only be set on the server; it is ignored in validating responses on the client.
    pub fn ext<S: Into<Option<&'a str>>>(mut self, ext: S) -> Self {
        self.0.ext = ext.into();
        self
    }

    /// Get the response from this builder
    pub fn response(self) -> Response<'a> {
        self.0
    }
}

#[cfg(all(test, any(feature = "use_ring", feature = "use_openssl")))]
mod test {
    use super::ResponseBuilder;
    use crate::credentials::Key;
    use crate::header::Header;
    use crate::mac::Mac;
    use crate::RequestState;
    use std::time::{Duration, UNIX_EPOCH};

    fn make_reqstate() -> RequestState {
        RequestState {
            ts: UNIX_EPOCH + Duration::new(1353832234, 0),
            nonce: "j4h3g2".to_string(),
        }
    }

    #[test]
    fn test_validation_no_hash() {
        let reqstate = make_reqstate();
        let resp =
            ResponseBuilder::from_request_state(&reqstate, "POST", "localhost", 9988, "/a/b")
                .response();
        let mac: Mac = Mac::from(vec![
            48, 133, 228, 163, 224, 197, 222, 77, 117, 81, 143, 73, 71, 120, 68, 238, 228, 40, 55,
            64, 190, 73, 102, 123, 79, 185, 199, 26, 62, 1, 137, 170,
        ]);
        let server_header = Header::new(
            None,
            None,
            None,
            Some(mac),
            Some("server-ext"),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(resp.validate_header(&server_header, &Key::new("tok", crate::SHA256).unwrap()));
    }

    #[test]
    fn test_validation_hash_in_header() {
        // When a hash is provided in the response header, but no hash is added to the Response,
        // it is ignored (so validation succeeds)
        let reqstate = make_reqstate();
        let resp =
            ResponseBuilder::from_request_state(&reqstate, "POST", "localhost", 9988, "/a/b")
                .response();
        let mac: Mac = Mac::from(vec![
            33, 147, 159, 211, 184, 194, 189, 74, 53, 229, 241, 161, 215, 145, 22, 34, 206, 207,
            242, 100, 33, 193, 36, 96, 149, 133, 180, 4, 132, 87, 207, 238,
        ]);
        let server_header = Header::new(
            None,
            None,
            None,
            Some(mac),
            Some("server-ext"),
            Some(vec![1, 2, 3, 4]),
            None,
            None,
        )
        .unwrap();
        assert!(resp.validate_header(&server_header, &Key::new("tok", crate::SHA256).unwrap()));
    }

    #[test]
    fn test_validation_hash_required_but_not_given() {
        // When Response.hash is called, but no hash is in the hader, validation fails.
        let reqstate = make_reqstate();
        let hash = vec![1, 2, 3, 4];
        let resp =
            ResponseBuilder::from_request_state(&reqstate, "POST", "localhost", 9988, "/a/b")
                .hash(hash)
                .response();
        let mac: Mac = Mac::from(vec![
            48, 133, 228, 163, 224, 197, 222, 77, 117, 81, 143, 73, 71, 120, 68, 238, 228, 40, 55,
            64, 190, 73, 102, 123, 79, 185, 199, 26, 62, 1, 137, 170,
        ]);
        let server_header = Header::new(
            None,
            None,
            None,
            Some(mac),
            Some("server-ext"),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!resp.validate_header(&server_header, &Key::new("tok", crate::SHA256).unwrap()));
    }

    #[test]
    fn test_validation_hash_validated() {
        // When a hash is provided in the response header and the Response.hash method is called,
        // the two must match
        let reqstate = make_reqstate();
        let hash = vec![1, 2, 3, 4];
        let resp =
            ResponseBuilder::from_request_state(&reqstate, "POST", "localhost", 9988, "/a/b")
                .hash(hash)
                .response();
        let mac: Mac = Mac::from(vec![
            33, 147, 159, 211, 184, 194, 189, 74, 53, 229, 241, 161, 215, 145, 22, 34, 206, 207,
            242, 100, 33, 193, 36, 96, 149, 133, 180, 4, 132, 87, 207, 238,
        ]);
        let server_header = Header::new(
            None,
            None,
            None,
            Some(mac),
            Some("server-ext"),
            Some(vec![1, 2, 3, 4]),
            None,
            None,
        )
        .unwrap();
        assert!(resp.validate_header(&server_header, &Key::new("tok", crate::SHA256).unwrap()));

        // a different supplied hash won't match..
        let hash = vec![99, 99, 99, 99];
        let resp =
            ResponseBuilder::from_request_state(&reqstate, "POST", "localhost", 9988, "/a/b")
                .hash(hash)
                .response();
        assert!(!resp.validate_header(&server_header, &Key::new("tok", crate::SHA256).unwrap()));
    }
}
