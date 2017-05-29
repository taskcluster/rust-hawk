use mac::Mac;
use header::Header;
use credentials::Key;
use error::HawkError;

/// A Response represents a response from an HTTP server.
///
/// The structure is created from a request and then used to either create (server) or validate
/// (client) a `Server-Authentication` header.
///
/// Like `Request`, this follows the builder pattern, but only for the `hash` and `ext` properties.
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
    req_header: &'a Header,
    hash: Option<&'a [u8]>,
    ext: Option<&'a str>,
}

impl<'a> Response<'a> {
    /// Generate a new Response from a request header.
    ///
    /// This is more commonly accessed through `Request::make_response`.
    pub fn from_request_header(req_header: &'a Header,
                               method: &'a str,
                               host: &'a str,
                               port: u16,
                               path: &'a str)
                               -> Self {
        Response {
            method: method,
            host: host,
            port: port,
            path: path,
            req_header: req_header,
            hash: None,
            ext: None,
        }
    }

    /// Set the content hash for the response.
    ///
    /// This should always be calculated from the response payload, not copied from a header.
    pub fn hash(mut self, hash: &'a [u8]) -> Self {
        // TODO: use into
        self.hash = Some(hash);
        self
    }

    /// Set the `ext` Hawk property for the response.
    ///
    /// This need only be set on the server; it is ignored in validating responses on the client.
    pub fn ext(mut self, ext: &'a str) -> Self {
        // TODO: use into
        self.ext = Some(ext);
        self
    }

    /// Create a new Header for this response, based on the given request and request header
    pub fn make_header(&self, key: &Key) -> Result<Header, HawkError> {
        let mac;
        // TODO: use .ok_or here (but this is hard with `ref nonce`)
        if let Some(ts) = self.req_header.ts {
            if let Some(ref nonce) = self.req_header.nonce {
                mac = Mac::new(true,
                               &key,
                               ts,
                               nonce,
                               self.method,
                               self.host,
                               self.port,
                               self.path,
                               self.hash,
                               self.ext)?;
            } else {
                return Err(HawkError::MissingAttributes);
            }
        } else {
            return Err(HawkError::MissingAttributes);
        }

        // Per JS implementation, the Server-Authorization header includes only mac, hash, and ext
        Ok(Header::new(None,
                       None,
                       None,
                       Some(mac),
                       match self.ext {
                           None => None,
                           Some(v) => Some(v.to_string()),
                       },
                       match self.hash {
                           None => None,
                           Some(v) => Some(v.to_vec()),
                       },
                       None,
                       None))
    }

    /// Validate a Server-Authorization header.
    ///
    /// This checks that the MAC matches and, if a hash has been supplied locally,
    /// checks that one was provided from the server and that it, too, matches.
    pub fn validate_header(&self, response_header: &Header, key: &Key) -> bool {
        // extract required fields, returning early if they are not present
        let ts = match self.req_header.ts {
            Some(ts) => ts,
            None => {
                return false;
            }
        };
        let nonce = match self.req_header.nonce {
            Some(ref nonce) => nonce,
            None => {
                return false;
            }
        };
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
        match Mac::new(true,
                       key,
                       ts,
                       nonce,
                       self.method,
                       self.host,
                       self.port,
                       self.path,
                       header_hash,
                       header_ext) {
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
        if let Some(local_hash) = self.hash {
            if let Some(server_hash) = header_hash {
                if local_hash != server_hash {
                    return false;
                }
            } else {
                return false;
            }
        }

        // NOTE: the timestamp self.req_header.ts was generated locally, so
        // there is no need to verify it

        true
    }
}

#[cfg(test)]
mod test {
    use super::Response;
    use header::Header;
    use credentials::Key;
    use mac::Mac;
    use time::Timespec;
    use ring::digest;

    fn make_req_header() -> Header {
        Header::new(None,
                    Some(Timespec::new(1353832234, 0)),
                    Some("j4h3g2"),
                    None,
                    None,
                    None,
                    None,
                    None)
    }

    #[test]
    fn test_validation_no_hash() {
        let req_header = make_req_header();
        let resp = Response::from_request_header(&req_header, "POST", "localhost", 9988, "/a/b");
        let mac: Mac = Mac::from(vec![48, 133, 228, 163, 224, 197, 222, 77, 117, 81, 143, 73, 71,
                                      120, 68, 238, 228, 40, 55, 64, 190, 73, 102, 123, 79, 185,
                                      199, 26, 62, 1, 137, 170]);
        let server_header = Header::new(None,
                                        None,
                                        None,
                                        Some(mac),
                                        Some("server-ext"),
                                        None,
                                        None,
                                        None);
        assert!(resp.validate_header(&server_header, &Key::new("tok", &digest::SHA256)));
    }

    #[test]
    fn test_validation_hash_in_header() {
        // When a hash is provided in the response header, but no hash is added to the Response,
        // it is ignored (so validation succeeds)
        let req_header = make_req_header();
        let resp = Response::from_request_header(&req_header, "POST", "localhost", 9988, "/a/b");
        let mac: Mac = Mac::from(vec![33, 147, 159, 211, 184, 194, 189, 74, 53, 229, 241, 161,
                                      215, 145, 22, 34, 206, 207, 242, 100, 33, 193, 36, 96, 149,
                                      133, 180, 4, 132, 87, 207, 238]);
        let server_header = Header::new(None,
                                        None,
                                        None,
                                        Some(mac),
                                        Some("server-ext"),
                                        Some(vec![1, 2, 3, 4]),
                                        None,
                                        None);
        assert!(resp.validate_header(&server_header, &Key::new("tok", &digest::SHA256)));
    }

    #[test]
    fn test_validation_hash_required_but_not_given() {
        // When Response.hash is called, but no hash is in the hader, validation fails.
        let req_header = make_req_header();
        let hash = vec![1, 2, 3, 4];
        let resp = Response::from_request_header(&req_header, "POST", "localhost", 9988, "/a/b")
            .hash(&hash[..]);
        let mac: Mac = Mac::from(vec![48, 133, 228, 163, 224, 197, 222, 77, 117, 81, 143, 73, 71,
                                      120, 68, 238, 228, 40, 55, 64, 190, 73, 102, 123, 79, 185,
                                      199, 26, 62, 1, 137, 170]);
        let server_header = Header::new(None,
                                        None,
                                        None,
                                        Some(mac),
                                        Some("server-ext"),
                                        None,
                                        None,
                                        None);
        assert!(!resp.validate_header(&server_header, &Key::new("tok", &digest::SHA256)));
    }

    #[test]
    fn test_validation_hash_validated() {
        // When a hash is provided in the response header and the Response.hash method is called,
        // the two must match
        let req_header = make_req_header();
        let hash = vec![1, 2, 3, 4];
        let resp = Response::from_request_header(&req_header, "POST", "localhost", 9988, "/a/b")
            .hash(&hash[..]);
        let mac: Mac = Mac::from(vec![33, 147, 159, 211, 184, 194, 189, 74, 53, 229, 241, 161,
                                      215, 145, 22, 34, 206, 207, 242, 100, 33, 193, 36, 96, 149,
                                      133, 180, 4, 132, 87, 207, 238]);
        let server_header = Header::new(None,
                                        None,
                                        None,
                                        Some(mac),
                                        Some("server-ext"),
                                        Some(vec![1, 2, 3, 4]),
                                        None,
                                        None);
        assert!(resp.validate_header(&server_header, &Key::new("tok", &digest::SHA256)));

        // a different supplied hash won't match..
        let hash = vec![99, 99, 99, 99];
        let resp = Response::from_request_header(&req_header, "POST", "localhost", 9988, "/a/b")
            .hash(&hash[..]);
        assert!(!resp.validate_header(&server_header, &Key::new("tok", &digest::SHA256)));
    }
}
