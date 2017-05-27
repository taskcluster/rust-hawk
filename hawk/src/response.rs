use mac::Mac;
use header::Header;
use credentials::Key;
use error::HawkError;

/// A Response represents a response from an HTTP server.
///
/// The structure is created from a request and then used to either create (server) or validate
/// (client) a `Server-Authentication` header.
///
/// # Examples
///
/// TODO
///
/// See the documentation in the crate root for examples of creating and validating headers.
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
    pub fn from_request_header(req_header: &'a Header,
                               method: &'a str,
                               host: &'a str,
                               port: u16,
                               path: &'a str,
                               hash: Option<&'a [u8]>,
                               ext: Option<&'a str>)
                               -> Self {
        Response {
            method: method,
            host: host,
            port: port,
            path: path,
            req_header: req_header,
            hash: hash,
            ext: ext,
        }
    }

    /// Create a new Header for this response, based on the given request and request header
    pub fn generate_header(&self, key: &Key) -> Result<Header, HawkError> {
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

        // first verify the MAC
        match Mac::new(true,
                       key,
                       ts,
                       nonce,
                       self.method,
                       self.host,
                       self.port,
                       self.path,
                       self.hash,
                       self.ext) {
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
        match (&self.hash, &response_header.hash) {
            (&Some(rh), &Some(ref hh)) => {
                if rh != &hh[..] {
                    return false;
                }
            }
            (&Some(_), &None) => {
                return false;
            }
            (&None, &Some(_)) => {
                return false;
            }
            (&None, &None) => (),
        }

        // NOTE: the timestamp self.req_header.ts was generated locally, so
        // there is no need to verify it

        true
    }
}

#[cfg(test)]
mod test {} // TODO: tests
