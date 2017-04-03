use ring::{digest, hmac};

/// Hawk credentials: an ID and a key associated with that ID.  The digest algorithm
/// must be agreed between the server and the client, and the length of the key is
/// specific to that algorithm.
pub struct Credentials {
    pub id: String,
    pub key: hmac::SigningKey,
}

impl Credentials {
    /// Create a new set of credentials, using the given key and algorithm.
    ///
    /// While any sequence of bytes can be specified as a key, note that each digest algorithm has
    /// a suggested key length, and that passwords should *not* be used as keys.  Keys of incorrect
    /// length are handled according to the digest's implementation.
    pub fn new<S, B>(id: S, key: B, algorithm: &'static digest::Algorithm) -> Credentials
        where S: Into<String>,
              B: Into<Vec<u8>>
    {
        let key = key.into();
        let key = hmac::SigningKey::new(algorithm, key.as_ref());
        Credentials {
            id: id.into(),
            key: key,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ring::digest;

    #[test]
    fn test_new_sha256() {
        let id = "clientId";
        let key = vec![0u8; 32];
        assert_eq!(Credentials::new(id, key, &digest::SHA256).id, "clientId".to_string());
    }

    #[test]
    fn test_new_sha256_bad_length() {
        let id = "clientId";
        let key = vec![0u8; 99];
        assert_eq!(Credentials::new(id, key, &digest::SHA256).id, "clientId".to_string());
    }
}
