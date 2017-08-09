use ring::{digest, hmac};

/// Hawk key.
///
/// While any sequence of bytes can be specified as a key, note that each digest algorithm has
/// a suggested key length, and that passwords should *not* be used as keys.  Keys of incorrect
/// length are handled according to the digest's implementation.
pub struct Key(hmac::SigningKey);

impl Key {
    pub fn new<B>(key: B, algorithm: &'static digest::Algorithm) -> Key
        where B: Into<Vec<u8>>
    {
        Key(hmac::SigningKey::new(algorithm, key.into().as_ref()))
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let digest = hmac::sign(&self.0, data);
        let mut mac = vec![0; self.0.digest_algorithm().output_len];
        mac.clone_from_slice(digest.as_ref());
        mac
    }
}

/// Hawk credentials: an ID and a key associated with that ID.  The digest algorithm
/// must be agreed between the server and the client, and the length of the key is
/// specific to that algorithm.
pub struct Credentials {
    pub id: String,
    pub key: Key,
}

#[cfg(test)]
mod test {
    use super::*;
    use ring::digest;

    #[test]
    fn test_new_sha256() {
        let key = vec![77u8; 32];
        // hmac::SigningKey doesn't allow any visibilty inside, so we just build the
        // key and assume it works..
        Key::new(key, &digest::SHA256);
    }

    #[test]
    fn test_new_sha256_bad_length() {
        let key = vec![0u8; 99];
        Key::new(key, &digest::SHA256);
    }
}
