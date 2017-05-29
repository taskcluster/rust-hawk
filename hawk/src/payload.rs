use ring::digest;

/// A utility for hashing payloads. Feed your entity body to this, then pass the `finish`
/// result to a request or response.
pub struct PayloadHasher {
    context: digest::Context,
    algorithm: &'static digest::Algorithm,
}

impl PayloadHasher {
    /// Create a new PayloadHasher. The `content_type` should be lower-case and should
    /// not include parameters. The digest is assumed to be the same as the digest used
    /// for the credentials in the request.
    pub fn new<'a, B>(content_type: B, algorithm: &'static digest::Algorithm) -> Self
        where B: Into<&'a [u8]>
    {
        let mut hasher = PayloadHasher {
            context: digest::Context::new(algorithm),
            algorithm: algorithm,
        };
        hasher.update(&b"hawk.1.payload\n"[..]);
        hasher.update(content_type.into());
        hasher.update(&b"\n"[..]);
        hasher
    }

    /// Hash a single value and return it
    pub fn hash<'a, B1, B2>(content_type: B1,
                            algorithm: &'static digest::Algorithm,
                            payload: B2)
                            -> Vec<u8>
        where B1: Into<&'a [u8]>,
              B2: Into<&'a [u8]>
    {
        let mut hasher = PayloadHasher::new(content_type.into(), algorithm);
        hasher.update(payload);
        hasher.finish()
    }

    /// Update the hash with new data.
    pub fn update<'a, B>(&mut self, data: B)
        where B: Into<&'a [u8]>
    {
        let data = data.into();
        self.context.update(&data);
    }

    /// Finish hashing and return the result
    ///
    /// Note that this appends a newline to the payload, as does the JS Hawk implementaiton.
    pub fn finish(mut self) -> Vec<u8> {
        self.update(&b"\n"[..]);
        let digest = self.context.finish();
        let mut rv = vec![0; self.algorithm.output_len];
        rv.clone_from_slice(digest.as_ref());
        return rv;
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadHasher;
    use ring::digest::SHA256;

    #[test]
    fn hash_consistency() {
        let mut hasher1 = PayloadHasher::new(&b"text/plain"[..], &SHA256);
        hasher1.update(&b"pay"[..]);
        hasher1.update(&b"load"[..]);
        let hash1 = hasher1.finish();

        let mut hasher2 = PayloadHasher::new(&b"text/plain"[..], &SHA256);
        hasher2.update(&b"payload"[..]);
        let hash2 = hasher2.finish();

        let hash3 = PayloadHasher::hash(&b"text/plain"[..], &SHA256, &b"payload"[..]);

        assert_eq!(hash1,
                   vec![94, 16, 18, 216, 211, 65, 209, 208, 179, 220, 77, 56, 116, 162, 71, 244,
                        214, 10, 7, 3, 156, 125, 202, 174, 255, 95, 42, 66, 142, 115, 102, 101]);
        assert_eq!(hash2, hash1);
        assert_eq!(hash3, hash1);
    }
}
