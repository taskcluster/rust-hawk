use ring::digest;

/// A utility for hashing payloads. Feed your entity body to this, then pass the `finish`
/// result to a request or response.
pub struct PayloadHasher {
    context: digest::Context,
    algorithm: &'static digest::Algorithm,
}

// TODO: this produces vecs, but request expects slices..

impl PayloadHasher {
    /// Create a new PayloadHasher. The `content_type` should be lower-case and should
    /// not include parameters. The digest is assumed to be the same as the digest used
    /// for the credentials in the request.
    pub fn new(content_type: &str, algorithm: &'static digest::Algorithm) -> Self {
        let mut hasher = PayloadHasher {
            context: digest::Context::new(algorithm),
            algorithm: algorithm,
        };
        hasher.update("hawk.1.payload\n");
        hasher.update(content_type);
        hasher.update("\n");
        hasher
    }

    /// Hash a single value and return it
    pub fn hash<I>(content_type: &str, algorithm: &'static digest::Algorithm, payload: I) -> Vec<u8>
        where I: Into<Vec<u8>>
    {
        let mut hasher = PayloadHasher::new(content_type, algorithm);
        hasher.update(payload);
        hasher.finish()
    }

    /// Update the hash with new data.
    pub fn update<I>(&mut self, data: I)
        where I: Into<Vec<u8>>
    {
        self.context.update(&data.into());
    }

    /// Finish hashing and return the result
    pub fn finish(self) -> Vec<u8> {
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
        let mut hasher1 = PayloadHasher::new("text/plain", &SHA256);
        hasher1.update("pay");
        hasher1.update("load");
        let hash1 = hasher1.finish();

        let mut hasher2 = PayloadHasher::new("text/plain", &SHA256);
        hasher2.update("payload");
        let hash2 = hasher2.finish();

        let hash3 = PayloadHasher::hash("text/plain", &SHA256, "payload");

        assert_eq!(hash1,
                   vec![225, 68, 122, 117, 216, 108, 218, 219, 48, 208, 69, 118, 157, 126, 119,
                        209, 205, 109, 173, 75, 255, 47, 180, 155, 55, 26, 251, 145, 81, 212, 81,
                        54]);
        assert_eq!(hash2, hash1);
        assert_eq!(hash3, hash1);
    }
}
