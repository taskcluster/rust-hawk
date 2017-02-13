use ring::{digest, hmac};
use ring::rand;

/// Hawk credentials: an id, a key associated with that ID, and an algorithm.
pub struct Credentials {
    pub id: String,
    pub key: hmac::SigningKey,
}

impl Credentials {
    pub fn new<S, B>(id: S, key: B, algorithm: &'static digest::Algorithm) -> Credentials
        where S: Into<String>,
              B: Into<Vec<u8>>
    {
        let key = key.into();
        let key = hmac::SigningKey::new(algorithm, key.as_ref());
        Credentials {
            id: id.into(),
            key: key.into(),
        }
    }
}

/// Context for Hawk client authentication.  This contains informatino that does not change from
/// request to request.
pub struct Context<'a> {
    pub credentials: &'a Credentials,
    pub rng: &'a rand::SecureRandom,

    // Optional fields for Hawk requests
    pub app: Option<&'a String>,
    pub dlg: Option<&'a String>,
}
