use ring::{digest, hmac};
use ring::rand;

/// Hawk credentials: an ID and a key associated with that ID.  The digest algorithm
/// must be agreed between the server and the client, and the length of the key is
/// specific to that algorithm.
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
            key: key,
        }
    }
}

/// Context for Hawk client authentication.  This contains the information that does not change
/// from request to request.
///
/// Most users will create a single Context for all Hawk requests.
pub struct Context<'a> {
    pub credentials: &'a Credentials,
    pub rng: &'a rand::SecureRandom,

    /// Optional application string to include in the header
    pub app: Option<&'a String>,

    /// Optional delegated-by attribute to include in the header
    pub dlg: Option<&'a String>,
}
