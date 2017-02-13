use ring::rand;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;

/// Create a random string with `bytes` bytes of entropy.  The string
/// is base64-encoded. so it will be longer than bytes characters.
pub fn random_string(rng: &rand::SecureRandom, bytes: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; bytes];
    if let Err(_) = rng.fill(&mut bytes) {
        return Err("Cannot create random string".to_string());
    }
    Ok(bytes.to_base64(base64::Config {
        char_set: base64::CharacterSet::Standard,
        newline: base64::Newline::LF,
        pad: true,
        line_length: None,
    }))
}
