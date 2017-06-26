use base64;
use mac::Mac;
use error::*;
use std::str;
use std::str::FromStr;
use time::Timespec;

/// A Bewit is a piece of data attached to a GET request that functions in place of a Hawk
/// Authentication header.  It contains the four fields given here.
#[derive(Clone, Debug)]
pub struct Bewit {
    /// The client id for the request
    pub id: String,

    /// The expiration time of the Bewit; it should not be considered valid after this time
    pub exp: Timespec,

    /// The MAC of the request
    pub mac: Mac,

    /// The `ext` data included with the request
    pub ext: Option<String>,
}

impl Bewit {
    // TODO: do a better job with refs here -- Cow?
    /// Create a new bewit with the given values.
    ///
    /// See Request.make_bewit for an easier way to make a bewit
    pub fn new(id: String, exp: Timespec, mac: Mac, ext: Option<String>) -> Bewit {
        Bewit {
            id: id,
            exp: exp,
            mac: mac,
            ext: ext,
        }
    }

    /// Generate the fully-encoded string for this bewit
    pub fn to_str(&self) -> String {
        // TODO: is this the right rustish name for this?
        let raw = format!("{}\\{}\\{}\\{}",
                          self.id,
                          self.exp.sec,
                          base64::encode(&self.mac),
                          match self.ext {
                              Some(ref e) => e,
                              None => "",
                          });

        base64::encode_config(&raw, base64::URL_SAFE_NO_PAD)
    }
}

const BACKSLASH: u8 = '\\' as u8;

impl FromStr for Bewit {
    type Err = Error;
    fn from_str(bewit: &str) -> Result<Bewit> {
        let bewit = base64::decode(bewit)
            .chain_err(|| "Error decoding bewit base64")?;
        println!("decoded {:?}", bewit);

        let parts: Vec<&[u8]> = bewit.split(|c| *c == BACKSLASH).collect();
        if parts.len() != 4 {
            bail!("Invalid bewit format");
        }

        let id = String::from_utf8(parts[0].to_vec())
            .chain_err(|| "Invalid bewit id")?;
        println!("id {:?}", id);

        let exp = str::from_utf8(parts[1])
            .chain_err(|| "Invalid bewit exp")?;
        let exp = i64::from_str(&exp).chain_err(|| "Invalid bewit exp")?;
        let exp = Timespec::new(exp, 0);
        println!("exp {:?}", exp);

        let mac = str::from_utf8(parts[2])
            .chain_err(|| "Invalid bewit mac")?;
        let mac = Mac::from(base64::decode(mac).chain_err(|| "Invalid bewit mac")?);
        println!("mac {:?}", mac);

        let ext = match parts[3].len() {
            0 => None,
            _ => {
                Some(String::from_utf8(parts[3].to_vec())
                         .chain_err(|| "Invalid bewit ext")?)
            }
        };
        println!("ext {:?}", ext);

        Ok(Bewit {
               id: id,
               exp: exp,
               mac: mac,
               ext: ext,
           })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use credentials::Key;
    use ring::digest;
    use mac::{Mac, MacType};

    #[test]
    fn test_to_str() {
        let key = Key::new(vec![11u8, 19, 228, 209, 79, 189, 200, 59, 166, 47, 86, 254, 235, 184,
                                120, 197, 75, 152, 201, 79, 115, 61, 111, 242, 219, 187, 173, 14,
                                227, 108, 60, 232],
                           &digest::SHA256);
        let mac = Mac::new(MacType::Header,
                           &key,
                           Timespec::new(1353832834, 100),
                           "nonny",
                           "POST",
                           "mysite.com",
                           443,
                           "/v1/api",
                           None,
                           None)
                .unwrap();
        let bewit = Bewit::new("me".to_string(),
                               Timespec::new(1353832834, 0),
                               mac.clone(),
                               None);
        assert_eq!(bewit.to_str(),
                   "bWVcMTM1MzgzMjgzNFxmaXk0ZTV3QmRhcEROeEhIZUExOE5yU3JVMVUzaVM2NmdtMFhqVEpwWXlVPVw");
        let bewit = Bewit::new("me".to_string(),
                               Timespec::new(1353832834, 0),
                               mac,
                               Some("abcd".to_string()));
        assert_eq!(bewit.to_str(),
                   "bWVcMTM1MzgzMjgzNFxmaXk0ZTV3QmRhcEROeEhIZUExOE5yU3JVMVUzaVM2NmdtMFhqVEpwWXlVPVxhYmNk");
    }

    #[test]
    fn test_from_str_invalid_base64() {
        assert!(Bewit::from_str("!/==").is_err());
    }

    #[test]
    fn test_from_str_invalid_too_many_parts() {
        let bewit = base64::encode(&"a\\123\\abc\\ext\\WHUT?".as_bytes());
        assert!(Bewit::from_str(&bewit).is_err());
    }

    #[test]
    fn test_from_str_invalid_too_few_parts() {
        let bewit = base64::encode(&"a\\123\\abc".as_bytes());
        assert!(Bewit::from_str(&bewit).is_err());
    }

    #[test]
    fn test_from_str_invalid_not_utf8() {
        let a = 'a' as u8;
        let one = '1' as u8;
        let slash = '\\' as u8;
        let invalid1 = 0u8;
        let invalid2 = 159u8;
        let bewit = base64::encode(&[invalid1, invalid2, slash, one, slash, a, slash, a]);
        assert!(Bewit::from_str(&bewit).is_err());
        let bewit = base64::encode(&[a, slash, invalid1, invalid2, slash, a, slash, a]);
        assert!(Bewit::from_str(&bewit).is_err());
        let bewit = base64::encode(&[a, slash, one, slash, invalid1, invalid2, slash, a]);
        assert!(Bewit::from_str(&bewit).is_err());
        let bewit = base64::encode(&[a, slash, one, slash, a, slash, invalid1, invalid2]);
        assert!(Bewit::from_str(&bewit).is_err());
    }
}
