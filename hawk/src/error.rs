use std::fmt;
use std::io;
use std::error;
use std::convert::From;
use ring;

#[derive(Debug)]
pub enum HawkError {
    HeaderParseError,
    MissingAttributes,
    UnknownAttribute,
    InvalidTimestamp,
    Base64DecodeError,
    UrlError(String),
    CryptoError,
    IoError(io::Error),
}

impl From<ring::error::Unspecified> for HawkError {
    fn from(_: ring::error::Unspecified) -> Self {
        HawkError::CryptoError
    }
}

impl From<io::Error> for HawkError {
    fn from(err: io::Error) -> HawkError {
        HawkError::IoError(err)
    }
}

impl fmt::Display for HawkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl error::Error for HawkError {
    fn description(&self) -> &str {
        match *self {
            HawkError::HeaderParseError => "Unparsable Hawk header",
            HawkError::MissingAttributes => "Hawk header is missing required attributes",
            HawkError::UnknownAttribute => "Hawk header has an unknown attribute",
            HawkError::InvalidTimestamp => "Hawk header's `ts` value is invalid",
            HawkError::Base64DecodeError => "One of the Hawk header's base64-encoded values is invalid",
            HawkError::UrlError(_) => "Error parsing a URL",
            HawkError::CryptoError => "Cryptographic error",
            HawkError::IoError(_) => "encountered an I/O error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            HawkError::IoError(ref err) => Some(err as &error::Error),
            _ => None,
        }
    }
}
