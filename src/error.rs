use failure::Fail;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Unparseable Hawk header: {}", _0)]
    HeaderParseError(String),

    #[fail(display = "Invalid url: {}", _0)]
    InvalidUrl(String),

    #[fail(display = "Missing `ts` attribute in Hawk header")]
    MissingTs,

    #[fail(display = "Missing `nonce` attribute in Hawk header")]
    MissingNonce,

    #[fail(display = "{}", _0)]
    InvalidBewit(#[fail(cause)] InvalidBewit),

    #[fail(display = "{}", _0)]
    Io(#[fail(cause)] std::io::Error),

    #[fail(display = "Base64 Decode error: {}", _0)]
    Decode(#[fail(cause)] base64::DecodeError),

    #[fail(display = "RNG error: {}", _0)]
    Rng(#[fail(cause)] rand::Error),
}

#[derive(Fail, Debug, PartialEq)]
pub enum InvalidBewit {
    #[fail(display = "Multiple bewits in URL")]
    Multiple,
    #[fail(display = "Invalid bewit format")]
    Format,
    #[fail(display = "Invalid bewit id")]
    Id,
    #[fail(display = "Invalid bewit exp")]
    Exp,
    #[fail(display = "Invalid bewit mac")]
    Mac,
    #[fail(display = "Invalid bewit ext")]
    Ext,
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Decode(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rand::Error> for Error {
    fn from(e: rand::Error) -> Self {
        Error::Rng(e)
    }
}

impl From<InvalidBewit> for Error {
    fn from(e: InvalidBewit) -> Self {
        Error::InvalidBewit(e)
    }
}
