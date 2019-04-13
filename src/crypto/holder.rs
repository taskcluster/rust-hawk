use once_cell::sync::OnceCell;
use failure::Fail;
use super::Cryptographer;

static CRYPTOGRAPHER: OnceCell<&'static dyn Cryptographer> = OnceCell::INIT;

#[derive(Debug, Fail)]
#[fail(display = "Cryptographer already initialized")]
pub struct SetCryptographerError(());

/// Sets the global object that will be used for cryptographic operations.
///
/// This is a convenience wrapper over [`set_cryptographer`],
/// but takes a `Box<dyn Cryptographer>` instead.
pub fn set_boxed_cryptographer(c: Box<dyn Cryptographer>) -> Result<(), SetCryptographerError> {
    set_cryptographer(Box::leak(c))
}

/// Sets the global object that will be used for cryptographic operations.
///
/// This function may only be called once in the lifetime of a program.
///
/// Any calls into this crate that perform cryptography prior to calling this
/// function will panic.
pub fn set_cryptographer(c: &'static dyn Cryptographer) -> Result<(), SetCryptographerError> {
    CRYPTOGRAPHER.set(c).map_err(|_| SetCryptographerError(()))
}

pub(crate) fn get_crypographer() -> &'static dyn Cryptographer {
    autoinit_crypto();
    CRYPTOGRAPHER.get().map(|d| *d).expect("`hawk` cryptographer not initialized!")
}

#[cfg(feature = "use_ring")]
#[inline]
fn autoinit_crypto() {
    let _ = set_cryptographer(&super::ring::RingCryptographer);
}

#[cfg(feature = "use_openssl")]
#[inline]
fn autoinit_crypto() {
}

#[cfg(not(any(feature = "use_openssl", feature = "use_ring")))]
#[inline]
fn autoinit_crypto() {
}
