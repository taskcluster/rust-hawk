//! This module contains basic base64 functionality as used in Hawk.

use base64::engine::{
    fast_portable::{FastPortable, FastPortableConfig},
    DecodePaddingMode,
};

/// BEWIT_ENGINE encodes to a url-safe value with no padding.
pub(crate) const BEWIT_ENGINE: FastPortable = FastPortable::from(
    &base64::alphabet::URL_SAFE,
    FastPortableConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

/// STANDARD_ENGINE encodes with the standard alphabet and includes padding.
pub(crate) const STANDARD_ENGINE: FastPortable = base64::engine::DEFAULT_ENGINE;
