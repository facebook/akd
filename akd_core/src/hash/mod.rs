// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains all the hashing utilities needed for the AKD directory
//! and verification operations

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::String;

/// A hash digest of a specified number of bytes
pub type Digest = [u8; DIGEST_BYTES];
/// Represents an empty digest, with no data contained
pub const EMPTY_DIGEST: [u8; DIGEST_BYTES] = [0u8; DIGEST_BYTES];
/// The number of bytes in a digest
pub const DIGEST_BYTES: usize = 32;

#[cfg(test)]
mod tests;

/// Try and parse a digest from an unknown length of bytes. Helpful for converting a `Vec<u8>`
/// to a [Digest]
pub fn try_parse_digest(value: &[u8]) -> Result<Digest, String> {
    if value.len() != DIGEST_BYTES {
        Err(format!(
            "Failed to parse Digest. Expected {} bytes but the value has {} bytes",
            DIGEST_BYTES,
            value.len()
        ))
    } else {
        let mut arr = EMPTY_DIGEST;
        arr.copy_from_slice(value);
        Ok(arr)
    }
}
