// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the hashing utilities needed for the AKD directory
//! and verification operations

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::String;
use core::slice;

/// A hash digest of a specified number of bytes
pub type Digest = [u8; DIGEST_BYTES];
/// Represents an empty digest, with no data contained
pub const EMPTY_DIGEST: [u8; DIGEST_BYTES] = [0u8; DIGEST_BYTES];

// =========================================
// ========== Blake3 settings ==============
// =========================================
#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "blake3")]
pub use crate::hash::blake3::hash;
#[cfg(feature = "blake3")]
pub use crate::hash::blake3::DIGEST_BYTES;

// =========================================
// ========== Sha2 settings ===============
// =========================================
#[cfg(feature = "sha2")]
pub mod sha2;
#[cfg(feature = "sha2")]
pub use crate::hash::sha2::hash;
#[cfg(feature = "sha2")]
pub use crate::hash::sha2::DIGEST_BYTES;

// =========================================
// ========== Sha3 settings ===============
// =========================================
#[cfg(feature = "sha3")]
pub mod sha3;
#[cfg(feature = "sha3")]
pub use crate::hash::sha3::hash;
#[cfg(feature = "sha3")]
pub use crate::hash::sha3::DIGEST_BYTES;

#[cfg(test)]
mod tests;

/// An error occurred while hashing data
#[derive(Debug, Eq, PartialEq)]
pub enum HashError {
    /// No direction was present when expected
    NoDirection(String),
}

impl core::fmt::Display for HashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            HashError::NoDirection(msg) => format!("(No Direction) - {}", msg),
        };
        write!(f, "Hashing error: {}", code)
    }
}

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

/// Merge N hashes into a single Digest
pub fn merge(items: &[Digest]) -> Digest {
    let p = items.as_ptr();
    let len = items.len() * DIGEST_BYTES;
    let data: &[u8] = unsafe { slice::from_raw_parts(p as *const u8, len) };
    hash(data)
}

/// Takes the hash of a value and merges it with a `u64`, hashing the result.
pub fn merge_with_u64(digest: Digest, value: u64) -> Digest {
    let mut data = [0; DIGEST_BYTES + 8];
    data[..DIGEST_BYTES].copy_from_slice(&digest);
    data[DIGEST_BYTES..].copy_from_slice(&value.to_be_bytes());
    hash(&data)
}
