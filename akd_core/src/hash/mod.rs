// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the hashing utilities needed for the AKD directory
//! and verification operations

use crate::Direction;
use crate::NodeLabel;

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::String;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;
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
        write!(f, "Hashing error {}", code)
    }
}

/// Try and parse a digest from an unknown length of bytes. Helpful for converting a Vec<u8>
/// to a Digest
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

/// Take a hash and merge it with an integer and hash the resulting bytes
pub fn merge_with_int(digest: Digest, value: u64) -> Digest {
    let mut data = [0; DIGEST_BYTES + 8];
    data[..DIGEST_BYTES].copy_from_slice(&digest);
    // this comes from winter_crypto::Hasher. We stick with little-endian bytes everywhere
    // to avoid system-specific implementation headaches
    data[DIGEST_BYTES..].copy_from_slice(&value.to_le_bytes());
    hash(&data)
}

/// Hashes all the children of a node, as well as their labels
pub fn build_and_hash_layer(
    hashes: Vec<Digest>,
    dir: Direction,
    ancestor_hash: Digest,
    parent_label: NodeLabel,
) -> Result<Digest, HashError> {
    let direction = dir.ok_or_else(|| {
        HashError::NoDirection(format!("Empty direction for {:?}", parent_label.label_val))
    })?;
    let mut hashes_mut = hashes.to_vec();
    hashes_mut.insert(direction, ancestor_hash);
    Ok(hash_layer(hashes_mut, parent_label))
}

/// Helper for build_and_hash_layer
pub fn hash_layer(hashes: Vec<Digest>, parent_label: NodeLabel) -> Digest {
    let new_hash = merge(&[hashes[0], hashes[1]]);
    merge(&[new_hash, parent_label.hash()])
}
