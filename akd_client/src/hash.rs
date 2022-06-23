// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains hashing utilities for the verification proofs utilizing
//! various hashing schemes: SHA2 256, 512; SHA3 256, 512; BLAKE3 256

use core::slice;

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;

use crate::types::Digest as PublicDigest;
use crate::types::{Direction, NodeLabel};
use crate::{verify_error, VerificationError};

// ======================================
// SHA2 Settings
// ======================================
#[cfg(any(feature = "sha256", feature = "sha512"))]
use sha2::Digest;
#[cfg(feature = "sha256")]
pub(crate) const DIGEST_BYTES: usize = 32;
#[cfg(feature = "sha512")]
pub(crate) const DIGEST_BYTES: usize = 64;

// ======================================
// SHA3 Settings
// ======================================

#[cfg(any(feature = "sha3_256", feature = "sha3_512"))]
use sha3::Digest;
#[cfg(feature = "sha3_256")]
pub(crate) const DIGEST_BYTES: usize = 32;
#[cfg(feature = "sha3_512")]
pub(crate) const DIGEST_BYTES: usize = 64;

// ======================================
// BLAKE3 Settings
// ======================================
#[cfg(feature = "blake3")]
pub(crate) const DIGEST_BYTES: usize = 32;

/// Hash a single byte array
pub(crate) fn hash(item: &[u8]) -> PublicDigest {
    #[cfg(feature = "blake3")]
    return blake3::hash(item).into();

    #[cfg(feature = "sha256")]
    let hash = sha2::Sha256::digest(item);
    #[cfg(feature = "sha512")]
    let hash = sha2::Sha512::digest(item);
    #[cfg(feature = "sha3_256")]
    let hash = sha3::Sha3_256::digest(item);
    #[cfg(feature = "sha3_512")]
    let hash = sha3::Sha3_512::digest(item);
    #[cfg(not(feature = "blake3"))]
    {
        if hash.len() == DIGEST_BYTES {
            // OK
            let ptr = hash.as_ptr() as *const [u8; DIGEST_BYTES];
            unsafe { *ptr }
        } else {
            panic!("Hash digest is not {} bytes", DIGEST_BYTES);
        }
    }
}

/// Merge N hashes
pub(crate) fn merge(items: &[[u8; DIGEST_BYTES]]) -> PublicDigest {
    let p = items.as_ptr();
    let len = items.len() * DIGEST_BYTES;
    let data: &[u8] = unsafe { slice::from_raw_parts(p as *const u8, len) };
    hash(data)
}

/// Take a hash and merge it with an integer and hash the resulting bytes
#[cfg(feature = "vrf")]
pub(crate) fn merge_with_int(digest: PublicDigest, value: u64) -> PublicDigest {
    let mut data = [0; DIGEST_BYTES + 8];
    data[..DIGEST_BYTES].copy_from_slice(&digest);
    // this comes from winter_crypto::Hasher. We stick with little-endian bytes everywhere
    // to avoid system-specific implementation headaches
    data[DIGEST_BYTES..].copy_from_slice(&value.to_le_bytes());
    hash(&data)
}

/// Hashes all the children of a node, as well as their labels
pub(crate) fn build_and_hash_layer(
    hashes: Vec<PublicDigest>,
    dir: Direction,
    ancestor_hash: PublicDigest,
    parent_label: NodeLabel,
) -> Result<PublicDigest, VerificationError> {
    let direction = dir.ok_or_else(|| {
        verify_error!(NoDirection, PublicDigest, format!("{:?}", parent_label.val))
    })?;
    let mut hashes_mut = hashes.to_vec();
    hashes_mut.insert(direction, ancestor_hash);
    Ok(hash_layer(hashes_mut, parent_label))
}

/// Helper for build_and_hash_layer
pub(crate) fn hash_layer(hashes: Vec<PublicDigest>, parent_label: NodeLabel) -> PublicDigest {
    let new_hash = merge(&[hashes[0], hashes[1]]);
    merge(&[new_hash, parent_label.hash()])
}
