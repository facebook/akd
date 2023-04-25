// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains hashing utilities for sha2 hashing

use sha2::Digest;

/// The number of bytes in a digest for SHA2 256 hashes
#[cfg(feature = "sha256")]
pub const DIGEST_BYTES: usize = 32;
/// The number of bytes in a digest for SHA2 512 hashes
#[cfg(feature = "sha512")]
pub const DIGEST_BYTES: usize = 64;
/// The number of bytes in a digest for the truncated SHA2 512 hashes.
/// This means we take the first 32 bytes of a 64 byte hash.
#[cfg(feature = "sha512_256")]
pub const DIGEST_BYTES: usize = 32;

/// Hash a single byte array
pub fn hash(item: &[u8]) -> crate::hash::Digest {
    #[cfg(feature = "sha256")]
    let hash = sha2::Sha256::digest(item);
    #[cfg(feature = "sha512")]
    let hash = sha2::Sha512::digest(item);
    #[cfg(feature = "sha512_256")]
    let hash = sha2::Sha512_256::digest(item);

    if hash.len() == DIGEST_BYTES {
        // OK
        let ptr = hash.as_ptr() as *const [u8; DIGEST_BYTES];
        unsafe { *ptr }
    } else {
        panic!("Hash digest is not {} bytes", DIGEST_BYTES);
    }
}
