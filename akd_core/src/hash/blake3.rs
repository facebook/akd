// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains hashing utilities for blake3 hashing

/// The number of bytes in a digest for Blake3 hashes
pub const DIGEST_BYTES: usize = 32;

/// Hash a single byte array
pub fn hash(item: &[u8]) -> crate::hash::Digest {
    return ::blake3::hash(item).into();
}
