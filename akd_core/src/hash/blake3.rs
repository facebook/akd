// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains hashing utilities for blake3 hashing

/// The number of bytes in a digest for Blake3 hashes
pub const DIGEST_BYTES: usize = 32;

/// Hash a single byte array
pub fn hash(item: &[u8]) -> crate::hash::Digest {
    ::blake3::hash(item).into()
}
