// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Utility functions

/// Retrieve the marker version
#[cfg(feature = "vrf")]
pub(crate) fn get_marker_version(version: u64) -> u64 {
    64u64 - (version.leading_zeros() as u64) - 1u64
}

// Note that this is the truncating version, since the only thing being
// verified where this is called is the final hash.
// If the hash function's output is too large, truncating it should be ok.
// tl;dr TRUNCATES!
#[cfg(feature = "vrf")]
pub(crate) fn vec_to_u8_arr(vector_u8: Vec<u8>) -> [u8; 32] {
    let mut out_arr = [0u8; 32];
    out_arr[..vector_u8.len()].clone_from_slice(&vector_u8[..32]);
    out_arr
}
