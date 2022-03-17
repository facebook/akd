// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Utility functions

#[cfg(feature = "nostd")]
use alloc::vec::Vec;

/// Retrieve the marker version
pub(crate) fn get_marker_version(version: u64) -> u64 {
    64u64 - (version.leading_zeros() as u64) - 1u64
}

// Corresponds to the I2OSP() function from RFC8017, prepending the length of
// a byte array to the byte array (so that it is ready for serialization and hashing)
//
// Input byte array cannot be > 2^64-1 in length
pub(crate) fn i2osp_array(input: &[u8]) -> Vec<u8> {
    [&(input.len() as u64).to_be_bytes(), input].concat()
}

pub(crate) fn generate_commitment_from_proof_client(
    value: &crate::AkdValue,
    proof: &[u8],
) -> crate::Digest {
    crate::hash::hash(&[i2osp_array(value), i2osp_array(proof)].concat())
}
