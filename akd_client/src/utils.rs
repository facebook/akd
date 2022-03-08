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

// FIXME: Make a real commitment here, alongwith a blinding factor. See issue #123
/// Gets the bytes for a value.
pub(crate) fn value_to_bytes(value: &crate::AkdValue) -> crate::Digest {
    crate::hash::hash(value)
}
