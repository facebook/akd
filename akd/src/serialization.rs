// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module provides helpful serialization calls for mapping to/from a winter_crypto::Hasher::Digest

use crate::errors::HistoryTreeNodeError;
use winter_crypto::Hasher;
use winter_utils::{Deserializable, Serializable, SliceReader};

/// Converts from &[u8] to H::Digest
pub fn to_digest<H: Hasher>(input: &[u8]) -> Result<H::Digest, HistoryTreeNodeError> {
    H::Digest::read_from(&mut SliceReader::new(input))
        .map_err(|_| HistoryTreeNodeError::SerializationError)
}

/// Converts from H::Digest to Vec<u8>
pub fn from_digest<H: Hasher>(input: H::Digest) -> Result<Vec<u8>, HistoryTreeNodeError> {
    let mut output = vec![];
    input.write_into(&mut output);
    Ok(output)
}
