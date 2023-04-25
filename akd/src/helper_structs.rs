// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Helper structs that are used for various data structures,
//! to make it easier to pass arguments around.

use crate::Digest;
use crate::{storage::types::ValueState, NodeLabel};

/// Root hash of the tree and its associated epoch
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EpochHash(pub u64, pub Digest);

impl EpochHash {
    /// Get the contained epoch
    pub fn epoch(&self) -> u64 {
        self.0
    }
    /// Get the contained hash
    pub fn hash(&self) -> Digest {
        self.1
    }
}

#[derive(Clone, Debug)]
/// Info needed for a lookup of a user for an epoch
pub struct LookupInfo {
    pub(crate) value_state: ValueState,
    pub(crate) marker_version: u64,
    pub(crate) existent_label: NodeLabel,
    pub(crate) marker_label: NodeLabel,
    pub(crate) non_existent_label: NodeLabel,
}
