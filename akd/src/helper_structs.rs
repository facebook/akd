// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Helper structs that are used for various data structures,
//! to make it easier to pass arguments around.

#[cfg(feature = "serde_serialization")]
use crate::serialization::{digest_deserialize, digest_serialize};

use winter_crypto::Hasher;

use crate::{storage::types::ValueState, NodeLabel};

/// Represents a node's label & associated hash
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct Node<H: Hasher> {
    /// the label associated with the accompanying hash
    pub label: NodeLabel,
    /// the hash associated to this label
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "digest_serialize")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "digest_deserialize")
    )]
    pub hash: H::Digest,
}

// can't use #derive because it doesn't bind correctly
// #derive and generics are not friendly; might make Debug weird too ...
// see also:
// https://users.rust-lang.org/t/why-does-deriving-clone-not-work-in-this-case-but-implementing-manually-does/29075
// https://github.com/rust-lang/rust/issues/26925
impl<H: Hasher> Copy for Node<H> {}

impl<H: Hasher> Clone for Node<H> {
    fn clone(&self) -> Node<H> {
        *self
    }
}

/// Root hash of the tree and its associated epoch
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EpochHash<H: Hasher>(pub u64, pub H::Digest);

#[derive(Clone)]
/// Info needed for a lookup of a user for an epoch
pub struct LookupInfo {
    pub(crate) value_state: ValueState,
    pub(crate) marker_version: u64,
    pub(crate) existent_label: NodeLabel,
    pub(crate) marker_label: NodeLabel,
    pub(crate) non_existent_label: NodeLabel,
}
