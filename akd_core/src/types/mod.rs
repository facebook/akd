// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all of the structs which need to be constructed
//! to verify any of the following AKD proofs
//!
//! 1. Lookup
//! 2: Key history
//! 3: Audit (append-only)

use crate::hash::Digest;
#[cfg(feature = "serde_serialization")]
use crate::utils::serde_helpers::{
    bytes_deserialize_hex, bytes_serialize_hex, digest_deserialize, digest_serialize,
};
use crate::ARITY;

#[cfg(feature = "nostd")]
use alloc::vec::Vec;
#[cfg(feature = "nostd")]
use alloc::{format, string::String};
#[cfg(feature = "nostd")]
use core::cmp::{Ord, Ordering, PartialOrd};
#[cfg(feature = "rand")]
use rand::{CryptoRng, Rng};
#[cfg(not(feature = "nostd"))]
use std::cmp::{Ord, Ordering, PartialOrd};

pub mod node_label;
pub use node_label::*;

/// The possible VALID child directions
pub const DIRECTIONS: [Direction; 2] = [Direction::Left, Direction::Right];

// ============================================
// Traits
// ============================================

/// Retrieve the in-memory size of a structure
pub trait SizeOf {
    /// Retrieve the in-memory size of a structure
    fn size_of(&self) -> usize;
}

// ============================================
// Typedefs and constants
// ============================================

/// This type is used to indicate a direction for a
/// particular node relative to its parent. We use
/// 0 to represent "left" and 1 to represent "right".
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Direction {
    /// Left
    Left = 0u8,
    /// Right
    Right = 1u8,
    /// No direction
    None = u8::MAX,
}

impl SizeOf for Direction {
    fn size_of(&self) -> usize {
        // The size of the enum is 24 bytes. The extra 8 bytes are used to store a 64-bit discriminator that is used to identify the variant currently saved in the enum.
        24usize
    }
}

impl core::convert::TryFrom<u8> for Direction {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            u8::MAX => Ok(Direction::None),
            0u8 => Ok(Direction::Left),
            1u8 => Ok(Direction::Right),
            _ => Err(format!(
                "Invalid value for direction received: {}. Supported values are 0, 1, {}",
                value,
                u8::MAX
            )),
        }
    }
}

/// The label of a particular entry in the AKD
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AkdLabel(
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "bytes_serialize_hex")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "bytes_deserialize_hex")
    )]
    pub Vec<u8>,
);

impl SizeOf for AkdLabel {
    fn size_of(&self) -> usize {
        self.0.len()
    }
}

impl core::ops::Deref for AkdLabel {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for AkdLabel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AkdLabel {
    /// Build an [`AkdLabel`] struct from an UTF8 string
    pub fn from_utf8_str(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    #[cfg(feature = "rand")]
    /// Gets a random value for a AKD
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self::from_utf8_str(&crate::utils::get_random_str(rng))
    }
}

/// The value of a particular entry in the AKD
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AkdValue(
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "bytes_serialize_hex")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "bytes_deserialize_hex")
    )]
    pub Vec<u8>,
);

impl SizeOf for AkdValue {
    fn size_of(&self) -> usize {
        self.0.len()
    }
}

impl core::ops::Deref for AkdValue {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for AkdValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AkdValue {
    /// Build an [`AkdValue`] struct from an UTF8 string
    pub fn from_utf8_str(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    #[cfg(feature = "rand")]
    /// Gets a random value for a AKD
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self::from_utf8_str(&crate::utils::get_random_str(rng))
    }
}

/// The value to be hashed every time an empty node's hash is to be considered
pub const EMPTY_VALUE: [u8; 1] = [0u8];

/// A "tombstone" is a false value in an AKD ValueState denoting that a real value has been removed (e.g. data rentention policies).
/// Should a tombstone be encountered, we have to assume that the hash of the value is correct, and we move forward without being able to
/// verify the raw value. We utilize an empty array to save space in the storage layer
///
/// See [GitHub issue #130](https://github.com/novifinancial/akd/issues/130) for more context
pub const TOMBSTONE: &[u8] = &[];

// ============================================
// Structs
// ============================================

/// Represents a node (label + hash) in the AKD
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Node {
    /// The label of the node
    pub label: NodeLabel,
    /// The associated hash of the node
    #[cfg_attr(
        feature = "serde_serialization",
        serde(
            serialize_with = "digest_serialize",
            deserialize_with = "digest_deserialize"
        )
    )]
    pub hash: Digest,
}

impl SizeOf for Node {
    fn size_of(&self) -> usize {
        self.label.size_of() + self.hash.len()
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        self.label.cmp(&other.label)
    }
}

/// Represents a specific level of the tree with the parental sibling and the direction
/// of the parent for use in tree hash calculations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct LayerProof {
    /// The parent's label
    pub label: NodeLabel,
    /// Siblings of the parent
    pub siblings: [Node; ARITY - 1],
    /// The direction
    pub direction: Direction,
}

/// Merkle proof of membership of a [`NodeLabel`] with a particular hash
/// value in the tree at a given epoch
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MembershipProof {
    /// The node label
    pub label: NodeLabel,
    /// The hash of the value
    #[cfg_attr(
        feature = "serde_serialization",
        serde(
            serialize_with = "digest_serialize",
            deserialize_with = "digest_deserialize"
        )
    )]
    pub hash_val: Digest,
    /// The parents of the node in question
    pub layer_proofs: Vec<LayerProof>,
}

/// Merkle Patricia proof of non-membership for a [`NodeLabel`] in the tree
/// at a given epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct NonMembershipProof {
    /// The label in question
    pub label: NodeLabel,
    /// The longest prefix in the tree
    pub longest_prefix: NodeLabel,
    /// The children of the longest prefix
    pub longest_prefix_children: [Node; ARITY],
    /// The membership proof of the longest prefix
    pub longest_prefix_membership_proof: MembershipProof,
}

/// Proof that a given label was at a particular state at the given epoch.
/// This means we need to show that the state and version we are claiming for this node must have been:
/// * committed in the tree,
/// * not too far ahead of the most recent marker version,
/// * not stale when served.
/// This proof is sent in response to a lookup query for a particular key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct LookupProof {
    /// The epoch of this record
    pub epoch: u64,
    /// The plaintext value in question
    pub plaintext_value: AkdValue,
    /// The version of the record
    pub version: u64,
    /// VRF proof for the label corresponding to this version
    pub existence_vrf_proof: Vec<u8>,
    /// Record existence proof
    pub existence_proof: MembershipProof,
    /// VRF proof for the marker preceding (less than or equal to) this version
    pub marker_vrf_proof: Vec<u8>,
    /// Existence at specific marker
    pub marker_proof: MembershipProof,
    /// VRF proof for the label corresponding to this version being stale
    pub freshness_vrf_proof: Vec<u8>,
    /// Freshness proof (non member at previous epoch)
    pub freshness_proof: NonMembershipProof,
    /// Proof for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_proof: Vec<u8>,
}

/// A vector of UpdateProofs are sent as the proof to a history query for a particular key.
/// For each version of the value associated with the key, the verifier must check that:
/// * the version was included in the claimed epoch,
/// * the previous version was retired at this epoch,
/// * the version did not exist prior to this epoch,
/// * the next few versions (up until the next marker), did not exist at this epoch,
/// * the future marker versions did  not exist at this epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct UpdateProof {
    /// Epoch of this update
    pub epoch: u64,
    /// Value at this update
    pub plaintext_value: AkdValue,
    /// Version at this update
    pub version: u64,
    /// VRF proof for the label for the current version
    pub existence_vrf_proof: Vec<u8>,
    /// Membership proof to show that the key was included in this epoch
    pub existence_at_ep: MembershipProof,
    /// VRF proof for the label for the previous version which became stale
    pub previous_version_vrf_proof: Option<Vec<u8>>,
    /// Proof that previous value was set to old at this epoch
    pub previous_version_stale_at_ep: Option<MembershipProof>,
    /// Proof for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_proof: Vec<u8>,
}

/// This proof is just an array of [`UpdateProof`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct HistoryProof {
    /// The update proofs in the key history
    pub update_proofs: Vec<UpdateProof>,
    /// VRF Proofs for the labels of the next few values
    pub next_few_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that the next few values did not exist at this time
    pub non_existence_of_next_few: Vec<NonMembershipProof>,
    /// VRF proofs for the labels of future marker entries
    pub future_marker_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that future markers did not exist
    pub non_existence_of_future_markers: Vec<NonMembershipProof>,
}

/// The payload that is outputted as a result of successful verification of
/// a [LookupProof] or [HistoryProof]. This includes the fields containing the
/// epoch that the leaf was published in, the version corresponding to the value,
/// and the value itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct VerifyResult {
    /// The epoch of this record
    pub epoch: u64,
    /// Version at this update
    pub version: u64,
    /// The plaintext value associated with the record
    pub value: AkdValue,
}

/// Proof that no leaves were deleted from the initial epoch.
/// This means that unchanged_nodes should hash to the initial root hash
/// and the vec of inserted is the set of leaves inserted between these epochs.
/// If we built the tree using the nodes in inserted and the nodes in unchanged_nodes
/// as the leaves with the correct epoch of insertion,
/// it should result in the final root hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct SingleAppendOnlyProof {
    /// The inserted nodes & digests
    pub inserted: Vec<Node>,
    /// The unchanged nodes & digests
    pub unchanged_nodes: Vec<Node>,
}

/// Proof that no leaves were deleted from the initial epoch.
/// This is done using a list of SingleAppendOnly proofs, one proof
/// for each epoch between the initial epoch and final epochs which are
/// being audited.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct AppendOnlyProof {
    /// Proof for a single epoch being append-only
    pub proofs: Vec<SingleAppendOnlyProof>,
    /// Epochs over which this audit is being performed
    pub epochs: Vec<u64>,
}
