// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains all of the structs which need to be constructed
//! to verify any of the following AKD proofs
//!
//! 1. Lookup
//! 2. Key history
//! 3. Audit (append-only)

use crate::hash::Digest;
#[cfg(feature = "serde_serialization")]
use crate::utils::serde_helpers::{
    azks_value_hex_deserialize, azks_value_hex_serialize, bytes_deserialize_hex,
    bytes_serialize_hex,
};
use crate::ARITY;

#[cfg(feature = "nostd")]
use alloc::string::{String, ToString};
#[cfg(feature = "nostd")]
use alloc::vec::Vec;
#[cfg(feature = "nostd")]
use core::cmp::{Ord, Ordering, PartialOrd};
#[cfg(feature = "rand")]
use rand::{CryptoRng, Rng};
#[cfg(not(feature = "nostd"))]
use std::cmp::{Ord, Ordering, PartialOrd};

pub mod node_label;
pub use node_label::*;

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

/// Whether or not a node is marked as stale or fresh
/// Stale nodes are no longer active because a newer
/// version exists to replace them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VersionFreshness {
    /// Represents not being the most recent version
    Stale = 0u8,
    /// Corresponds to the most recent version
    Fresh = 1u8,
}

/// This type is used to indicate whether or not
/// one label is a prefix of another, and if so,
/// whether the longer string has a 0 after the prefix,
/// or a 1 after the prefix. If the first label is equal
/// to the second, or not a prefix of the second, then it
/// is considered invalid.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum PrefixOrdering {
    /// Corresponds to a [Direction::Left]
    WithZero = 0u8,
    /// Corresponds to a [Direction::Right]
    WithOne = 1u8,
    /// First label is either equal to the second, or
    /// simply not a prefix of the second
    Invalid = u8::MAX,
}

impl SizeOf for PrefixOrdering {
    fn size_of(&self) -> usize {
        // The size of the enum is 24 bytes. The extra 8 bytes are used to store a 64-bit
        // discriminator that is used to identify the variant currently saved in the enum.
        24usize
    }
}

impl From<Bit> for PrefixOrdering {
    fn from(bit: Bit) -> Self {
        match bit {
            Bit::Zero => Self::WithZero,
            Bit::One => Self::WithOne,
        }
    }
}

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
}

impl SizeOf for Direction {
    fn size_of(&self) -> usize {
        // The size of the enum is 24 bytes. The extra 8 bytes are used to store a 64-bit
        // discriminator that is used to identify the variant currently saved in the enum.
        24usize
    }
}

impl From<Bit> for Direction {
    fn from(bit: Bit) -> Self {
        match bit {
            Bit::Zero => Self::Left,
            Bit::One => Self::Right,
        }
    }
}

impl core::convert::TryFrom<PrefixOrdering> for Direction {
    type Error = String;
    fn try_from(prefix_ordering: PrefixOrdering) -> Result<Self, Self::Error> {
        match prefix_ordering {
            PrefixOrdering::WithZero => Ok(Direction::Left),
            PrefixOrdering::WithOne => Ok(Direction::Right),
            _ => Err("Could not convert from PrefixOrdering to Direction".to_string()),
        }
    }
}

impl Direction {
    /// Returns the opposite of the direction
    pub fn other(&self) -> Self {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

/// The label of a particular entry in the AKD
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

impl core::convert::From<&str> for AkdLabel {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl core::convert::From<&String> for AkdLabel {
    fn from(s: &String) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl AkdLabel {
    #[cfg(feature = "rand")]
    /// Gets a random label
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes.to_vec())
    }
}

/// The value of a particular entry in the AKD
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

impl core::convert::From<&str> for AkdValue {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl core::convert::From<&String> for AkdValue {
    fn from(s: &String) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl AkdValue {
    #[cfg(feature = "rand")]
    /// Gets a random value for a AKD
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes.to_vec())
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

/// The value associated with an element of the AZKS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AzksValue(pub Digest);

/// Used to denote an azks value that has been hashed together with an epoch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AzksValueWithEpoch(pub Digest);

/// Represents an element to be inserted into the AZKS. This
/// is a pair consisting of a label ([NodeLabel]) and a value.
/// The purpose of the directory publish is to convert an
/// insertion set of ([AkdLabel], [AkdValue]) tuples into a
/// set of [AzksElement]s, which are then inserted into
/// the AZKS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AzksElement {
    /// The label of the node
    pub label: NodeLabel,
    /// The associated hash of the node
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "azks_value_hex_serialize")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "azks_value_hex_deserialize")
    )]
    pub value: AzksValue,
}

impl SizeOf for AzksElement {
    fn size_of(&self) -> usize {
        self.label.size_of() + self.value.0.len()
    }
}

impl PartialOrd for AzksElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AzksElement {
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
pub struct SiblingProof {
    /// The parent's label
    pub label: NodeLabel,
    /// Sibling of the parent that is not on the path
    pub siblings: [AzksElement; 1],
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
    pub hash_val: AzksValue,
    /// The parents of the node in question
    pub sibling_proofs: Vec<SiblingProof>,
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
    pub longest_prefix_children: [AzksElement; ARITY],
    /// The membership proof of the longest prefix
    pub longest_prefix_membership_proof: MembershipProof,
}

/// Proof that a given label was at a particular state at the given epoch.
/// This means we need to show that the state and version we are claiming for this node must have been:
/// * committed in the tree,
/// * not too far ahead of the most recent marker version,
/// * not stale when served.
///
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
    pub value: AkdValue,
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
    pub commitment_nonce: Vec<u8>,
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
    pub value: AkdValue,
    /// Version at this update
    pub version: u64,
    /// VRF proof for the label for the current version
    pub existence_vrf_proof: Vec<u8>,
    /// Membership proof to show that the key was included in this epoch
    pub existence_proof: MembershipProof,
    /// VRF proof for the label for the previous version which became stale
    pub previous_version_vrf_proof: Option<Vec<u8>>,
    /// Proof that previous value was set to old at this epoch
    pub previous_version_proof: Option<MembershipProof>,
    /// Nonce for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_nonce: Vec<u8>,
}

/// A client can query for a history of all versions associated with a given [AkdLabel], or the most recent k versions.
/// The server returns a [HistoryProof] which can be verified to extract a list of [VerifyResult]s, one for each
/// version.
/// Let `n` be the latest version, `n_prev_pow` be the power of 2 that is at most n, `n_next_pow` the next power of 2 after `n`, and `epoch_prev_pow` be the power of 2 that
/// is at most the current epoch. The [HistoryProof] consists of:
/// - A list of [UpdateProof]s, one for each version, which each contain a membership proof for the version `n` being fresh,
///   and a membership proof for the version `n-1` being stale
/// - A membership proof for `n_prev_pow` (or empty if n is a power of 2)
/// - A series of non-membership proofs for each version in the range `[n+1, n_next_pow]`
/// - A series of non-membership proofs for each power of 2 in the range `[n_next_pow, epoch_prev_pow]`
///
/// A client verifies this proof by first verifying each of the update proofs, checking that they are in decreasing
/// consecutive order by version. Then, it verifies the remaining proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct HistoryProof {
    /// The update proofs in the key history
    pub update_proofs: Vec<UpdateProof>,
    /// VRF Proofs for the labels of the values for past markers
    pub past_marker_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that the values for the past markers exist
    pub existence_of_past_marker_proofs: Vec<MembershipProof>,
    /// VRF proofs for the labels of future marker entries
    pub future_marker_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that future markers did not exist
    pub non_existence_of_future_marker_proofs: Vec<NonMembershipProof>,
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
    pub inserted: Vec<AzksElement>,
    /// The unchanged nodes & digests
    pub unchanged_nodes: Vec<AzksElement>,
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
