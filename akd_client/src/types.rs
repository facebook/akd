// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all of the structs which need to be constructed
//! to verify any of the following AKD proofs
//!
//! 1. Lookup
//!
//! Append-only and history proofs to come

use crate::ARITY;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;
use core::convert::TryInto;

// ============================================
// Typedefs and constants
// ============================================

/// This type is used to indicate a direction for a
/// particular node relative to its parent.
pub type Direction = Option<usize>;
/// The label of a particular entry in the AKD
pub type AkdLabel = Vec<u8>;
/// The value of a particular entry in the AKD
pub type AkdValue = Vec<u8>;
/// A hash digest (size will depend on hashing algorithm specified
/// at compilation time)
pub type Digest = [u8; crate::hash::DIGEST_BYTES];

/// The value to be hashed every time an empty node's hash is to be considered
pub const EMPTY_VALUE: [u8; 1] = [0u8];

/// The label used for an empty node
pub const EMPTY_LABEL: NodeLabel = NodeLabel {
    val: [1u8; 32],
    len: 0,
};

/// A "tombstone" is a false value in an AKD ValueState denoting that a real value has been removed (e.g. data rentention policies).
/// Should a tombstone be encountered, we have to assume that the hash of the value is correct, and we move forward without being able to
/// verify the raw value. We utilize an empty array to save space in the storage layer
///
/// See [GitHub issue #130](https://github.com/novifinancial/akd/issues/130) for more context
pub const TOMBSTONE: &[u8] = &[];

// ============================================
// Structs
// ============================================

/// Represents the label of a AKD node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct NodeLabel {
    /// val stores a binary string as a u64
    pub val: [u8; 32],
    /// len keeps track of how long the binary string is
    pub len: u32,
}

impl NodeLabel {
    pub(crate) fn hash(&self) -> Digest {
        let hash_input = [&self.len.to_be_bytes()[..], &self.val].concat();
        crate::hash::hash(&hash_input)
    }

    /// Takes as input a pointer to the caller and another NodeLabel,
    /// returns a NodeLabel that is the longest common prefix of the two.
    pub(crate) fn get_longest_common_prefix(&self, other: NodeLabel) -> Self {
        let shorter_len = if self.len < other.len {
            self.len
        } else {
            other.len
        };

        let mut prefix_len = 0;
        while prefix_len <= shorter_len
            && self.get_bit_at(prefix_len) == other.get_bit_at(prefix_len)
        {
            prefix_len += 1;
        }
        if *self == EMPTY_LABEL || other == EMPTY_LABEL {
            return EMPTY_LABEL;
        }
        self.get_prefix(prefix_len)
    }

    /// Returns the bit at a specified index, and a 0 on an out of range index
    fn get_bit_at(&self, index: u32) -> u8 {
        if index >= self.len {
            return 0;
        }

        let usize_index: usize = index.try_into().unwrap();
        let index_full_blocks = usize_index / 8;
        let index_remainder = usize_index % 8;
        (self.val[index_full_blocks] >> (7 - index_remainder)) & 1
    }

    /// Returns the prefix of a specified length, and the entire value on an out of range length
    pub(crate) fn get_prefix(&self, len: u32) -> Self {
        if len >= self.len {
            return *self;
        }
        if len == 0 {
            return Self {
                val: [0u8; 32],
                len: 0,
            };
        }

        let usize_len: usize = (len - 1).try_into().unwrap();
        let len_remainder = usize_len % 8;
        let len_div = usize_len / 8;

        let mut out_val = [0u8; 32];
        out_val[..len_div].clone_from_slice(&self.val[..len_div]);
        out_val[len_div] = (self.val[len_div] >> (7 - len_remainder)) << (7 - len_remainder);

        Self { val: out_val, len }
    }
}

/// Represents a node (label + hash) in the AKD
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    /// The label of the node
    pub label: NodeLabel,
    /// The associated hash of the node
    pub hash: Digest,
}

/// Represents a specific level of the tree with the parental sibling and the direction
/// of the parent for use in tree hash calculations
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipProof {
    /// The node label
    pub label: NodeLabel,
    /// The hash of the value
    pub hash_val: Digest,
    /// The parents of the node in question
    pub layer_proofs: Vec<LayerProof>,
}

/// Merkle Patricia proof of non-membership for a [`NodeLabel`] in the tree
/// at a given epoch.
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub previous_val_vrf_proof: Option<Vec<u8>>,
    /// Proof that previous value was set to old at this epoch
    pub previous_val_stale_at_ep: Option<MembershipProof>,
    /// Proof for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_proof: Vec<u8>,
}

/// This proof is just an array of [`UpdateProof`]s.
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryProof {
    /// The update proofs in the key history
    pub update_proofs: Vec<UpdateProof>,
    /// The epochs at which updates were made.
    pub epochs: Vec<u64>,
    /// VRF Proofs for the labels of the next few values
    pub next_few_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that the next few values did not exist at this time
    pub non_existence_of_next_few: Vec<NonMembershipProof>,
    /// VRF proofs for the labels of future marker entries
    pub future_marker_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that future markers did not exist
    pub non_existence_of_future_markers: Vec<NonMembershipProof>,
}
