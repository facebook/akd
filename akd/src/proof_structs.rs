// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Note that the proofs [`AppendOnlyProof`], [`MembershipProof`] and [`NonMembershipProof`] are Merkle Patricia tree proofs,
//! while the proofs [`HistoryProof`] and [`LookupProof`] are AKD proofs.

use crate::serialization::{digest_deserialize, digest_serialize};
use crate::{node_state::Node, node_state::NodeLabel, storage::types::AkdValue, Direction, ARITY};
use serde::{Deserialize, Serialize};
use winter_crypto::Hasher;

/// Proof value at a single layer of the tree
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct LayerProof<H: Hasher> {
    /// The parent's label
    pub label: NodeLabel,
    /// Siblings of the parent
    pub siblings: [Node<H>; ARITY - 1],
    /// The direction
    pub direction: Direction,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for LayerProof<H> {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            siblings: self.siblings,
            direction: self.direction,
        }
    }
}

/// Merkle proof of membership of a [`NodeLabel`] with a particular hash value
/// in the tree at a given epoch.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct MembershipProof<H: Hasher> {
    /// The node label
    pub label: NodeLabel,
    /// The hash of the value
    #[serde(serialize_with = "digest_serialize")]
    #[serde(deserialize_with = "digest_deserialize")]
    pub hash_val: H::Digest,
    /// The proofs at the layers up the tree
    pub layer_proofs: Vec<LayerProof<H>>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for MembershipProof<H> {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            hash_val: self.hash_val,
            layer_proofs: self.layer_proofs.clone(),
        }
    }
}

/// Merkle Patricia proof of non-membership for a [`NodeLabel`] in the tree
/// at a given epoch.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct NonMembershipProof<H: Hasher> {
    /// The label in question
    pub label: NodeLabel,
    /// The longest prefix in the tree
    pub longest_prefix: NodeLabel,
    /// The children of the longest prefix
    pub longest_prefix_children: [Node<H>; ARITY],
    /// The membership proof of the longest prefix
    pub longest_prefix_membership_proof: MembershipProof<H>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for NonMembershipProof<H> {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            longest_prefix: self.longest_prefix,
            longest_prefix_children: self.longest_prefix_children,
            longest_prefix_membership_proof: self.longest_prefix_membership_proof.clone(),
        }
    }
}

/// Proof that no leaves were deleted from the initial epoch.
/// This means that unchanged_nodes should hash to the initial root hash
/// and the vec of inserted is the set of leaves inserted between these epochs.
/// If we built the tree using the nodes in inserted and the nodes in unchanged_nodes
/// as the leaves, it should result in the final root hash.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct AppendOnlyProof<H: Hasher> {
    /// The inserted nodes & digests
    pub inserted: Vec<Node<H>>,
    /// The unchanged nodes & digests
    pub unchanged_nodes: Vec<Node<H>>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for AppendOnlyProof<H> {
    fn clone(&self) -> Self {
        Self {
            inserted: self.inserted.clone(),
            unchanged_nodes: self.unchanged_nodes.clone(),
        }
    }
}

/// Proof that a given label was at a particular state at the given epoch.
/// This means we need to show that the state and version we are claiming for this node must have been:
/// * committed in the tree,
/// * not too far ahead of the most recent marker version,
/// * not stale when served.
/// This proof is sent in response to a lookup query for a particular key.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct LookupProof<H: Hasher> {
    /// The epoch of this record
    pub epoch: u64,
    /// The plaintext value in question
    pub plaintext_value: AkdValue,
    /// The version of the record
    pub version: u64,
    /// Record existence proof
    pub existence_proof: MembershipProof<H>,
    /// Existence at specific marker
    pub marker_proof: MembershipProof<H>,
    /// Freshness proof (non member at previous epoch)
    pub freshness_proof: NonMembershipProof<H>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for LookupProof<H> {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch,
            plaintext_value: self.plaintext_value.clone(),
            version: self.version,
            existence_proof: self.existence_proof.clone(),
            marker_proof: self.marker_proof.clone(),
            freshness_proof: self.freshness_proof.clone(),
        }
    }
}

/// A vector of UpdateProofs are sent as the proof to a history query for a particular key.
/// For each version of the value associated with the key, the verifier must check that:
/// * the version was included in the claimed epoch,
/// * the previous version was retired at this epoch,
/// * the version did not exist prior to this epoch,
/// * the next few versions (up until the next marker), did not exist at this epoch,
/// * the future marker versions did  not exist at this epoch.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct UpdateProof<H: Hasher> {
    /// Epoch of this update
    pub epoch: u64,
    /// Value at this update
    pub plaintext_value: AkdValue,
    /// Version at this update
    pub version: u64,
    /// Membership proof to show that the key was included in this epoch
    pub existence_at_ep: MembershipProof<H>,
    /// Proof that previous value was set to old at this epoch
    pub previous_val_stale_at_ep: Option<MembershipProof<H>>,
    /// Proof that this value didn't exist prior to this ep
    pub non_existence_before_ep: Option<NonMembershipProof<H>>,
    /// Proof that the next few values did not exist at this time
    pub non_existence_of_next_few: Vec<NonMembershipProof<H>>,
    /// Proof that future markers did not exist
    pub non_existence_of_future_markers: Vec<NonMembershipProof<H>>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for UpdateProof<H> {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch,
            plaintext_value: self.plaintext_value.clone(),
            version: self.version,
            existence_at_ep: self.existence_at_ep.clone(),
            previous_val_stale_at_ep: self.previous_val_stale_at_ep.clone(),
            non_existence_before_ep: self.non_existence_before_ep.clone(),
            non_existence_of_next_few: self.non_existence_of_next_few.clone(),
            non_existence_of_future_markers: self.non_existence_of_future_markers.clone(),
        }
    }
}

/// This proof is just an array of [`UpdateProof`]s.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct HistoryProof<H: Hasher> {
    /// The update proofs in the key history
    pub proofs: Vec<UpdateProof<H>>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for HistoryProof<H> {
    fn clone(&self) -> Self {
        Self {
            proofs: self.proofs.clone(),
        }
    }
}
