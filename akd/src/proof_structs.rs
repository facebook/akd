// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Note that the proofs [`AppendOnlyProof`], [`MembershipProof`] and [`NonMembershipProof`] are Merkle Patricia tree proofs,
//! while the proofs [`HistoryProof`] and [`LookupProof`] are AKD proofs.

#[cfg(feature = "serde_serialization")]
use crate::serialization::{digest_deserialize, digest_serialize};
use crate::{node_label::NodeLabel, storage::types::AkdValue, Direction, Node, ARITY};
use winter_crypto::Hasher;

/// Proof value at a single layer of the tree
/// Note that this is really a helper struct to
/// hold the sibling path for a Merkle tree proof.
/// When sending a sibling path, you need to know
/// which direction to hash a node (left or right)
/// since in a compressed tree, the label alone is not
/// enough to derive the path.
/// Thus, we include the direction at which to place the
/// ancestor of the node for which a proof is being generated.
/// The parent is the parent of the level in the tree at which you are.
/// See documentation for [`MembershipProof`] to see how this is used.
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
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
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct MembershipProof<H: Hasher> {
    /// The node label
    pub label: NodeLabel,
    /// The hash of the value
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "digest_serialize")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "digest_deserialize")
    )]
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
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
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
/// This is done using a list of SingleAppendOnly proofs, one proof
/// for each epoch between the initial epoch and final epochs which are
/// being audited.
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct AppendOnlyProof<H: Hasher> {
    /// Proof for a single epoch being append-only
    pub proofs: Vec<SingleAppendOnlyProof<H>>,
    /// Epochs over which this audit is being performed
    pub epochs: Vec<u64>,
}

/// Proof that no leaves were deleted from the initial epoch.
/// This means that unchanged_nodes should hash to the initial root hash
/// and the vec of inserted is the set of leaves inserted between these epochs.
/// If we built the tree using the nodes in inserted and the nodes in unchanged_nodes
/// as the leaves with the correct epoch of insertion,
/// it should result in the final root hash.
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct SingleAppendOnlyProof<H: Hasher> {
    /// The inserted nodes & digests
    pub inserted: Vec<Node<H>>,
    /// The unchanged nodes & digests
    pub unchanged_nodes: Vec<Node<H>>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for SingleAppendOnlyProof<H> {
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
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct LookupProof<H: Hasher> {
    /// The epoch of this record
    pub epoch: u64,
    /// The plaintext value in question
    pub plaintext_value: AkdValue,
    /// The version of the record
    pub version: u64,
    /// VRF proof for the label corresponding to this version
    pub existence_vrf_proof: Vec<u8>,
    /// Record existence proof
    pub existence_proof: MembershipProof<H>,
    /// VRF proof for the marker preceding (less than or equal to) this version
    pub marker_vrf_proof: Vec<u8>,
    /// Existence at specific marker
    pub marker_proof: MembershipProof<H>,
    /// VRF proof for the label corresponding to this version being stale
    pub freshness_vrf_proof: Vec<u8>,
    /// Freshness proof (non membership of stale label)
    pub freshness_proof: NonMembershipProof<H>,
    /// Proof for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_proof: Vec<u8>,
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
            existence_vrf_proof: self.existence_vrf_proof.clone(),
            marker_vrf_proof: self.marker_vrf_proof.clone(),
            freshness_vrf_proof: self.freshness_vrf_proof.clone(),
            commitment_proof: self.commitment_proof.clone(),
        }
    }
}

/// This proof is an array of [`UpdateProof`]s
/// and proofs of non-membership of future entries
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct HistoryProof<H: Hasher> {
    /// For each version v = 1...n of a user's key,
    /// include a proof that the previous version
    /// was retired at the same time as this version
    /// was added. (for version 1, it's just a mem proof).
    pub update_proofs: Vec<UpdateProof<H>>,
    /// VRF Proofs for the labels of the next few values, these are
    /// values in the set [latest_version + 1, ..., 2^(log(latest_version+1))-1]
    pub next_few_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that the next few values did not exist at this time
    pub non_existence_of_next_few: Vec<NonMembershipProof<H>>,
    /// VRF proofs for the labels of future marker entries, these are values with
    /// version numbers [2^(log(latest_version+1)), ..., 2^(log(latest_epoch))]
    pub future_marker_vrf_proofs: Vec<Vec<u8>>,
    /// Proof that future markers did not exist
    pub non_existence_of_future_markers: Vec<NonMembershipProof<H>>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for HistoryProof<H> {
    fn clone(&self) -> Self {
        Self {
            update_proofs: self.update_proofs.clone(),
            next_few_vrf_proofs: self.next_few_vrf_proofs.clone(),
            non_existence_of_next_few: self.non_existence_of_next_few.clone(),
            future_marker_vrf_proofs: self.future_marker_vrf_proofs.clone(),
            non_existence_of_future_markers: self.non_existence_of_future_markers.clone(),
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
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct UpdateProof<H: Hasher> {
    /// The epoch of this record
    pub epoch: u64,
    /// Version at this update
    pub version: u64,
    /// The plaintext value in question
    pub plaintext_value: AkdValue,
    /// VRF proof for the label for the current version
    pub existence_vrf_proof: Vec<u8>,
    /// Membership proof to show that the key was included in this epoch
    pub existence_at_ep: MembershipProof<H>,
    /// VRF proof for the label for the previous version which became stale
    pub previous_version_vrf_proof: Option<Vec<u8>>,
    /// Proof that previous value was set to old at this epoch
    pub previous_version_stale_at_ep: Option<MembershipProof<H>>,
    /// Proof for commitment value derived from raw AkdLabel and AkdValue
    pub commitment_proof: Vec<u8>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<H: Hasher> Clone for UpdateProof<H> {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch,
            version: self.version,
            plaintext_value: self.plaintext_value.clone(),
            existence_vrf_proof: self.existence_vrf_proof.clone(),
            existence_at_ep: self.existence_at_ep.clone(),
            previous_version_vrf_proof: self.previous_version_vrf_proof.clone(),
            previous_version_stale_at_ep: self.previous_version_stale_at_ep.clone(),
            commitment_proof: self.commitment_proof.clone(),
        }
    }
}
