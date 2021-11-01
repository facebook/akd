// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use winter_crypto::Hasher;

use crate::{node_state::NodeLabel, storage::types::Values, Direction, ARITY};

#[derive(Debug, Clone)]
pub struct MembershipProof<H: Hasher> {
    pub(crate) label: NodeLabel,
    pub(crate) hash_val: H::Digest,
    pub(crate) parent_labels: Vec<NodeLabel>,
    pub(crate) sibling_labels: Vec<[NodeLabel; ARITY - 1]>,
    pub(crate) sibling_hashes: Vec<[H::Digest; ARITY - 1]>,
    pub(crate) dirs: Vec<Direction>,
}

#[derive(Debug, Clone)]
pub struct NonMembershipProof<H: Hasher> {
    pub(crate) label: NodeLabel,
    pub(crate) longest_prefix: NodeLabel,
    pub(crate) longest_prefix_children_labels: [NodeLabel; ARITY],
    pub(crate) longest_prefix_children_values: [H::Digest; ARITY],
    pub(crate) longest_prefix_membership_proof: MembershipProof<H>,
}

#[derive(Debug, Clone)]
pub struct AppendOnlyProof<H: Hasher> {
    pub(crate) inserted: Vec<(NodeLabel, H::Digest)>,
    pub(crate) unchanged_nodes: Vec<(NodeLabel, H::Digest)>,
}

#[derive(Debug, Clone)]
pub struct LookupProof<H: Hasher> {
    pub(crate) epoch: u64,
    pub(crate) plaintext_value: Values,
    pub(crate) version: u64,
    pub(crate) existence_proof: MembershipProof<H>,
    pub(crate) marker_proof: MembershipProof<H>,
    pub(crate) freshness_proof: NonMembershipProof<H>,
}

#[derive(Debug, Clone)]
pub struct UpdateProof<H: Hasher> {
    pub(crate) epoch: u64,
    pub(crate) plaintext_value: Values,
    pub(crate) version: u64,
    pub(crate) existence_at_ep: MembershipProof<H>, // membership proof to show that the key was included in this epoch
    pub(crate) previous_val_stale_at_ep: Option<MembershipProof<H>>, // proof that previous value was set to old at this epoch
    pub(crate) non_existence_before_ep: Option<NonMembershipProof<H>>, // proof that this value didn't exist prior to this ep
    #[allow(unused)]
    pub(crate) non_existence_of_next_few: Vec<NonMembershipProof<H>>, // proof that the next few values did not exist at this time
    #[allow(unused)]
    pub(crate) non_existence_of_future_markers: Vec<NonMembershipProof<H>>, // proof that future markers did not exist
}

#[derive(Debug, Clone)]
pub struct HistoryProof<H: Hasher> {
    #[allow(unused)]
    pub(crate) proofs: Vec<UpdateProof<H>>,
}
