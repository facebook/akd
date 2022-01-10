// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module defines the inter-node and external messages which the quorum handles that are
//! not defined within the AKD crate.

use crate::comms::NodeId;

// ===========================================================
// Inter node messages
// ===========================================================
pub(crate) mod inter_node {
    // Verify Request
    pub(crate) struct VerifyRequest<H: winter_crypto::Hasher> {
        pub(crate) append_only_proof: akd::proof_structs::AppendOnlyProof<H>,
        pub(crate) previous_hash: H::Digest,
        pub(crate) new_hash: H::Digest,
        pub(crate) epoch: u64,
    }
    // Verify Response
    pub(crate) struct VerifyResponse<H: winter_crypto::Hasher> {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
        pub(crate) verified_hash: Option<H::Digest>,
    }
}

// ===========================================================
// Public messages
// ===========================================================

/// Verify the changes from epoch - 1 => epoch with the following properties.
/// If verification is successful, we can proceed with generating & saving a commitment
pub struct VerifyChangesRequest<H: winter_crypto::Hasher> {
    /// The proof generated from the AKD publish operation
    pub append_only_proof: akd::proof_structs::AppendOnlyProof<H>,
    /// The previous hash, which the "unchanged" proof nodes should result with. Also
    /// should match the hash of the last commitment
    pub previous_hash: H::Digest,
    /// The current hash, which after inserting the "inserted" nodes, should be the result
    pub new_hash: H::Digest,
    /// The new epoch number. Should = last_committed_epoch + 1
    pub epoch: u64,
}

/// Enroll a new member to the quorum. The potential member will be independently
/// verified by each of the nodes in the quorum
pub struct EnrollMemberRequest {
    /// The new potential node's public key
    pub public_key: Vec<u8>,
    // TODO: this type needs to be changed
    /// The new node's open contact information to receive test information
    pub contact_information: String,
}

/// Request to remove the specified member. If a quorum of other nodes can be achieved
/// which agree that the member in question should be removed (is unreachable or is
/// computing invalid proofs) then the leader can reconstruct the quorum key and regenerate
/// shards for the remaining nodes.
pub struct RemoveMemberRequest {
    /// The id of the node to attempt to remove
    pub node_id: NodeId,
}
