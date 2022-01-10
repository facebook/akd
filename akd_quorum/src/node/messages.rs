// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module defines the inter-node and external messages which the quorum handles that are
//! not defined within the AKD crate.

// ===========================================================
// Inter node messages
// ===========================================================
pub(crate) mod inter_node {
    use crate::comms::NodeId;

    // ****************************************
    // Verify a proof
    // ****************************************

    /// A request to verify a given append-only proof of the key directory
    /// initated by a leader process
    pub(crate) struct VerifyRequest<H: winter_crypto::Hasher> {
        pub(crate) append_only_proof: akd::proof_structs::AppendOnlyProof<H>,
        pub(crate) previous_hash: H::Digest,
        pub(crate) new_hash: H::Digest,
        pub(crate) epoch: u64,
    }
    /// Response to a verification request, which if verified, includes
    /// the encrypted shard of this quorum key and the hash which was verified,
    /// encrypted with the requesting node's public key
    pub(crate) struct VerifyResponse<H: winter_crypto::Hasher> {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
        pub(crate) verified_hash: Option<H::Digest>,
    }

    // ****************************************
    // Add a node
    // ****************************************

    /// A request to enroll a new member into the quorum. Includes
    /// the new member's public key for encrypted communications and
    /// the contact information (ip/port) for socket communcation
    pub(crate) struct AddNodeInit {
        pub(crate) public_key: Vec<u8>,
        pub(crate) contact_info: crate::comms::ContactInformation,
    }
    /// If enrollment test is successful from the edge node, this
    /// returns the quorum key shard, encrypted with the request leader's
    /// public key, which will eventually be utilized to generate
    /// new shard components and distributed to the membership
    pub(crate) struct AddNodeTestResult {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
    }
    /// Request to change the quorum membership for the additional
    /// node which may have passed muster. If successful, this will
    /// contain the new encrypted quorum key shard, encrypted with
    /// the RECIPIENT's public key and additionally the new member's
    /// information
    pub(crate) struct AddNodeResult {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
        pub(crate) new_member: crate::storage::MemberInformation,
    }

    // ****************************************
    // Remove a node
    // ****************************************

    /// Initiates a request to remove the specified node either due to
    /// non-compliance or non-functionality. Nodes cannot be removed upon
    /// generic request. Quorum membership can only GROW upon request, not
    /// shrink. Shrinkage only occurs on failure scenarios or detectable faults
    pub(crate) struct RemoveNodeInit {
        pub(crate) member_information: crate::storage::MemberInformation,
    }
    /// Each edge node will "test" the member to be removed, and if they deem
    /// it in non-compliance (or non-contactable), then they will return their
    /// portion of the quorum key shard, encrypted with the initiating user's
    /// public key to signify that they agree with a membership modification.
    pub(crate) struct RemoveNodeTestResult {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
    }
    /// If enough nodes are unable to contact the offending member or deem the
    /// node to be non-compliant with the quorum's protocols, then new shards excluding
    /// the offending node will be generated and the offending node will be removed
    /// from the quorum computations
    pub(crate) struct RemoveNodeResult {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
        pub(crate) offending_member: NodeId,
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
    pub node_id: crate::comms::NodeId,
}
