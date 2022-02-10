// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Storage definition for the quorum node non-secure storage

use crate::comms::NodeId;

use akd::errors::StorageError;
use async_trait::async_trait;

// =====================================================
// Structs w/implementations
// =====================================================

/// Represents a commitment from >= 2f+1 nodes
/// forming a "quorum" which states that at least 2f+1
/// nodes agree that the current epoch hsa passed all
/// necessary checks
pub struct QuorumCommitment<H>
where
    H: winter_crypto::Hasher,
{
    /// The epoch of this commitment
    pub current_epoch: u64,
    /// The hash from the previous commitment
    pub previous_hash: H::Digest,
    /// The hash of the current directory structure at epoch ```current_epoch```
    pub current_hash: H::Digest,
    /// The signature on the hash
    pub signature: Vec<u8>,
}

/// Represents the information about a member
/// of the quorum and all the necessary properties
/// to encrypt messages to this member (i.e. their public
/// key information)
#[derive(Clone)]
pub struct MemberInformation {
    /// The public key of the member node
    pub public_key: Vec<u8>,
    /// The id of the member node
    pub node_id: NodeId,
    /// Node contact information (ip/port/etc)
    pub contact_information: crate::comms::ContactInformation,
}

// =====================================================
// Trait definitions
// =====================================================

/// Implements a storage layer for the quorum which handles I/O
/// for the necessary stable-state functionality which is needed by the
/// operators on the quorum node
#[async_trait]
pub trait QuorumStorage<H>: Send + Sync + Clone
where
    H: winter_crypto::Hasher,
{
    /// Retrieve the other members of the quorum set
    async fn retrieve_quorum_members(&self) -> Result<Vec<MemberInformation>, StorageError>; // stored in node-private storage

    /// Retrieve a specific raft member by its id
    async fn retrieve_quorum_member(
        &self,
        node_id: NodeId,
    ) -> Result<MemberInformation, StorageError>; // stored in node-private storage

    /// Update the members of the quorum set (triggered by removal or addition of a node)
    async fn add_quorum_member(&self, node: MemberInformation) -> Result<(), StorageError>; // stored in node-private storage

    /// Remove the specific quorum member from our set of membership and decrement all node id's > this id
    async fn remove_quorum_member(&self, node_id: NodeId) -> Result<(), StorageError>; // stored in node-private storage

    /// Retrieve the latest commitment (i.e. if you're validating a epoch, the previous one)
    async fn get_latest_commitment(&self) -> Result<QuorumCommitment<H>, StorageError>; // stored in public storage

    /* Leader-only operations */

    /// Commit a new commitment to the data layer, with associated signature using
    /// the quorum key
    async fn save_commitment(&self, commitment: QuorumCommitment<H>) -> Result<(), StorageError>; // stored in public storage
}
