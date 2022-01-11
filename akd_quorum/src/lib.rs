// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This crate implements the membership logic for a participant of a the witness pool which verifies
//! the append-only nature of the key directory. This is to be deployed in a pool nature, and will inter-communicate
//! between nodes in order to pass shard logic, manage enrollment & de-enrollment, and sign proof + emit it to stable storage.
//!
//! ⚠️ **Warning**: This implementation has not been audited and is not ready for use in a real system. Use at your own risk!
//! # Overview
//! To prevent a split-view attack the root hash of every epoch needs to have a signature signed by a private key which cannot be leaked from the quorum
//! (via shared-secret methodology). This quorum participates to independently validate the append-only proof of the key directory and each participant
//! provides their partial shard of the quorum signing key and when enough participants agree, the changes are signed off on and stored in persistent storage.
//!
//! That way a proof only needs to give the root hash, and the signature on it to ascertain the quorum has agreed on the changes, and the AKD
//! (or any other 3rd party) cannot generate its own signatures.
//!
//! Eventually these auditors can be participants from external entities who can participate in the quorum vote.
//!
//! ## Requirements
//!
//! 1. The Quorum Key (QK) is long-lived and securely managed such that individual (or a few) participants cannot generate their own signatures and invalidate the trust of the system
//! 2. The quorum participants can evolve over time (i.e. removal in the face of failures, and additions for future collaborative growth or upgrades).
//! 3. Communication channels are secure, such that 3rd parties cannot sniff the key shares over the wire and compromise the QK.
//! 4. The public key of the QK is publicly distributed such that it's easy to client-side validate the validity of the epochs without additional I/O operations to a potentially malicious acting key directory.
//!
//! # Design overview:
//!
//! A Quorum Key is generated at the beginning of the life of the quorum, and the private key is broken into "shards" via [Shamir secret sharing](https://github.com/dsprenkels/sss-rs).
//! These shards are transmitted to the quorum participants who hold them in secure storage. The shards are generated with the following properties
//!
//! 1. There are 3 _f_ + 1 nodes in the quorum
//! 2. 2 _f_ + 1 nodes need to agree to reconstruct the signing key (quorum key)
//! 3. The public key is given publicly to every client which will need to verify the signature
//!
//! ## Communcation with the quorum
//!
//! The collection of nodes in this quorum receive commands from an external 3rd party (key directory epoch notification or admin interface for example).
//! The messages they can receive are the following
//!
//! 1. New epoch publication - The AKD has published a new epoch and the quorum should validate the changes and generate a signature
//! 2. Quorum member enrollment - The quorum should attempt to add the new member to the set. A series of independent tests will be
//! performed against the new member and if they pass, a new shard-set will be generated and the node enrolled
//! 3. Quorum member removal - The quorum has a member which should be removed. If 2 _f_ + 1 nodes agree, the Quorum Key is reconstructed and new shards are generated and
//! distributed to the remaining membership.
//!
//! For any of these messages, whichever node receives the request is denoted as the leader. We do not need the full [RAFT](https://en.wikipedia.org/wiki/Raft_(algorithm))
//! protocol, since we have no need for a persistent leader and the nodes are effectively stateless in between operations.
//! The temporary request leader is responsible for communicating with the other quorum members and gathering
//! their votes, reconstructing the shards, and either signing the commitment or enrolling the new member (re-generating shards and transmitting them).
//!
//! ## Inter-node messages:
//!
//! 1. Vote - args: (proof and hash information)
//!   a. Reply: Success(shard) or Failure (errors)
//! 2. Generate enrollment test - args: (member information, public key, etc)
//!   a. Reply: A "test" of enrollment for a new quorum member, with the result temporarily stored in the local machine
//! 3. Process enrollment test result - args: (member reply to specific proof)
//!   a. Reply: If test successful, return the shard to the "leader". If not, return failure and don't disclose the shard
//! 4. Remove member - args: (node_id)
//!   a. Reply: Agree(shard) or Disagree (error)
//! 5. Update stored shard - args: (new_shard, commitment_over_shard_signed_by_quorum_key)
//!   a. We need to provide a commitment, so the membership doesn't replace shards with invalid information which is potentially a different quorum key and
//!   corrupting the quorum
//!
//! ## Retrieval of the latest commitment
//!
//! Since the public key is available to anyone who cares, external parties can read directly from the storage layer to minimize I/O to the quorum, as they
//! will likely be resource constrained with validating the commitments between epochs and processing membership changes.
//!
//! NOTE: If the storage layer is mutated directly, then the quorum will start failing commitments and signatures will not match so the system fault will be detectable.

#![warn(missing_docs)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::fmt;

pub mod comms;
pub mod crypto;
pub mod node;
pub mod storage;

pub(crate) mod proto;

#[derive(Debug, PartialEq)]
/// A failure occurred encrypting or decrypting a message
pub enum QuorumOperationError {
    /// An encryption error occurred
    Encryption(String),
    /// A storage error occurred
    Storage(akd::errors::StorageError),
    /// A sharding error occurred (generation or reconstruction)
    Sharding(String),
    /// A communication error occurred
    Communication(crate::comms::CommunicationError),

    /// An untyped error has occurred
    Unknown(String),
}

impl std::fmt::Display for QuorumOperationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use QuorumOperationError::*;
        match self {
            Encryption(err) => write!(f, "Encryption error ({})", err),
            Storage(err) => write!(f, "Storage error ({:?})", err),
            Sharding(err) => write!(f, "Sharding error ({})", err),
            Communication(comm_err) => write!(f, "Communication error ({:?})", comm_err),
            Unknown(msg) => write!(f, "Unknown error ({})", msg),
        }
    }
}

impl From<akd::errors::StorageError> for QuorumOperationError {
    fn from(err: akd::errors::StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<shamirsecretsharing::SSSError> for QuorumOperationError {
    fn from(err: shamirsecretsharing::SSSError) -> Self {
        QuorumOperationError::Sharding(format!("Shamir Sharding Error \"{}\"", err))
    }
}

impl From<crate::comms::CommunicationError> for QuorumOperationError {
    fn from(err: crate::comms::CommunicationError) -> Self {
        QuorumOperationError::Communication(err)
    }
}

impl From<String> for QuorumOperationError {
    fn from(err: String) -> Self {
        QuorumOperationError::Unknown(err)
    }
}

impl From<tokio::task::JoinError> for QuorumOperationError {
    fn from(_err: tokio::task::JoinError) -> Self {
        QuorumOperationError::Unknown("Tokio task join error".to_string())
    }
}
