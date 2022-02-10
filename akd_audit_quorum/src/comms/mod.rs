// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains communication paths for various node-node and node-proxy communications

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Sender;

pub mod nonces;

// =====================================================
// Types and constants
// =====================================================

/// The id of this node in the quorum members
pub(crate) type NodeId = u64;
/// Nonce for inter-node messages to prevent replay attacks.
pub(crate) type Nonce = u128;

// =====================================================
// Structs w/implementations
// =====================================================

/// Contact information for a node
#[derive(Clone, PartialEq)]
pub struct ContactInformation {
    /// Node ip address
    pub ip_address: String,
    /// Node port
    pub port: u16,
}

impl Display for ContactInformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip_address, self.port)
    }
}
/// An encrypted inter-node message
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Which node is the intended target
    pub to: NodeId,
    /// Which node is the sender
    pub from: NodeId,
    /// Encrypted payload with embedded nonce
    pub encrypted_message_with_nonce: Vec<u8>,
}

/// Represents a communication error
#[derive(Debug, PartialEq)]
pub enum CommunicationError {
    /// An error occurred sending the message over the communication channel
    SendError(String),
    /// An error occurred receiving a message over the communication channel
    ReceiveError(String),
    /// An error occurred processing a nonce
    NonceError(NodeId, Nonce, String),
    /// A serialization error occurred
    Serialization(String),
    /// Message reception timeout
    Timeout,
}

impl From<protobuf::ProtobufError> for CommunicationError {
    fn from(pe: protobuf::ProtobufError) -> Self {
        Self::Serialization(format!("Protobuf serialization error\n{}", pe))
    }
}

/// Represents a result to an message processing
pub enum MessageProcessingResult {
    /// Result, with optional payload to send to client
    Ok(Option<EncryptedMessage>),
    /// Error occurred
    Error(String),
    /// Timeout
    Timeout,
}

/// Represents a message received by this node
pub struct MessageResult {
    /// The received message
    pub message: EncryptedMessage,
    /// Optional handling timeout
    pub timeout: Option<tokio::time::Duration>,
    /// Reply (RPC) channel
    pub reply: Sender<MessageProcessingResult>,
}

// =====================================================
// Trait definitions
// =====================================================

/// Represents a quorum member _reliable_ inter-node communication channel. It is
/// critical that these calls only fail in the face of _real_ failure, meaning that
/// they implement retries with exponential backoff internally when attempting inter-node
/// communications.
#[async_trait::async_trait]
pub trait QuorumCommunication<H>: Send + Sync + Clone
where
    H: winter_crypto::Hasher,
{
    /// A call to send a message to a quorum member node, with an optional reply
    /// when on the same tcp channel.
    async fn send_and_maybe_receive(
        &self,
        message: EncryptedMessage,
        timeout: Option<tokio::time::Duration>,
    ) -> Result<Option<EncryptedMessage>, CommunicationError>;

    /// Blocking receive call which waits for messages coming from other raft nodes
    async fn receive_inter_node(
        &self,
        timeout_ms: u64,
    ) -> Result<MessageResult, CommunicationError>;

    /// Send a message to not a node id, but the specified contact information. This is
    /// utilized for testing new potential members of the quorum and is a blocking call
    /// waiting on the result to come back
    async fn send_to_contact_info(
        &self,
        contact_info: ContactInformation,
        message: EncryptedMessage,
        timeout_ms: u64,
    ) -> Result<EncryptedMessage, CommunicationError>;

    // /// Blocking receive call which waits for messages coming from the public communication channel
    // /// (i.e. messages from admin interface or AKD)
    // async fn receive_public(
    //     &self,
    //     timeout_ms: u64,
    // ) -> Result<crate::node::messages::PublicNodeMessage<H>, CommunicationError>;
}
