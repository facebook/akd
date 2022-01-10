// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains communication paths for various node-node and node-proxy communications

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Sender;

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
pub struct ContactInformation {
    /// Node ip address
    pub(crate) ip_address: String,
    /// Node port
    pub(crate) port: u16,
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
}

/// Represents a result to an RPC request
pub enum RpcResult {
    /// Result
    Ok(EncryptedMessage),
    /// Error occurred
    Error(String),
    /// Timeout
    Timeout,
}

/// Represents a message received by this node
pub enum MessageResult {
    /// A message was not received within the handling window
    Timeout,
    /// A fire and forget message, i.e. no reply necessary
    FireAndForget(EncryptedMessage),
    /// A RPC request, awaiting a reply
    Rpc(
        EncryptedMessage,
        Option<tokio::time::Duration>,
        Sender<RpcResult>,
    ),
}

// =====================================================
// Trait definitions
// =====================================================

/// Represents a quorum member inter-node communication channel
#[async_trait::async_trait]
pub trait QuorumCommunication {
    /// Retrieve the next nonce for the specified node id. If the requested node
    /// has no nonce, a random nonce will be returned which will cause a mis-match with the
    /// message which it is being attempted for. This is fine since raft is robust to message
    /// failures.
    async fn get_expected_nonce(&self, node_id: NodeId) -> Nonce;

    /// Increment the nonce for a given recepient, so the message cannot be replayed
    async fn increment_nonce(&self, node_id: NodeId) -> Result<(), CommunicationError>;

    /// Send a message to another node (routing information is contained in the message)
    /// [fire and forget]
    async fn send_message(&self, message: EncryptedMessage) -> Result<(), CommunicationError>;

    /// A remote-procedure-call to another node in the raft. I.e. send & receive reply
    async fn rpc(
        &self,
        message: EncryptedMessage,
        timeout: Option<tokio::time::Duration>,
    ) -> Result<EncryptedMessage, CommunicationError>;

    /// Blocking receive call which waits for messages coming from other raft nodes
    async fn receive(&self, timeout_ms: u64) -> Result<MessageResult, CommunicationError>;
}
