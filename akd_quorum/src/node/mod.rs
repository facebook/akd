// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module handles the node's primary message handling logic and
//! the state of the node

use crate::comms::{EncryptedMessage, MessageResult, NodeId, Nonce, RpcResult};
use crate::QuorumOperationError;

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Sender;
use tokio::time::Duration;

// =====================================================
// Typedefs and constants
// =====================================================

/// The size of the membership (presently)
pub(crate) type GroupSize = u8;

const NODE_MESSAGE_RECEPTION_TIMEOUT_MS: u64 = 1000;
static THIS_NODE_MESSAGE_RECEPTION_TIMEOUT_MS: OnceCell<u64> = OnceCell::new();
fn get_this_reception_timeout_ms() -> u64 {
    *THIS_NODE_MESSAGE_RECEPTION_TIMEOUT_MS.get_or_init(|| {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        // something uniform in 1s -> 1.2s
        NODE_MESSAGE_RECEPTION_TIMEOUT_MS + rng.gen_range(0..200)
    })
}

// =====================================================
// Structs w/implementations
// =====================================================

// *Crate-only structs*

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// The quorum configuration
pub struct Config {
    /// The group size of the quorum membership
    pub(crate) group_size: GroupSize,
}

impl Config {
    /// A disabled pool (testing)
    pub fn disabled() -> Self {
        Self { group_size: 0 }
    }

    /// Is this quorum disabled?
    pub fn is_disabled(&self) -> bool {
        self.group_size == 0
    }
}

/// Regular state for the node
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct NodeState {
    /// Quorum configuration
    pub(crate) config: Config,
    /// This node's id in the quorum
    pub(crate) node_id: NodeId,
}

// *Public Structs*

/// A decrypted inter-raft message
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Which node is the intended target
    pub to: NodeId,
    /// Which node is the originator
    pub from: NodeId,
    /// Message nonce
    pub nonce: Nonce,
    /// Message payload
    pub serialized_message: Vec<u8>,
}

/// A node in the quorum
#[derive(Debug)]
pub struct QuorumMember<QuorumMemberInformation, H, Storage, Comms, Crypto> {
    storage: Storage,
    comms: Comms,
    crypto: Crypto,
    state: NodeState,
    _h: std::marker::PhantomData<H>,
    _qmi: std::marker::PhantomData<QuorumMemberInformation>,
}

impl<QuorumMemberInformation, H, Storage, Comms, Crypto>
    QuorumMember<QuorumMemberInformation, H, Storage, Comms, Crypto>
where
    QuorumMemberInformation: Sized,
    H: winter_crypto::Hasher,
    Comms: crate::comms::QuorumCommunication,
    Crypto: crate::crypto::QuorumCryptographer,
    Storage: crate::storage::QuorumStorage<H>,
{
    /// Create a new Quorum Member with all the fixin's
    pub fn new(node_id: u64, config: Config, storage: Storage, crypto: Crypto, comms: Comms) -> Self {
        Self {
            state: NodeState {
                node_id,
                config,
            },
            storage,
            crypto,
            comms,
            _h: std::marker::PhantomData,
            _qmi: std::marker::PhantomData,
        }
    }

    /// Main processing loop for a node. If it ever exits, we assume the node has "died"
    /// and we immediately should panic! to fail hard & fast to issue a program restart
    pub async fn main(&self) -> Result<(), QuorumOperationError> {
        loop {
            let received = self.comms.receive(get_this_reception_timeout_ms()).await?;
            match received {
                MessageResult::FireAndForget(emessage) => {
                    let message = self.decrypt_message(emessage).await?;
                    self.handle_fire_and_forget(message).await?;
                }
                MessageResult::Rpc(emessage, timeout, reply) => {
                    let message = self.decrypt_message(emessage).await?;
                    self.handle_rpc(message, timeout, reply).await?;
                }
                MessageResult::Timeout => {
                    self.handle_timeout().await?;
                }
            }
        }
    }

    async fn handle_fire_and_forget(&self, _message: Message) -> Result<(), QuorumOperationError> {
        // one-off messages
        Ok(())
    }

    async fn handle_timeout(&self) -> Result<(), QuorumOperationError> {
        // node reception timeout
        Ok(())
    }

    async fn build_enc_message(
        &self,
        to: NodeId,
        message: Vec<u8>,
        nonce: u128,
    ) -> Result<EncryptedMessage, QuorumOperationError> {
        // get remote node contact information
        let remote_node_info = self.storage.retrieve_quorum_member(to).await?;
        let remote_node_public_key: Vec<u8> = remote_node_info.public_key;

        // encrypt the data
        let enc = self
            .crypto
            .encrypt_material(remote_node_public_key, message, nonce)
            .await?;

        // generate reply message
        let message = EncryptedMessage {
            to,
            from: self.state.node_id,
            encrypted_message_with_nonce: enc,
        };
        Ok(message)
    }

    async fn rpc_inner_job(
        &self,
        message: Message,
    ) -> Result<EncryptedMessage, QuorumOperationError> {
        // reply to the source
        let to = message.from;

        // TODO: handling message & getting the reply
        let reply = vec![];

        let nonce = self.comms.get_expected_nonce(to).await;
        let message = self.build_enc_message(to, reply, nonce).await?;
        // on success, we can increment the msg nonce
        self.comms.increment_nonce(to).await?;
        Ok(message)
    }

    async fn handle_rpc(
        &self,
        message: Message,
        timeout: Option<Duration>,
        reply: Sender<RpcResult>,
    ) -> Result<(), QuorumOperationError> {
        let job = self.rpc_inner_job(message);
        let result = match timeout {
            Some(tic_toc) => match tokio::time::timeout(tic_toc, job).await {
                Err(_) => RpcResult::Timeout,
                Ok(Ok(result)) => RpcResult::Ok(result),
                Ok(Err(r_err)) => RpcResult::Error(r_err.to_string()),
            },
            None => match job.await {
                Ok(result) => RpcResult::Ok(result),
                Err(r_err) => RpcResult::Error(r_err.to_string()),
            },
        };
        reply.send(result).map_err(|_| {
            QuorumOperationError::Communication(crate::comms::CommunicationError::SendError(
                "Failed to send reply in RPC call (likely channel closed)".to_string(),
            ))
        })?;
        Ok(())
    }

    async fn decrypt_message(
        &self,
        message: EncryptedMessage,
    ) -> Result<Message, QuorumOperationError> {
        if message.to != self.state.node_id {
            return Err(crate::comms::CommunicationError::ReceiveError(format!(
                "Received a message not intended for this node (intended: {}, actual: {})",
                message.to, self.state.node_id,
            ))
            .into());
        }

        // the message should be sent utilizing OUR public key, meaning that we don't need to retrieve any
        // key information as the crypto layer should have access directly
        let msg = self
            .crypto
            .decrypt_material(message.encrypted_message_with_nonce)
            .await?;

        // validate the nonce
        let expected_nonce = self.comms.get_expected_nonce(message.from).await;
        if msg.1 == expected_nonce {
            // bump the nonce by 1 to prevent the replay attack
            self.comms.increment_nonce(message.from).await?;
        } else {
            // nonce-mismatch!
            // TODO: log nonce mis-match
            // TODO: add stats counter on mismatch
            return Err(crate::comms::CommunicationError::ReceiveError(format!(
                "Nonce mismatch in raft inter-messages: Node {}, Nonce: {}, Expected Nonce: {}",
                message.from, msg.1, expected_nonce
            ))
            .into());
        }

        Ok(Message {
            from: message.from,
            to: message.to,
            nonce: msg.1,
            serialized_message: msg.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn config_disabled() {
        let config = Config::disabled();
        assert!(config.is_disabled());
    }
}
