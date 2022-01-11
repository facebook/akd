// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module handles the node's primary message handling logic and
//! the state of the node

use crate::comms::{EncryptedMessage, NodeId, Nonce, RpcResult};
use crate::QuorumOperationError;

use log::{debug, error, warn};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot::Sender;
use tokio::time::Duration;

mod inter_node_logic;
pub mod messages;

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

/// A decrypted inter-raft message
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Message {
    /// Which node is the intended target
    pub(crate) to: NodeId,
    /// Which node is the originator
    pub(crate) from: NodeId,
    /// Message nonce
    pub(crate) nonce: Nonce,
    /// Message payload
    pub(crate) serialized_message: Vec<u8>,
}

// *Public Structs*

/// A node in the quorum
#[derive(Debug)]
pub struct QuorumMember<H, Storage, Comms, Crypto> {
    storage: Arc<Storage>,
    comms: Arc<Comms>,
    crypto: Arc<Crypto>,
    state: Arc<NodeState>,
    _h: std::marker::PhantomData<H>,
}

unsafe impl<H, Storage, Comms, Crypto> Send for QuorumMember<H, Storage, Comms, Crypto> {}
unsafe impl<H, Storage, Comms, Crypto> Sync for QuorumMember<H, Storage, Comms, Crypto> {}

impl<H, Storage, Comms, Crypto> Clone for QuorumMember<H, Storage, Comms, Crypto>
where
    H: winter_crypto::Hasher,
    Comms: crate::comms::QuorumCommunication,
    Crypto: crate::crypto::QuorumCryptographer,
    Storage: crate::storage::QuorumStorage<H>,
{
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            comms: self.comms.clone(),
            crypto: self.crypto.clone(),
            state: self.state.clone(), // should this be a single, thread-safe instance? Is it ever mutated/updated?
            _h: std::marker::PhantomData,
        }
    }
}

impl<H, Storage, Comms, Crypto> QuorumMember<H, Storage, Comms, Crypto>
where
    H: winter_crypto::Hasher + 'static,
    Comms: crate::comms::QuorumCommunication + 'static,
    Crypto: crate::crypto::QuorumCryptographer + 'static,
    Storage: crate::storage::QuorumStorage<H> + 'static,
{
    /// Create a new Quorum Member with all the fixin's
    pub fn new(
        node_id: u64,
        config: Config,
        storage: Storage,
        crypto: Crypto,
        comms: Comms,
    ) -> Self {
        Self {
            state: Arc::new(NodeState { node_id, config }),
            storage: Arc::new(storage),
            crypto: Arc::new(crypto),
            comms: Arc::new(comms),
            _h: std::marker::PhantomData,
        }
    }

    /// Main processing loop for a node. If it ever exits, we assume the node has "died"
    /// and we immediately should panic! to fail hard & fast to issue a program restart
    pub async fn main(&self) -> Result<(), QuorumOperationError> {
        // spawn the handler futures
        let self_1 = self.clone();
        let inter_node_future = tokio::task::spawn(async move {
            let self_1_1 = self_1;
            self_1_1.inter_node_message_handler().await
        });

        let self_2 = self.clone();
        let public_future =
            tokio::task::spawn(async move { self_2.public_message_handler().await });

        // select the first task to exit of all the futures, which will fail the node & restart
        // all processes
        tokio::select! {
            inter_node_result = inter_node_future => {
                if let Err(err) = &inter_node_result {
                    error!("Inter-node message handler exited with error\n{}", err);
                } else {
                    error!("Inter-node message handler exited with no code");
                }
                inter_node_result?
            },
            public_result = public_future => {
                if let Err(err) = &public_result {
                    error!("Public message handler exited with error\n{}", err);
                } else {
                    error!("Public message handler exited with no code");
                }
                public_result?
            }
        }
    }

    async fn public_message_handler(&self) -> Result<(), QuorumOperationError> {
        loop {
            let received = self
                .comms
                .receive_public(get_this_reception_timeout_ms())
                .await;
            match received {
                Err(crate::comms::CommunicationError::Timeout) => {
                    self.handle_reception_timeout().await?
                }
                Err(other_err) => {
                    // comms channel errors should bubble up since that signifies a bigger issue that a restart may be necessary for
                    return Err(QuorumOperationError::Communication(other_err));
                }
                Ok(_received) => {
                    // TODO:
                    // // TODO: Should deserialization errors and whatnot require a node reboot?
                    // let message = self.decrypt_message(received.message).await?;
                    // self.handle_inter_node_message_helper(message, received.timeout, received.reply).await?;
                }
            }
        }
    }

    async fn inter_node_message_handler(&self) -> Result<(), QuorumOperationError> {
        loop {
            let received = self
                .comms
                .receive_inter_node(get_this_reception_timeout_ms())
                .await;
            match received {
                Err(crate::comms::CommunicationError::Timeout) => {
                    self.handle_reception_timeout().await?
                }
                Err(other_err) => {
                    // comms channel errors should bubble up since that signifies a bigger issue that a restart may be necessary for
                    return Err(QuorumOperationError::Communication(other_err));
                }
                Ok(received) => {
                    // deserialization or message handling errors should not require a node reboot.
                    match self.decrypt_message(received.message).await {
                        Ok(message) => {
                            match self
                                .handle_inter_node_message_helper(
                                    message,
                                    received.timeout,
                                    received.reply,
                                )
                                .await
                            {
                                Ok(()) => {}
                                Err(err) => {
                                    warn!("Error handling message: {}", err);
                                    // TODO: other logs or stat counters?
                                }
                            }
                        }
                        Err(err) => {
                            error!("Error decrypting node message");
                            return Err(err);
                        }
                    }
                }
            }
        }
    }

    async fn handle_reception_timeout(&self) -> Result<(), QuorumOperationError> {
        // node reception timeout
        Ok(())
    }

    async fn handle_inter_node_message(
        &self,
        message: Message,
    ) -> Result<EncryptedMessage, QuorumOperationError> {
        // reply to the source
        let to = message.from;

        // TODO: handling message & getting the reply
        let deserialized = messages::inter_node::InterNodeMessage::<H>::try_deserialize(
            message.serialized_message,
        )?;

        let reply = vec![];

        let nonce = self.comms.get_expected_nonce(to).await;
        let message = self.encrypt_message(to, reply, nonce).await?;
        // on success, we can increment the msg nonce
        self.comms.increment_nonce(to).await?;
        Ok(message)
    }

    async fn handle_inter_node_message_helper(
        &self,
        message: Message,
        timeout: Option<Duration>,
        reply: Sender<RpcResult>,
    ) -> Result<(), QuorumOperationError> {
        let job = self.handle_inter_node_message(message);
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

    async fn encrypt_message(
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
            .encrypt_message(remote_node_public_key, message, nonce)
            .await?;

        // generate reply message
        let message = EncryptedMessage {
            to,
            from: self.state.node_id,
            encrypted_message_with_nonce: enc,
        };
        Ok(message)
    }

    async fn decrypt_message(
        &self,
        message: EncryptedMessage,
    ) -> Result<Message, QuorumOperationError> {
        if message.to != self.state.node_id {
            let message = format!(
                "Received a message not intended for this node (intended: {}, actual: {})",
                message.to, self.state.node_id,
            );
            warn!("{}", message);
            return Err(crate::comms::CommunicationError::ReceiveError(message).into());
        }

        // the message should be sent utilizing OUR public key, meaning that we don't need to retrieve any
        // key information as the crypto layer should have access directly
        let (data, nonce) = self
            .crypto
            .decrypt_message(message.encrypted_message_with_nonce)
            .await?;

        // validate the nonce
        let expected_nonce = self.comms.get_expected_nonce(message.from).await;
        if nonce == expected_nonce {
            // bump the nonce by 1 to prevent the replay attack
            self.comms.increment_nonce(message.from).await?;
        } else {
            // nonce-mismatch!
            let message = format!(
                "Nonce mismatch in raft inter-messages: Node {}, Nonce: {}, Expected Nonce: {}",
                message.from, nonce, expected_nonce
            );
            warn!("{}", message);
            // TODO: add stats counter on mismatch
            return Err(crate::comms::CommunicationError::ReceiveError(message).into());
        }

        debug!("Node {} received message from {}", message.to, message.from);
        Ok(Message {
            from: message.from,
            to: message.to,
            nonce: nonce,
            serialized_message: data,
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
