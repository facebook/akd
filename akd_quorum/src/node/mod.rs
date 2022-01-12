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

use log::{debug, error, info, warn};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::sync::Arc;
use tokio::sync::oneshot::Sender;
use tokio::time::Duration;

pub mod messages;
mod node_logic;

use self::messages::{*, inter_node::*};
use self::node_logic::{NodeStatus, WorkerState, LeaderState};

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

/// The overall state of the node, including backlogged message
/// queue for unrelated messages
#[derive(Clone)]
pub(crate) struct NodeState<H>
where
    H: winter_crypto::Hasher + Clone,
{
    /// Quorum configuration
    pub(crate) config: Arc<tokio::sync::RwLock<Config>>,
    /// This node's id in the quorum
    pub(crate) node_id: NodeId,
    /// The current status of the node
    pub(crate) status: Arc<tokio::sync::RwLock<NodeStatus<H>>>,

    /// Queue of backlogged messages in reception order
    pub(crate) message_queue: Arc<tokio::sync::RwLock<Vec<NodeMessage<H>>>>,
}

unsafe impl<H> Sync for NodeState<H> where H: winter_crypto::Hasher + Clone {}
unsafe impl<H> Send for NodeState<H> where H: winter_crypto::Hasher + Clone {}

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
pub struct QuorumMember<H, Storage, Comms, Crypto>
where
    H: winter_crypto::Hasher + Clone,
{
    storage: Arc<Storage>,
    comms: Arc<Comms>,
    crypto: Arc<Crypto>,
    state: Arc<NodeState<H>>,
    _h: std::marker::PhantomData<H>,
}

unsafe impl<H, Storage, Comms, Crypto> Send for QuorumMember<H, Storage, Comms, Crypto> where
    H: winter_crypto::Hasher + Clone
{
}
unsafe impl<H, Storage, Comms, Crypto> Sync for QuorumMember<H, Storage, Comms, Crypto> where
    H: winter_crypto::Hasher + Clone
{
}

impl<H, Storage, Comms, Crypto> Clone for QuorumMember<H, Storage, Comms, Crypto>
where
    H: winter_crypto::Hasher + Clone,
    Comms: crate::comms::QuorumCommunication<H>,
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
    H: winter_crypto::Hasher + Clone + Sync + Send + 'static,
    Comms: crate::comms::QuorumCommunication<H> + 'static,
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
            state: Arc::new(NodeState {
                node_id,
                config: Arc::new(tokio::sync::RwLock::new(config)),
                status: Arc::new(tokio::sync::RwLock::new(NodeStatus::<H>::Ready)),
                message_queue: Arc::new(tokio::sync::RwLock::new(vec![])),
            }),
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
        let (sender, mut receiver) = tokio::sync::mpsc::channel(25);

        let self_1 = self.clone();
        let public_future = tokio::task::spawn(async move {
            let self_1_1 = self_1;
            self_1_1.public_message_handler(sender).await
        });

        let self_2 = self.clone();
        let inter_node_future = tokio::task::spawn(async move {
            let self_2_1 = self_2;
            self_2_1.inter_node_message_handler(&mut receiver).await
        });

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

    async fn public_message_handler(
        &self,
        sender: tokio::sync::mpsc::Sender<PublicNodeMessage<H>>,
    ) -> Result<(), QuorumOperationError> {
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
                    let _ = sender.send(_received).await.map_err(|_| {
                        QuorumOperationError::Communication(
                            crate::comms::CommunicationError::SendError(
                                "Failed to transmit public message to node processing handler"
                                    .to_string(),
                            ),
                        )
                    })?;
                }
            }
        }
    }

    async fn inter_node_message_handler(
        &self,
        receiver: &mut tokio::sync::mpsc::Receiver<PublicNodeMessage<H>>,
    ) -> Result<(), QuorumOperationError> {
        loop {
            tokio::select! {
                node_message = self.comms.receive_inter_node(get_this_reception_timeout_ms()) => {
                    match node_message {
                        Err(crate::comms::CommunicationError::Timeout) => {
                            self.handle_reception_timeout().await?
                        }
                        Err(other_err) => {
                            // comms channel errors should bubble up since that signifies a bigger issue that a restart may be necessary for
                            return Err(QuorumOperationError::Communication(other_err));
                        }
                        Ok(received) => {
                            // deserialization or message handling errors should not require a node reboot.
                            match self.decrypt_message(received.message.clone()).await {
                                Ok(message) => {
                                    // move clone of state & self, + received into the async context & spawn onto green thread
                                    // to free up message reception
                                    let self_clone = self.clone();
                                    tokio::spawn(async move {
                                        match self_clone
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
                                    });
                                }
                                Err(err) => {
                                    error!("Error decrypting node message");
                                    return Err(err);
                                }
                            }
                        }
                    }
                },
                public_message = receiver.recv() => {
                    if let Some(msg) = public_message {
                        self.handle_message(NodeMessage::<H>::Public(msg)).await?;
                    } else {
                        warn!("Message receive handler received and empty message on the public message receive port");
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
    ) -> Result<Option<EncryptedMessage>, QuorumOperationError> {
        // reply to the source
        let to = message.from;

        let deserialized = messages::inter_node::InterNodeMessage::<H>::try_deserialize(
            message.serialized_message,
        )?;
        let result = self
            .handle_message(NodeMessage::<H>::Internal(message.from, deserialized))
            .await?;

        if let Some(response_message) = result {
            let reply = response_message.serialize()?;
            let nonce = self.comms.get_expected_nonce(to).await;
            let message = self.encrypt_message(to, reply, nonce).await?;
            // on success, we can increment the msg nonce
            self.comms.increment_nonce(to).await?;
            Ok(Some(message))
        } else {
            Ok(None)
        }
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
        let node_id = self.state.node_id;
        if message.to != node_id {
            let message = format!(
                "Received a message not intended for this node (intended: {}, actual: {})",
                message.to, node_id,
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

    async fn handle_message(
        &self,
        message: NodeMessage<H>,
    ) -> Result<Option<InterNodeMessage<H>>, QuorumOperationError> {
        let guard = self.state.status.read().await;
        match &(*guard) {
            NodeStatus::<H>::Ready => {
                match message {
                    NodeMessage::<H>::Public(public_message) => {
                        // all public messages are accepted when not currently in quorum operation
                        // This will move the node to LEADER status
                        match public_message {
                            PublicNodeMessage::Verify(verification) => {
                                self.public_verify_impl(verification).await?;
                            },
                            PublicNodeMessage::Enroll(enroll) => {
                                self.public_enroll_impl(enroll).await?;
                            },
                            PublicNodeMessage::Remove(remove) => {
                                self.public_remove_impl(remove).await?;
                            }
                        }
                    }
                    NodeMessage::<H>::Internal(from, internal_message) => {
                        match internal_message {
                            InterNodeMessage::VerifyRequest(verify_request) => {
                                // node will become worker
                                let result = self.verify_impl(from, verify_request).await?;
                                return Ok(Some(InterNodeMessage::<H>::VerifyResponse(result)));
                            }
                            InterNodeMessage::AddNodeInit(add_node_inint) => {
                                // node will become worker
                            }
                            InterNodeMessage::RemoveNodeInit(remove_node_init) => {
                                // node will become worker
                            }
                            other => {
                                warn!(
                                    "Received out-of-sync message on node {}\n{:?}",
                                    self.state.node_id, other
                                );
                            }
                        }
                    }
                }
            }
            NodeStatus::<H>::Leading(l_state) => {}
            NodeStatus::<H>::Following(w_state) => {}
        }
        // default reply is... no reply :)
        Ok(None)
    }

    async fn mutate_state(&self, new_state: NodeStatus<H>) {
        let mut guard = self.state.status.write().await;
        *guard = new_state;
    }

    async fn public_verify_impl(&self, verify_request: VerifyChangesRequest<H>) -> Result<(), QuorumOperationError> {
        let vf = VerifyRequest::<H> {
            new_hash: verify_request.new_hash,
            append_only_proof: verify_request.append_only_proof,
            epoch: verify_request.epoch
        };
        let node_ids = 0u64..(self.state.config.read().await.group_size as u64);
        let mut votes = HashMap::new();
        for id in node_ids {
            votes.insert(id, None);
        }
        self.mutate_state(NodeStatus::<H>::Leading(LeaderState::<H>::ProcessingVerification(vf.clone(), votes.clone()))).await;

        // TODO: distribute the "votes" to the quorum

        Ok(())
    }

    async fn public_enroll_impl(&self, enrollment_request: EnrollMemberRequest) -> Result<(), QuorumOperationError> {

        Ok(())
    }

    async fn public_remove_impl(&self, removal_request: RemoveMemberRequest) -> Result<(), QuorumOperationError> {

        Ok(())
    }

    async fn verify_impl(&self, from: NodeId, verify_request: VerifyRequest<H>) -> Result<VerifyResponse<H>, QuorumOperationError> {
        {
            self.mutate_state(NodeStatus::<H>::Following(WorkerState::<H>::Verifying(
                from,
                verify_request.clone(),
            )))
            .await;
            if let Ok(previous_commitment) = self.storage.get_latest_commitment().await {
                if let Err(error) = akd::auditor::verify_append_only(
                    verify_request.append_only_proof,
                    previous_commitment.current_hash,
                    verify_request.new_hash,
                )
                .await
                {
                    info!("Verification of proof for epoch {} did not verify with error {}", verify_request.epoch, error);
                    self.mutate_state(NodeStatus::<H>::Ready).await;
                    Ok(VerifyResponse::<H> {
                        verified_hash: None,
                        encrypted_quorum_key_shard: None,
                    })
                } else {
                    // OK, return our shard
                    let shard = self.crypto.retrieve_qk_shard(from).await?;
                    self.mutate_state(NodeStatus::<H>::Ready).await;
                    Ok(VerifyResponse::<H> {
                        verified_hash: Some(verify_request.new_hash),
                        encrypted_quorum_key_shard: Some(shard.payload),
                    })
                }
            } else {
                info!("Failed to retrieve the last commitment from storage");
                self.mutate_state(NodeStatus::<H>::Ready).await;
                Ok(VerifyResponse::<H> {
                    verified_hash: None,
                    encrypted_quorum_key_shard: None,
                })
            }
        }
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
