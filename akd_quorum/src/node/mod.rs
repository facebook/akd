// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module handles the node's primary message handling logic and
//! the state of the node

// TODO:
// 1. Handle message processing failure state transition. Do we just revert to "Ready"?
//    We probably need some kind of graceful failure transitions in the event we can't go from a -> b
// 2. Generation of AKD test's
// 3. Mutation of the quorum via setting new shards & modifying the current config

use crate::comms::{EncryptedMessage, NodeId, Nonce, RpcResult};
use crate::QuorumOperationError;

use itertools::Itertools;
use log::{debug, error, info, warn};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::oneshot::Sender;
use tokio::time::Duration;

pub mod messages;
mod node_states;

use self::messages::{inter_node::*, *};
use self::node_states::{LeaderState, NodeStatus, WorkerState};

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

const DISTRIBUTED_PROCESSING_TIMEOUT_SEC: u64 = 60 * 10;

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

    pub(crate) nonce_manager: crate::comms::nonces::NonceManager,
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
                nonce_manager: crate::comms::nonces::NonceManager::new(),
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
            let nonce = self.state.nonce_manager.get_next_outgoing_nonce(to).await;
            let message = self.encrypt_message(to, reply, nonce).await?;
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
        match self
            .state
            .nonce_manager
            .validate_nonce(message.from, nonce)
            .await
        {
            Ok(()) => {}
            Err(crate::comms::CommunicationError::NonceError(a, b, msg)) => {
                warn!("{}", msg);
                return Err(crate::comms::CommunicationError::NonceError(a, b, msg).into());
            }
            Err(other) => return Err(other.into()),
        }

        debug!("Node {} received message from {}", message.to, message.from);
        Ok(Message {
            from: message.from,
            to: message.to,
            nonce: nonce,
            serialized_message: data,
        })
    }

    /// Generate a test for a new node
    async fn generate_test(&self) -> Result<(bool, NewNodeTest<H>), QuorumOperationError> {
        // TODO: we need to generate a test which is randomly-ish generated and has the previous properties
        // 1. Hashes to the same previous_hash as what's currently in the commitment repository
        // 2. Has a properly constructed proof structure with unchanged nodes and inserted nodes (may request it from akd tier?)
        // 3. Will result in either a "true" result or "false" result, with a random outcome so it can't be predicted by other nodes.

        // TODO: Add a timer to randomly "test" nodes (say every 10-ish epochs) which will keep them "true" to form

        Ok((
            false,
            NewNodeTest {
                new_hash: H::hash(&[0u8; 32]),
                previous_hash: H::hash(&[0u8; 32]),
                requesters_public_key: self.crypto.retrieve_public_key().await?,
                test_proof: akd::proof_structs::AppendOnlyProof::<H> {
                    unchanged_nodes: vec![],
                    inserted: vec![],
                },
            },
        ))
    }

    async fn handle_message(
        &self,
        message: NodeMessage<H>,
    ) -> Result<Option<InterNodeMessage<H>>, QuorumOperationError> {
        match message {
            NodeMessage::Public(public_message) => {
                // all public messages are accepted when not currently in quorum operation
                // This will move the node to LEADER status
                match public_message {
                    PublicNodeMessage::Verify(verification) => {
                        self.public_verify_impl(verification).await?;
                    }
                    PublicNodeMessage::Enroll(enroll) => {
                        self.public_enroll_impl(enroll).await?;
                    }
                    PublicNodeMessage::Remove(remove) => {
                        self.public_remove_impl(remove).await?;
                    }
                }
            }
            NodeMessage::Internal(from, internal_message) => match internal_message {
                InterNodeMessage::VerifyRequest(verify_request) => {
                    if let Some(result) = self.verify_impl(from, verify_request).await? {
                        return Ok(Some(InterNodeMessage::VerifyResponse(result)));
                    }
                }
                InterNodeMessage::VerifyResponse(verify_response) => {
                    self.verify_response_impl(from, verify_response).await?;
                }
                InterNodeMessage::AddNodeInit(add_node_init) => {
                    if let Some(result) = self.add_node_impl(from, add_node_init).await? {
                        return Ok(Some(InterNodeMessage::AddNodeTestResult(result)));
                    }
                }
                InterNodeMessage::AddNodeTestResult(test_result) => {}
                InterNodeMessage::AddNodeResult(result) => {}
                InterNodeMessage::NewNodeTest(test) => {}
                InterNodeMessage::NewNodeTestResult(test_result) => {}
                InterNodeMessage::RemoveNodeInit(remove_node_init) => {}
                InterNodeMessage::RemoveNodeTestResult(test_result) => {}
                InterNodeMessage::RemoveNodeResult(result) => {}
                InterNodeMessage::InterNodeAck(ack) => {}
            },
        }
        // default reply is... no reply :)
        Ok(None)
    }

    async fn mutate_state(&self, new_state: NodeStatus<H>) {
        let mut guard = self.state.status.write().await;
        *guard = new_state;
    }

    async fn get_state(&self) -> NodeStatus<H> {
        let guard = self.state.status.read().await;
        guard.clone()
    }

    async fn public_verify_impl(
        &self,
        verify_request: VerifyChangesRequest<H>,
    ) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(_) | NodeStatus::Following(_) => {
                // defer, can only handle 1 public message at a time
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Public(PublicNodeMessage::Verify(
                        verify_request,
                    )));
                info!("Received a public verification request, but we're already processing a request");
            }
            NodeStatus::Ready => {
                // become the request leader, and perform the operation
                let internal_request = VerifyRequest::<H> {
                    new_hash: verify_request.new_hash,
                    append_only_proof: verify_request.append_only_proof,
                    epoch: verify_request.epoch,
                };

                let node_ids = 0u64..(self.state.config.read().await.group_size as u64);
                // set the state to "pending verification" waiting on the resultant votes
                self.mutate_state(NodeStatus::<H>::Leading(
                    LeaderState::<H>::ProcessingVerification(
                        tokio::time::Instant::now(),
                        internal_request.clone(),
                        HashMap::new(),
                    ),
                ))
                .await;

                // Perform our own portion of the verification process (i.e. our vote, and possibly our shard of the key)
                let self_clone = self.clone();
                let request_clone = internal_request.clone();
                let self_handle = tokio::task::spawn(async move {
                    let node_id = self_clone.state.node_id.clone();
                    let verification = self_clone.verify_impl(node_id, request_clone).await;
                    let mut status = self_clone.state.status.write().await;
                    if let NodeStatus::Leading(LeaderState::ProcessingVerification(
                        start_time,
                        the_request,
                        the_responses,
                    )) = &(*status)
                    {
                        match verification {
                            Ok(option_verification_result) => {
                                let mut hm = the_responses.clone();
                                hm.insert(node_id, option_verification_result);

                                match self_clone
                                    .try_generate_sig(
                                        start_time.clone(),
                                        the_request.clone(),
                                        hm.clone(),
                                    )
                                    .await
                                {
                                    Ok(true) => {
                                        // commitment cycle has completed, go to ready state
                                        self_clone.mutate_state(NodeStatus::Ready).await;
                                    }
                                    Ok(false) => {
                                        // else keep processing for more data collection, fail should bubble-up
                                        *status = NodeStatus::Leading(
                                            LeaderState::ProcessingVerification(
                                                tokio::time::Instant::now(),
                                                the_request.clone(),
                                                hm,
                                            ),
                                        );
                                    }
                                    Err(err) => {
                                        warn!("The leader failed to generate a commitment after gathering enough votes. Trying again later\nError: {}", err);
                                        // else keep processing for more data collection, fail should bubble-up
                                        *status = NodeStatus::Leading(
                                            LeaderState::ProcessingVerification(
                                                tokio::time::Instant::now(),
                                                the_request.clone(),
                                                hm,
                                            ),
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                warn!("The leader failed to verify the append-only nature of the changes. Reporting as verification failed\nError: {}", error);
                                let mut hm = the_responses.clone();
                                hm.insert(node_id, None);
                                *status = NodeStatus::Leading(LeaderState::ProcessingVerification(
                                    tokio::time::Instant::now(),
                                    the_request.clone(),
                                    hm,
                                ));
                            }
                        }
                    }
                });

                for id in node_ids {
                    // send message to node
                    if id == self.state.node_id {
                        // self contribution is needed is being computed in the background
                    } else {
                        let msg = InterNodeMessage::<H>::VerifyRequest(internal_request.clone())
                            .serialize()?;
                        let nonce = self.state.nonce_manager.get_next_outgoing_nonce(id).await;
                        let e_msg = self.encrypt_message(id, msg, nonce).await?;
                        self.comms.send_message(e_msg).await?;
                    }
                }

                // wait on the self-review of the changes
                self_handle.await?;
            }
        }

        Ok(())
    }

    async fn public_enroll_impl(
        &self,
        enrollment_request: EnrollMemberRequest,
    ) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(_) | NodeStatus::Following(_) => {
                // defer, can only handle 1 public message at a time
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Public(PublicNodeMessage::Enroll(
                        enrollment_request,
                    )));
                info!(
                    "Received a public enrollment request, but we're already processing a request"
                );
            }
            NodeStatus::Ready => {
                let internal_request = AddNodeInit {
                    public_key: enrollment_request.public_key,
                    contact_info: enrollment_request.contact_information,
                };

                let node_ids = 0u64..(self.state.config.read().await.group_size as u64);
                for id in node_ids {
                    // send message to node
                    let msg =
                        InterNodeMessage::<H>::AddNodeInit(internal_request.clone()).serialize()?;
                    let nonce = self.state.nonce_manager.get_next_outgoing_nonce(id).await;
                    let e_msg = self.encrypt_message(id, msg, nonce).await?;
                    self.comms.send_message(e_msg).await?;
                }
                // send the state to "pending verification" waiting on the votes
                self.mutate_state(NodeStatus::<H>::Leading(
                    LeaderState::<H>::ProcessingAddition(
                        tokio::time::Instant::now(),
                        internal_request.clone(),
                        HashMap::new(),
                    ),
                ))
                .await;
            }
        }

        Ok(())
    }

    async fn public_remove_impl(
        &self,
        removal_request: RemoveMemberRequest,
    ) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(_) | NodeStatus::Following(_) => {
                // defer, can only handle 1 public message at a time
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Public(PublicNodeMessage::Remove(
                        removal_request,
                    )));
                info!("Received a public removal request, but we're already processing a request");
            }
            NodeStatus::Ready => {
                let internal_request = RemoveNodeInit {
                    node_id: removal_request.node_id,
                };

                let node_ids = 0u64..(self.state.config.read().await.group_size as u64);
                for id in node_ids {
                    // send message to node
                    let msg = InterNodeMessage::<H>::RemoveNodeInit(internal_request.clone())
                        .serialize()?;
                    let nonce = self.state.nonce_manager.get_next_outgoing_nonce(id).await;
                    let e_msg = self.encrypt_message(id, msg, nonce).await?;
                    self.comms.send_message(e_msg).await?;
                }
                // send the state to "pending verification" waiting on the votes
                self.mutate_state(NodeStatus::<H>::Leading(
                    LeaderState::<H>::ProcessingRemoval(
                        tokio::time::Instant::now(),
                        internal_request.clone(),
                        HashMap::new(),
                    ),
                ))
                .await;
            }
        }

        Ok(())
    }

    async fn add_node_impl(
        &self,
        from: NodeId,
        add_node_init: AddNodeInit,
    ) -> Result<Option<AddNodeTestResult>, QuorumOperationError> {
        let state = self.get_state().await;
        let should_mutate_state = if let NodeStatus::Ready = &state {
            true
        } else {
            false
        };
        match self.get_state().await {
            NodeStatus::Ready | NodeStatus::Leading(LeaderState::ProcessingAddition(_, _, _))
                if from == self.state.node_id =>
            {
                // OK
                debug!(
                    "Node {} is testing new candidate node: {}",
                    from, add_node_init.contact_info
                );
                let (should_pass, test) = self.generate_test().await?;
                let add_node_init_copy = add_node_init.clone();

                if should_mutate_state {
                    self.mutate_state(NodeStatus::Following(WorkerState::TestingAddMember(
                        from,
                        add_node_init.clone(),
                        should_pass,
                    )))
                    .await;
                }

                // generate the plaintext msg
                let msg = InterNodeMessage::NewNodeTest(test).serialize()?;
                // encrypt the msg, nonce is going to be 0
                let e_msg = self
                    .crypto
                    .encrypt_message(add_node_init.public_key, msg, 0)
                    .await?;
                // formulate record
                let e_msg = EncryptedMessage {
                    to: u64::MAX,
                    from: self.state.node_id,
                    encrypted_message_with_nonce: e_msg,
                };
                // send & wait for the reply. 30s timeout as the test should be small and practical
                let result = self
                    .comms
                    .send_to_contact_info(
                        add_node_init.contact_info.clone(),
                        e_msg,
                        30u64 * 1000u64,
                    )
                    .await?;
                // decode the reply
                let msg = self.decrypt_message(result).await?;
                let deserialized = InterNodeMessage::<H>::try_deserialize(msg.serialized_message)?;
                // check the reply result
                if let InterNodeMessage::NewNodeTestResult(test_result) = deserialized {
                    if test_result.test_pass == should_pass {
                        // Passed test, give our shard to the leader
                        if should_mutate_state {
                            self.mutate_state(NodeStatus::Following(
                                WorkerState::WaitingOnMemberAddResult(add_node_init_copy),
                            ))
                            .await;
                        }
                        return Ok(Some(AddNodeTestResult {
                            contact_info: add_node_init.contact_info,
                            encrypted_quorum_key_shard: Some(
                                self.crypto.retrieve_qk_shard(from).await?.payload,
                            ),
                        }));
                    } else {
                        info!("Test node {} failed to correctly compute the test proof. Node {} disapproves of adding candidate to the quorum", add_node_init.contact_info, self.state.node_id);
                    }
                } else {
                    info!("Test node {} returned an incorrect message. Node {} disapproves of adding candidate to the quorum", add_node_init.contact_info, self.state.node_id);
                }

                // test failure
                if should_mutate_state {
                    self.mutate_state(NodeStatus::Following(
                        WorkerState::WaitingOnMemberAddResult(add_node_init_copy),
                    ))
                    .await;
                }
                return Ok(Some(AddNodeTestResult {
                    contact_info: add_node_init.contact_info,
                    encrypted_quorum_key_shard: None,
                }));
            }
            _ => {
                info!("Received a inter-node request to add a node, but the node is busy in an operation");
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Internal(
                        from,
                        InterNodeMessage::AddNodeInit(add_node_init),
                    ));
            }
        }
        Ok(None)
    }

    async fn verify_impl(
        &self,
        from: NodeId,
        verify_request: VerifyRequest<H>,
    ) -> Result<Option<VerifyResponse<H>>, QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Ready => {
                // OK
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
                        info!(
                            "Verification of proof for epoch {} did not verify with error {}",
                            verify_request.epoch, error
                        );
                        self.mutate_state(NodeStatus::<H>::Ready).await;
                        Ok(Some(VerifyResponse::<H> {
                            verified_hash: verify_request.new_hash,
                            encrypted_quorum_key_shard: None,
                        }))
                    } else {
                        // OK, return our shard
                        let shard = self.crypto.retrieve_qk_shard(from).await?;
                        self.mutate_state(NodeStatus::<H>::Ready).await;
                        Ok(Some(VerifyResponse::<H> {
                            verified_hash: verify_request.new_hash,
                            encrypted_quorum_key_shard: Some(shard.payload),
                        }))
                    }
                } else {
                    info!("Failed to retrieve the last commitment from storage");
                    self.mutate_state(NodeStatus::<H>::Ready).await;
                    Ok(Some(VerifyResponse::<H> {
                        verified_hash: verify_request.new_hash,
                        encrypted_quorum_key_shard: None,
                    }))
                }
            }
            NodeStatus::Following(_) | NodeStatus::Leading(_) => {
                info!("Received a inter-node request to verify a proof, but the node is busy in an operation");
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Internal(
                        from,
                        InterNodeMessage::VerifyRequest(verify_request),
                    ));
                Ok(None)
            }
        }
    }

    async fn verify_response_impl(
        &self,
        from: NodeId,
        verify_response: VerifyResponse<H>,
    ) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(LeaderState::ProcessingVerification(
                start_time,
                request,
                response_map,
            )) => {
                if verify_response.verified_hash == request.new_hash {
                    // this verification is related to our verification request, update the state
                    let mut new_map = response_map.clone();
                    new_map.insert(from, Some(verify_response));

                    if self
                        .try_generate_sig(start_time.clone(), request.clone(), new_map)
                        .await?
                    {
                        // commitment cycle has completed, go to ready state
                        self.mutate_state(NodeStatus::Ready).await;
                    } // else keep processing for more data collection, fail should bubble-up
                } else {
                    // defer
                    info!("Received a inter-node request to verify a proof, but the node is busy in an operation");
                    self.state
                        .message_queue
                        .write()
                        .await
                        .push(NodeMessage::Internal(
                            from,
                            InterNodeMessage::VerifyResponse(verify_response),
                        ));
                }
                Ok(())
            }
            // NodeStatus::Following(WorkerState::TestingAddMember(
            //     leader,
            //     node,
            //     test_should_be_a_pass,
            // )) if from == u64::MAX => { // node id == max value if it is NOT in the quorum (i.e. new node)
            //     let nonce = self
            //         .state
            //         .nonce_manager
            //         .get_next_outgoing_nonce(*leader)
            //         .await;

            //     let msg = match (
            //         *test_should_be_a_pass,
            //         verify_response.encrypted_quorum_key_shard.is_some(),
            //     ) {
            //         (a, b) if a == b => {
            //             // Test passed (either failed and expected fail or passed and expected pass)
            //             // gather our shard, and send it to the leader "approving" the node inclusion
            //             let shard = self.crypto.retrieve_qk_shard(*leader).await?;
            //             InterNodeMessage::<H>::AddNodeTestResult(AddNodeTestResult {
            //                 encrypted_quorum_key_shard: Some(shard.payload),
            //                 contact_info: node.contact_info.clone(),
            //             })
            //         }
            //         // The test failed, don't retrieve our shard component
            //         _ => InterNodeMessage::<H>::AddNodeTestResult(AddNodeTestResult {
            //             encrypted_quorum_key_shard: None,
            //             contact_info: node.contact_info.clone(),
            //         }),
            //     };

            //     let bytes = msg.serialize()?;
            //     let e_msg = self.encrypt_message(*leader, bytes, nonce).await?;
            //     self.comms.send_message(e_msg).await?;

            //     Ok(())
            // }
            // This verification is for an unrelated verification request (potentially a test, are we in a testing state?)
            // TODO: Node testing states
            _ => {
                warn!("We received a node's verification result from node {}, but we aren't waiting on verification results", from);
                Ok(())
            }
        }
    }

    async fn try_generate_sig(
        &self,
        start_time: tokio::time::Instant,
        request: VerifyRequest<H>,
        map: HashMap<NodeId, Option<VerifyResponse<H>>>,
    ) -> Result<bool, QuorumOperationError> {
        let group_size = self.state.config.read().await.group_size;
        let num_required_shards = Crypto::shards_required(group_size).into();

        let positives = map
            .iter()
            .map(|(_, oshard)| oshard.clone().map(|shard| shard.encrypted_quorum_key_shard))
            .flatten()
            .filter_map(|a| {
                a.map(|payload| crate::crypto::EncryptedQuorumKeyShard { payload: payload })
            })
            .collect::<Vec<_>>();
        if positives.len() >= num_required_shards {
            let previous_hash = self.storage.get_latest_commitment().await?;

            // we have enough shards to attempt a reconstruction
            let mut last_err = None;
            for combination in positives.iter().combinations(num_required_shards) {
                let v = combination
                    .into_iter()
                    .map(|item| item.clone())
                    .collect::<Vec<_>>();
                match self
                    .crypto
                    .generate_commitment::<H>(
                        v,
                        request.epoch,
                        previous_hash.previous_hash,
                        request.new_hash,
                    )
                    .await
                {
                    Ok(commitment) => {
                        self.storage.save_commitment(commitment).await?;
                        return Ok(true);
                    }
                    Err(err) => {
                        last_err = Some(err);
                    }
                }
            }
            if let Some(err) = last_err {
                // bubble-up the most recent commitment generation err
                info!(
                    "Failed to generate a commitment with any combination of shards. {}",
                    err
                );
                return Err(err);
            }
        }

        if tokio::time::Instant::now() - start_time
            > tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
        {
            warn!("Distributed processing did not complete within window of {} sec so terminating distributed operation\nWe received {} votes, {} of which were successful and didn't receive {} votes",
                DISTRIBUTED_PROCESSING_TIMEOUT_SEC,
                map.len(),
                positives.len(),
                group_size as usize - positives.len()
            );
            return Ok(true);
        }
        if map.len() == group_size as usize {
            // We have received responses from everyone, and were unable to generate a commitment. We can just exit and not sign-off on the changes
            info!("Distributed verification of the changes resulted in a proof which is unverified. Verification failed.");
            return Ok(true);
        }

        // not enough shards to generate a commitment, keep collecting
        Ok(false)
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
