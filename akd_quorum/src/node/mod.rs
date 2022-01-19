// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module handles the node's primary message handling logic and
//! the state of the node

// Tasks to solve
// 1. DONE Handle message processing failure state transition. Do we just revert to "Ready"?
//    We probably need some kind of graceful failure transitions in the event we can't go from a -> b
// 2. ** Generation of AKD test's
// 3. DONE Mutation of the quorum via setting new shards & modifying the current config
// 4. DONE We likely need more message drops if we're in the "ready" state and receive partial-working messages as it's unlikely we'll
//    ever get to a working state (i.e. we can't "remove" a node if we haven't tested the node, and if a removal msg came in, we should
//    clearly not handle it)
// 5. DONE Handling of the message queue backlog that may build up
// 6. DONE Periodic testing of nodes randomly

use crate::comms::{EncryptedMessage, MessageProcessingResult, NodeId, Nonce};
use crate::QuorumOperationError;

use itertools::Itertools;
use log::{debug, error, info, warn};
use once_cell::sync::OnceCell;
use rand::distributions::{Distribution, Uniform};
use rand::{Rng, SeedableRng};
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
        let mut rng = rand::thread_rng();
        // something uniform in 1s -> 1.2s
        NODE_MESSAGE_RECEPTION_TIMEOUT_MS + rng.gen_range(0..200)
    })
}

const DISTRIBUTED_PROCESSING_TIMEOUT_SEC: u64 = 60 * 10;

// Nodes are "tested" by other members every 1..10 minutes
const INTER_NODE_TEST_TIMEOUT_SEC: (u64, u64) = (60 * 5, 60 * 10);

// =====================================================
// Structs w/implementations
// =====================================================

// *Crate-only structs*

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// The quorum configuration
pub struct Config {
    pub(crate) node_id: NodeId,
    /// The group size of the quorum membership
    pub(crate) group_size: GroupSize,
}

impl Config {
    /// A disabled pool (testing)
    pub fn disabled() -> Self {
        Self {
            group_size: 0,
            node_id: 0,
        }
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
    pub fn new(config: Config, storage: Storage, crypto: Crypto, comms: Comms) -> Self {
        Self {
            state: Arc::new(NodeState {
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
        let public_future =
            tokio::task::spawn(async move { self_1.public_message_handler(sender).await });

        let self_2 = self.clone();
        let inter_node_future =
            tokio::task::spawn(
                async move { self_2.inter_node_message_handler(&mut receiver).await },
            );

        let self_3 = self.clone();
        let test_tick = tokio::task::spawn(async move {
            // ThreadRng
            let mut rng = rand::rngs::StdRng::from_entropy();
            let die = Uniform::from(INTER_NODE_TEST_TIMEOUT_SEC.0..INTER_NODE_TEST_TIMEOUT_SEC.1);
            loop {
                // sleep for a random amount of time
                let sleep_time = die.sample(&mut rng);
                tokio::time::sleep(tokio::time::Duration::from_secs(sleep_time)).await;
                // issue a "test" to another member node
                let _ = self_3.handle_message(NodeMessage::TestNode).await?;
            }
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
            test_tick_result = test_tick => {
                if let Err(err) = &test_tick_result {
                    error!("Node test timeout handler exited with error\n{}", err);
                } else {
                    error!("Node test timeout handler exited with no code");
                }
                test_tick_result?
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

    async fn flush_message_queue(&self) {
        let mut m_queue = {
            let mut queue_guard = self.state.message_queue.write().await;
            let out = queue_guard.clone();
            *queue_guard = vec![];
            out
            // drop the lock
        };
        // turn it into a queue
        m_queue.reverse();

        while let Some(msg) = m_queue.pop() {
            let o_target = match &msg {
                NodeMessage::Internal(from, _) => Some(*from),
                _ => None,
            };

            match (self.handle_message(msg).await, o_target) {
                (Ok(Some(result)), Some(to)) => match result.serialize() {
                    Ok(reply) => {
                        let nonce = self.state.nonce_manager.get_next_outgoing_nonce(to).await;
                        match self.encrypt_message(to, reply, nonce).await {
                            Ok(message) => {
                                if let Err(err) =
                                    self.comms.send_and_maybe_receive(message, None).await
                                {
                                    error!(
                                        "Failed to send reply for backlogged message\n{}",
                                        QuorumOperationError::from(err)
                                    );
                                }
                            }
                            Err(err) => {
                                error!("Failed to encrypt reply for backlogged message\n{}", err);
                            }
                        }
                    }
                    Err(err) => {
                        error!(
                            "Failed to serialize reply for backlogged message\n{}",
                            QuorumOperationError::from(err)
                        );
                    }
                },
                (Ok(_), _) => {
                    // no-op, message handled with no reply
                }
                (Err(err), _) => {
                    error!("Error handling backlogged message: {}", err);
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
                                    let _ = tokio::spawn(async move {
                                        if let Err(err) = self_clone
                                        .handle_inter_node_message_helper(
                                            message,
                                            received.timeout,
                                            received.reply,
                                        )
                                        .await {
                                            warn!("Error handling message: {}", err);
                                            // TODO: other logs or stat counters?
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
        // Message reception timeout

        // Perform a "state handler timer tick"
        let node_id = self.state.config.read().await.node_id;
        let _ = self
            .handle_message(NodeMessage::Internal(
                node_id,
                InterNodeMessage::<H>::TimerTick,
            ))
            .await?;

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

        // flush the message queue that may have accumulated
        self.flush_message_queue().await;

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
        reply: Sender<MessageProcessingResult>,
    ) -> Result<(), QuorumOperationError> {
        let job = self.handle_inter_node_message(message);
        let result = match timeout {
            Some(tic_toc) => match tokio::time::timeout(tic_toc, job).await {
                Err(_) => MessageProcessingResult::Timeout,
                Ok(Ok(result)) => MessageProcessingResult::Ok(result),
                Ok(Err(r_err)) => MessageProcessingResult::Error(r_err.to_string()),
            },
            None => match job.await {
                Ok(result) => MessageProcessingResult::Ok(result),
                Err(r_err) => MessageProcessingResult::Error(r_err.to_string()),
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
            from: self.state.config.read().await.node_id,
            encrypted_message_with_nonce: enc,
        };
        Ok(message)
    }

    async fn decrypt_message(
        &self,
        message: EncryptedMessage,
    ) -> Result<Message, QuorumOperationError> {
        let node_id = self.state.config.read().await.node_id;
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
            nonce,
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
        // process time'd operations, then we'll handle message-specific logic
        self.timer_tick().await?;

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
                    if let Some(result) = self.verify_request_impl(from, verify_request).await? {
                        return Ok(Some(InterNodeMessage::VerifyResponse(result)));
                    }
                }
                InterNodeMessage::VerifyResponse(verify_response) => {
                    self.verify_response_impl(from, verify_response).await?;
                }
                InterNodeMessage::AddNodeInit(add_node_init) => {
                    if let Some(result) = self.add_node_init_impl(from, add_node_init).await? {
                        return Ok(Some(InterNodeMessage::AddNodeTestResult(result)));
                    }
                }
                InterNodeMessage::AddNodeTestResult(test_result) => {
                    self.add_node_test_result_impl(from, test_result).await?
                }
                InterNodeMessage::AddNodeResult(result) => {
                    if let Some(ack) = self.add_node_result_impl(from, result).await? {
                        return Ok(Some(InterNodeMessage::InterNodeAck(ack)));
                    }
                }
                InterNodeMessage::NewNodeTest(test) => {
                    let result = self.new_node_test_impl(test).await?;
                    return Ok(Some(InterNodeMessage::NewNodeTestResult(result)));
                }
                InterNodeMessage::NewNodeTestResult(_test_result) => {
                    // cannot occur, it's a directly TCP reply
                    warn!("Received a NewNodeTestResult which isn't supported in an async reception channel");
                }
                InterNodeMessage::RemoveNodeInit(remove_node_init) => {
                    if let Some(result) = self.remove_node_init_impl(from, remove_node_init).await?
                    {
                        return Ok(Some(InterNodeMessage::RemoveNodeTestResult(result)));
                    }
                }
                InterNodeMessage::RemoveNodeTestResult(test_result) => {
                    // no reply to the edges directly
                    self.remove_node_test_result_impl(from, test_result).await?;
                }
                InterNodeMessage::RemoveNodeResult(result) => {
                    if let Some(ack) = self.remove_node_result_impl(from, result).await? {
                        return Ok(Some(InterNodeMessage::InterNodeAck(ack)));
                    }
                }
                InterNodeMessage::InterNodeAck(ack) => {
                    self.inter_node_ack_impl(from, ack).await?;
                }
                InterNodeMessage::TimerTick => {
                    // just an empty message to try the timer tick op
                }
            },
            NodeMessage::TestNode => {
                self.test_random_node().await?;
            }
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
                    previous_hash: verify_request.previous_hash,
                    new_hash: verify_request.new_hash,
                    append_only_proof: verify_request.append_only_proof,
                    epoch: verify_request.epoch,
                };

                // set the state to "pending verification" waiting on the resultant votes
                self.mutate_state(NodeStatus::<H>::Leading(
                    LeaderState::<H>::ProcessingVerification(
                        tokio::time::Instant::now(),
                        internal_request.clone(),
                        HashMap::new(),
                    ),
                ))
                .await;

                let p_commitment = self.storage.get_latest_commitment().await;
                match p_commitment {
                    Ok(commitment)
                        if commitment.current_epoch == verify_request.epoch - 1
                            && commitment.current_hash == verify_request.previous_hash =>
                    {
                        // OK to proceed, a linear-chain of history is established
                    }
                    _ => {
                        return Err(QuorumOperationError::Unknown("The verification request does not form a linear chain from the previous commitment!".to_string()));
                    }
                }

                // Perform our own portion of the verification process (i.e. our vote, and possibly our shard of the key)
                let self_clone = self.clone();
                let request_clone = internal_request.clone();
                let self_handle = tokio::task::spawn(async move {
                    let node_id = self_clone.state.config.read().await.node_id;
                    let verification = self_clone.verify_request_impl(node_id, request_clone).await;
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
                                    .try_generate_commitment(
                                        *start_time,
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

                // broadcast to the remaining other nodes the verification request
                let _ = self
                    .broadcast(
                        |_| InterNodeMessage::<H>::VerifyRequest(internal_request.clone()),
                        true,
                    )
                    .await?;

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

                let _ = self
                    .broadcast(
                        |_| InterNodeMessage::<H>::AddNodeInit(internal_request.clone()),
                        false,
                    )
                    .await?;

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

                // broadcast to all the nodes without waiting on the immediate result (there should be none)
                let _ = self
                    .broadcast(
                        |_| InterNodeMessage::<H>::RemoveNodeInit(internal_request.clone()),
                        false,
                    )
                    .await?;

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

    async fn add_node_init_impl(
        &self,
        from: NodeId,
        add_node_init: AddNodeInit,
    ) -> Result<Option<AddNodeTestResult>, QuorumOperationError> {
        let state = self.get_state().await;
        let node_id = self.state.config.read().await.node_id;
        let should_mutate_state = matches!(&state, NodeStatus::Ready);
        match &state {
            NodeStatus::Ready | NodeStatus::Leading(LeaderState::ProcessingAddition(_, _, _))
                if from == node_id =>
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
                        tokio::time::Instant::now(),
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
                    from: node_id,
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
                                WorkerState::WaitingOnMemberAddResult(
                                    tokio::time::Instant::now(),
                                    add_node_init_copy,
                                ),
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
                        info!("Test node {} failed to correctly compute the test proof. Node {} disapproves of adding candidate to the quorum", add_node_init.contact_info, node_id);
                    }
                } else {
                    info!("Test node {} returned an incorrect message. Node {} disapproves of adding candidate to the quorum", add_node_init.contact_info, node_id);
                }

                if should_mutate_state {
                    self.mutate_state(NodeStatus::Following(
                        WorkerState::WaitingOnMemberAddResult(
                            tokio::time::Instant::now(),
                            add_node_init_copy,
                        ),
                    ))
                    .await;
                }

                // test failure
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

    async fn add_node_result_impl(
        &self,
        from: NodeId,
        result: AddNodeResult,
    ) -> Result<Option<InterNodeAck>, QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Following(WorkerState::WaitingOnMemberAddResult(_, request))
                if request.contact_info == result.new_member.contact_information =>
            {
                let rclone = result.clone();
                // update the state back to "Ready" and process the shard inclusion
                self.mutate_state(NodeStatus::Ready).await;

                if let Some(shard) = result.encrypted_quorum_key_shard {
                    self.storage.add_quorum_member(result.new_member).await?;
                    self.crypto
                        .update_qk_shard(crate::crypto::EncryptedQuorumKeyShard { payload: shard })
                        .await?;
                }

                return Ok(Some(InterNodeAck {
                    ok: true,
                    err: None,
                    ackd_msg: AckableMessage::AddNodeResult(rclone),
                }));
            }
            _ => {
                info!("Received a inter-node request to process an add-node request, but the node is busy in an operation");
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Internal(
                        from,
                        InterNodeMessage::AddNodeResult(result),
                    ));
            }
        }
        Ok(None)
    }

    async fn add_node_test_result_impl(
        &self,
        from: NodeId,
        test_result: AddNodeTestResult,
    ) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(LeaderState::ProcessingAddition(_, request, response_map))
                if request.contact_info == test_result.contact_info =>
            {
                // this verification is related to our verification request, update the state
                let mut new_map = response_map.clone();
                new_map.insert(from, test_result);

                let config_guard = self.state.config.read().await;
                let this_node_id = config_guard.node_id;
                let group_size = config_guard.group_size;
                let num_required_shards = Crypto::shards_required(group_size).into();

                let mut public_keys = vec![];
                for node_id in 0..group_size as NodeId {
                    let contact = self
                        .storage
                        .retrieve_quorum_member(node_id)
                        .await?
                        .public_key;
                    public_keys.push(contact);
                }
                // add the new member into the quorum
                public_keys.push(request.public_key.clone());

                // identify the test-results that were "positive" for adding the new member
                let positives = new_map
                    .iter()
                    .map(|(_, oshard)| oshard.encrypted_quorum_key_shard.clone())
                    .flatten()
                    .map(|payload| crate::crypto::EncryptedQuorumKeyShard { payload })
                    .collect::<Vec<_>>();
                if positives.len() >= num_required_shards {
                    // we have enough shards to attempt a reconstruction
                    let mut new_shard_collection = vec![];
                    let mut last_err = None;
                    // Attempt all shard reconstruction combinations, in case one shard is malformed/corrupted
                    for combination in positives.iter().combinations(num_required_shards) {
                        let v = combination.into_iter().cloned().collect::<Vec<_>>();
                        // Generate the new shards from the old shards
                        match self
                            .crypto
                            .generate_encrypted_shards(v, public_keys.clone())
                            .await
                        {
                            Ok(new_shards) => {
                                new_shard_collection = new_shards;
                                break;
                            }
                            Err(err) => last_err = Some(err),
                        }
                    }

                    if new_shard_collection.len() == public_keys.len() {
                        // we reconstructed shards, broadcast them to the membership

                        // put state into adding member
                        let shard_map = new_shard_collection
                            .iter()
                            .enumerate()
                            .map(|(a, b)| (a as NodeId, b.clone()))
                            .collect::<HashMap<_, _>>();
                        // save the pending operation's for nodes that need to remove shards
                        self.mutate_state(NodeStatus::Leading(LeaderState::AddingMember(
                            tokio::time::Instant::now(),
                            request.clone(),
                            shard_map.clone(),
                        )))
                        .await;

                        // broadcast requests for shard removals
                        let results = self
                            .broadcast(
                                |node_id| {
                                    InterNodeMessage::<H>::AddNodeResult(AddNodeResult {
                                        encrypted_quorum_key_shard: Some(
                                            new_shard_collection[node_id as usize].payload.clone(),
                                        ),
                                        new_member: crate::storage::MemberInformation {
                                            node_id: group_size as NodeId,
                                            public_key: request.public_key.clone(),
                                            contact_information: request.contact_info.clone(),
                                        },
                                    })
                                },
                                true,
                            )
                            .await?;

                        // process all the node removals for nodes
                        for (other, item) in results.iter().enumerate() {
                            if let Some(InterNodeMessage::InterNodeAck(ack)) = item {
                                self.inter_node_ack_impl(other as NodeId, ack.clone())
                                    .await?;
                            } else {
                                self.inter_node_ack_impl(
                                    other as NodeId,
                                    InterNodeAck::fake_ack(false, true),
                                )
                                .await?;
                            }
                        }

                        // store _our_ shard
                        if let Some(pt) = shard_map.get(&this_node_id) {
                            self.crypto.update_qk_shard(pt.clone()).await?;
                            self.inter_node_ack_impl(
                                this_node_id,
                                InterNodeAck::fake_ack(true, true),
                            )
                            .await?;
                        } else {
                            self.inter_node_ack_impl(
                                this_node_id,
                                InterNodeAck::fake_ack(false, true),
                            )
                            .await?;
                            return Err("We didn't generate a shard for the leader!"
                                .to_string()
                                .into());
                        }

                        // NOTE: In the event that any nodes couldn't immediately process shard removals (i.e. they were busy
                        // processing another operation), then we need to allow the ability for background processing of ack's.
                        // This means that the inter_node_ack_impl's may NOT have set us back to "Ready" by this point, likely
                        // it is, however we need to handle the edge cases.
                    } else if let Some(err) = last_err {
                        // bubble-up the most recent commitment generation err
                        info!(
                            "Failed to generate new shards from previous encrypted shards. {}",
                            err
                        );
                        return Err(err);
                    }
                }

                if new_map.len() == group_size as usize {
                    // We have received responses from everyone, and were unable to generate a quorum. We can just exit and not sign-off on the changes
                    info!("Distributed verification of the member addition failed, resulting in no node addition.");
                    self.mutate_state(NodeStatus::Ready).await;
                }
            }
            NodeStatus::Ready => {
                // drop the message, as we shouldn't be in the ready state if we've processed the msg queue
            }
            _ => {
                info!("Received a inter-node request for a test result on a different node, but the node is busy in an operation");
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Internal(
                        from,
                        InterNodeMessage::AddNodeTestResult(test_result),
                    ));
            }
        }
        Ok(())
    }

    async fn new_node_test_impl(
        &self,
        test: NewNodeTest<H>,
    ) -> Result<NewNodeTestResult, QuorumOperationError> {
        if let NodeStatus::Ready = self.get_state().await {
            let pass =
                akd::auditor::audit_verify(test.previous_hash, test.new_hash, test.test_proof)
                    .await
                    .is_ok();
            return Ok(NewNodeTestResult { test_pass: pass });
        }
        // reply
        Ok(NewNodeTestResult { test_pass: false })
    }

    async fn get_random_id(&self) -> Option<(NodeId, NodeId)> {
        // NOTE: We cannot use thread_rng() here due to this being executed
        // on green threads. ThreadRng is not "Send"
        let mut rng = rand::rngs::StdRng::from_entropy();
        let config_guard = self.state.config.read().await;
        let node_id = config_guard.node_id;
        let group_size = config_guard.group_size;

        if group_size <= 1 {
            return None;
        }

        let die = Uniform::from(0..group_size as NodeId);
        // take the first sample
        let mut target_node = die.sample(&mut rng);
        while target_node == node_id {
            // keep sampling until we find an id that's not our own
            target_node = die.sample(&mut rng);
        }
        Some((target_node, node_id))
    }

    async fn test_random_node(&self) -> Result<(), QuorumOperationError> {
        if let Some((target_node, node_id)) = self.get_random_id().await {
            if let NodeStatus::Ready = self.get_state().await {
                let (should_pass, test) = self.generate_test().await?;
                self.mutate_state(NodeStatus::Following(WorkerState::TestingNode(
                    tokio::time::Instant::now(),
                    target_node,
                    should_pass,
                )))
                .await;

                debug!("Node {} is testing member node: {}", node_id, target_node);

                // TODO: randomize the epoch?
                let verify_request = VerifyRequest::<H> {
                    append_only_proof: test.test_proof,
                    epoch: 34,
                    new_hash: test.new_hash,
                    previous_hash: test.previous_hash,
                };

                // generate the plaintext msg
                let msg = InterNodeMessage::VerifyRequest::<H>(verify_request).serialize()?;
                let nonce = self
                    .state
                    .nonce_manager
                    .get_next_outgoing_nonce(target_node)
                    .await;
                let e_msg = self.encrypt_message(target_node, msg, nonce).await?;

                // send & wait for the reply. 30s timeout as the test should be small and practical
                match self
                    .comms
                    .send_and_maybe_receive(
                        e_msg,
                        Some(tokio::time::Duration::from_millis(30u64 * 1000u64)),
                    )
                    .await
                {
                    Err(comms_err) => {
                        warn!(
                            "Communication error to node {}. Requesting member's removal\n{}",
                            target_node,
                            QuorumOperationError::from(comms_err)
                        );

                        // revert the state to normal & input a "remove member" request
                        self.state
                            .message_queue
                            .write()
                            .await
                            .push(NodeMessage::Public(PublicNodeMessage::Remove(
                                RemoveMemberRequest {
                                    node_id: target_node,
                                },
                            )));
                        self.mutate_state(NodeStatus::Ready).await;
                    }
                    Ok(Some(result)) => {
                        let msg = self.decrypt_message(result).await?;
                        let deserialized =
                            InterNodeMessage::<H>::try_deserialize(msg.serialized_message)?;
                        if let InterNodeMessage::VerifyResponse(test_result) = deserialized {
                            if test_result.encrypted_quorum_key_shard.is_some() != should_pass {
                                info!(
                                    "Node {} failed it's proof test. Requesting member's removal",
                                    target_node
                                );
                                // push a message to do a node removal
                                self.state
                                    .message_queue
                                    .write()
                                    .await
                                    .push(NodeMessage::Public(PublicNodeMessage::Remove(
                                        RemoveMemberRequest {
                                            node_id: target_node,
                                        },
                                    )));
                            } // else correctly verified the proof, revert to Ready state and everything is good

                            // revert to ready state
                            self.mutate_state(NodeStatus::Ready).await;
                        }
                    }
                    Ok(None) => {
                        // it's in an async reply channel, we'll have to wait in the state handling state until the response comes in
                        // and add the logic to verify_request_impl
                    }
                }
            }
        }
        // else skip this testing cycle and wait until the next timer tick

        Ok(())
    }

    async fn remove_node_init_impl(
        &self,
        from: NodeId,
        remove_node_init: RemoveNodeInit,
    ) -> Result<Option<RemoveNodeTestResult>, QuorumOperationError> {
        let state = self.get_state().await;
        let node_id = self.state.config.read().await.node_id;
        let should_mutate_state = matches!(&state, NodeStatus::Ready);
        match &state {
            NodeStatus::Ready | NodeStatus::Leading(LeaderState::ProcessingRemoval(_, _, _))
                if from == node_id =>
            {
                // OK
                debug!(
                    "Node {} is testing member node: {}",
                    from, remove_node_init.node_id
                );
                let (should_pass, test) = self.generate_test().await?;

                // TODO: randomize the epoch?
                let verify_request = VerifyRequest::<H> {
                    append_only_proof: test.test_proof,
                    epoch: 34,
                    new_hash: test.new_hash,
                    previous_hash: test.previous_hash,
                };

                if should_mutate_state {
                    self.mutate_state(NodeStatus::Following(WorkerState::TestingRemoveMember(
                        tokio::time::Instant::now(),
                        from,
                        remove_node_init.clone(),
                        should_pass,
                    )))
                    .await;
                }

                // generate the plaintext msg
                let msg = InterNodeMessage::VerifyRequest::<H>(verify_request).serialize()?;
                let nonce = self
                    .state
                    .nonce_manager
                    .get_next_outgoing_nonce(remove_node_init.node_id)
                    .await;
                let e_msg = self
                    .encrypt_message(remove_node_init.node_id, msg, nonce)
                    .await?;

                // send & wait for the reply. 30s timeout as the test should be small and practical
                let o_result = self
                    .comms
                    .send_and_maybe_receive(
                        e_msg,
                        Some(tokio::time::Duration::from_millis(30u64 * 1000u64)),
                    )
                    .await?;
                if let Some(result) = o_result {
                    // decode the reply
                    let msg = self.decrypt_message(result).await?;
                    let deserialized =
                        InterNodeMessage::<H>::try_deserialize(msg.serialized_message)?;
                    // check the reply result
                    if should_mutate_state {
                        self.mutate_state(NodeStatus::Following(
                            WorkerState::WaitingOnMemberRemoveResult(
                                tokio::time::Instant::now(),
                                remove_node_init.clone(),
                            ),
                        ))
                        .await;
                    }
                    if let InterNodeMessage::VerifyResponse::<H>(test_result) = deserialized {
                        if test_result.encrypted_quorum_key_shard.is_some() != should_pass {
                            // failed test, we approve of removing this node (to the leader)
                            return Ok(Some(RemoveNodeTestResult {
                                offending_member: remove_node_init.node_id,
                                encrypted_quorum_key_shard: Some(
                                    self.crypto.retrieve_qk_shard(from).await?.payload,
                                ),
                            }));
                        } else {
                            // correctly verified proof, therefore we don't agree to removing it from the quorum
                            info!("Test node {} correctly validated the append-only proof. Node {} disapproves of removing candidate from the quorum", remove_node_init.node_id, node_id);
                        }
                    } else {
                        info!("Test node {} returned an incorrect message. Node {} approves of removing candidate from the quorum", remove_node_init.node_id, node_id);
                        // Failed test, give our shard to the leader
                        return Ok(Some(RemoveNodeTestResult {
                            offending_member: remove_node_init.node_id,
                            encrypted_quorum_key_shard: Some(
                                self.crypto.retrieve_qk_shard(from).await?.payload,
                            ),
                        }));
                    }

                    // test passage, i.e. we do NOT agree to remove the node from the quorum
                    return Ok(Some(RemoveNodeTestResult {
                        offending_member: remove_node_init.node_id,
                        encrypted_quorum_key_shard: None,
                    }));
                }
                // Else: it's in an async reply channel, we'll have to wait in the state handling state until the response comes in
                // and add the logic to verify_request_impl
            }
            _ => {
                info!("Received a inter-node request to remove a node, but the node is busy in an operation");
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Internal(
                        from,
                        InterNodeMessage::RemoveNodeInit(remove_node_init),
                    ));
            }
        }
        Ok(None)
    }

    async fn remove_node_result_impl(
        &self,
        from: NodeId,
        result: RemoveNodeResult,
    ) -> Result<Option<InterNodeAck>, QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Following(WorkerState::WaitingOnMemberRemoveResult(_, request))
                if request.node_id == result.offending_member =>
            {
                let rclone = result.clone();
                // update the state back to "Ready" and process the shard inclusion
                self.mutate_state(NodeStatus::Ready).await;

                if let Some(shard) = result.encrypted_quorum_key_shard {
                    self.storage
                        .remove_quorum_member(result.offending_member)
                        .await?;
                    self.crypto
                        .update_qk_shard(crate::crypto::EncryptedQuorumKeyShard { payload: shard })
                        .await?;
                    let mut config_guard = self.state.config.write().await;
                    if config_guard.node_id > request.node_id {
                        // the "member" node that was removed was below our node id, and therefore our id will be decremented
                        config_guard.node_id -= 1;
                    }
                    config_guard.group_size -= 1;
                }

                return Ok(Some(InterNodeAck {
                    ok: true,
                    err: None,
                    ackd_msg: AckableMessage::RemoveNodeResult(rclone),
                }));
            }
            NodeStatus::Ready => {
                // drop the message, as we shouldn't be in the ready state if we've processed the msg queue
            }
            _ => {
                info!("Received a inter-node request to finalize removal of a node, but the node is busy in an operation");
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Internal(
                        from,
                        InterNodeMessage::RemoveNodeResult(result),
                    ));
            }
        }

        Ok(None)
    }

    async fn remove_node_test_result_impl(
        &self,
        from: NodeId,
        remove_node_test_result: RemoveNodeTestResult,
    ) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(LeaderState::ProcessingRemoval(_, args, result_map))
                if args.node_id == remove_node_test_result.offending_member =>
            {
                let mut map = result_map.clone();
                map.insert(from, remove_node_test_result);

                let config_guard = self.state.config.read().await;
                let this_node_id = config_guard.node_id;
                let group_size = config_guard.group_size;
                let num_required_shards = Crypto::shards_required(group_size).into();

                let mut public_keys = vec![];
                for node_id in 0..group_size as NodeId {
                    // exclude the offending member in the public-key set
                    if node_id == args.node_id {
                        continue;
                    }
                    let contact = self
                        .storage
                        .retrieve_quorum_member(node_id)
                        .await?
                        .public_key;
                    public_keys.push(contact);
                }

                // identify the test-results that were "positive" for removal of the old member
                let positives = map
                    .iter()
                    .filter_map(|(_, oshard)| oshard.encrypted_quorum_key_shard.clone())
                    .map(|payload| crate::crypto::EncryptedQuorumKeyShard { payload })
                    .collect::<Vec<_>>();

                if positives.len() >= num_required_shards {
                    // we have enough shards to attempt a reconstruction
                    let mut new_shard_collection = vec![];
                    let mut last_err = None;
                    // Attempt all shard reconstruction combinations, in case one shard is malformed/corrupted
                    for combination in positives.iter().combinations(num_required_shards) {
                        let v = combination.into_iter().cloned().collect::<Vec<_>>();
                        // Generate the new shards from the old shards
                        match self
                            .crypto
                            .generate_encrypted_shards(v, public_keys.clone())
                            .await
                        {
                            Ok(new_shards) => {
                                new_shard_collection = new_shards;
                                break;
                            }
                            Err(err) => last_err = Some(err),
                        }
                    }

                    if new_shard_collection.len() == public_keys.len() {
                        // we reconstructed shards, broadcast them to the membership

                        // put state into adding member
                        let shard_map = new_shard_collection
                            .iter()
                            .enumerate()
                            .map(|(a, b)| (a as NodeId, b.clone()))
                            .collect::<HashMap<_, _>>();
                        // save the pending operation's for nodes that need to remove shards
                        self.mutate_state(NodeStatus::Leading(LeaderState::RemovingMember(
                            tokio::time::Instant::now(),
                            args.node_id,
                            shard_map.clone(),
                        )))
                        .await;

                        // broadcast requests for shard removals
                        let results = self
                            .broadcast(
                                |node_id| {
                                    InterNodeMessage::<H>::RemoveNodeResult(RemoveNodeResult {
                                        encrypted_quorum_key_shard: Some(
                                            new_shard_collection[node_id as usize].payload.clone(),
                                        ),
                                        offending_member: args.node_id,
                                    })
                                },
                                true,
                            )
                            .await?;

                        // process all the node removals for nodes
                        for (other, item) in results.iter().enumerate() {
                            if let Some(InterNodeMessage::InterNodeAck(ack)) = item {
                                self.inter_node_ack_impl(other as NodeId, ack.clone())
                                    .await?;
                            } else {
                                self.inter_node_ack_impl(
                                    other as NodeId,
                                    InterNodeAck::fake_ack(false, true),
                                )
                                .await?;
                            }
                        }

                        // store _our_ shard
                        if let Some(pt) = shard_map.get(&this_node_id) {
                            self.crypto.update_qk_shard(pt.clone()).await?;
                            self.inter_node_ack_impl(
                                this_node_id,
                                InterNodeAck::fake_ack(true, true),
                            )
                            .await?;
                        } else {
                            self.inter_node_ack_impl(
                                this_node_id,
                                InterNodeAck::fake_ack(false, true),
                            )
                            .await?;
                            return Err("We didn't generate a shard for the leader!"
                                .to_string()
                                .into());
                        }

                        // NOTE: In the event that any nodes couldn't immediately process shard removals (i.e. they were busy
                        // processing another operation), then we need to allow the ability for background processing of ack's.
                        // This means that the inter_node_ack_impl's may NOT have set us back to "Ready" by this point, likely
                        // it is, however we need to handle the edge cases.
                    } else if let Some(err) = last_err {
                        // bubble-up the most recent commitment generation err
                        info!(
                            "Failed to generate new shards from previous encrypted shards. {}",
                            err
                        );
                        return Err(err);
                    }
                } else if map.len() == group_size.into() {
                    // we've received responses from everyone and didn't generate a quorum, fail the removal operation
                    let _responses = self
                        .broadcast(
                            |_| {
                                InterNodeMessage::<H>::RemoveNodeResult(RemoveNodeResult {
                                    encrypted_quorum_key_shard: None,
                                    offending_member: args.node_id,
                                })
                            },
                            true,
                        )
                        .await?;
                    // we can ignore the respsonses, because _eventually_ we'll just time out on failures
                    // and the comms layer should handle transient comms errors

                    // we don't need to do anything, just revert to ready state
                    self.mutate_state(NodeStatus::Ready).await;
                }
                // else keep processing
            }
            NodeStatus::Ready => {
                // drop the message, as we shouldn't be in the ready state if we've processed the msg queue
            }
            _ => {
                info!("Received a inter-node request for a node removal test result, but the node is busy in an operation");
                self.state
                    .message_queue
                    .write()
                    .await
                    .push(NodeMessage::Internal(
                        from,
                        InterNodeMessage::RemoveNodeTestResult(remove_node_test_result),
                    ));
            }
        }
        Ok(())
    }

    async fn verify_request_impl(
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
                if let Err(error) = akd::auditor::verify_append_only(
                    verify_request.append_only_proof,
                    verify_request.previous_hash,
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
                        .try_generate_commitment(start_time, request.clone(), new_map)
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
            }
            NodeStatus::Following(WorkerState::TestingRemoveMember(
                _,
                leader,
                args,
                should_pass,
            )) => {
                // received a test-result from a worker node, which was an async reply so we need to handle it here
                // and send the result to the leader node

                self.mutate_state(NodeStatus::Following(
                    WorkerState::WaitingOnMemberRemoveResult(
                        tokio::time::Instant::now(),
                        args.clone(),
                    ),
                ))
                .await;

                if verify_response.encrypted_quorum_key_shard.is_some() != should_pass {
                    // failed test, we approve of removing this node
                    let msg = InterNodeMessage::<H>::RemoveNodeTestResult(RemoveNodeTestResult {
                        offending_member: args.node_id,
                        encrypted_quorum_key_shard: Some(
                            self.crypto.retrieve_qk_shard(from).await?.payload,
                        ),
                    });
                    let serialized = msg.serialize()?;
                    let nonce = self
                        .state
                        .nonce_manager
                        .get_next_outgoing_nonce(leader)
                        .await;
                    let e_msg = self.encrypt_message(leader, serialized, nonce).await?;
                    let _ = self.comms.send_and_maybe_receive(e_msg, None).await?;
                } // else node passed the test, it should stay in the quorum
            }
            NodeStatus::Following(WorkerState::TestingNode(_, node, should_pass)) => {
                if verify_response.encrypted_quorum_key_shard.is_some() != should_pass {
                    // we should trigger a node removal
                    self.state
                        .message_queue
                        .write()
                        .await
                        .push(NodeMessage::Public(PublicNodeMessage::Remove(
                            RemoveMemberRequest { node_id: node },
                        )));
                }
                // bring state back to nominal
                self.mutate_state(NodeStatus::Ready).await;
            }
            _ => {
                warn!("We received a node's verification result from node {}, but we aren't waiting on verification results", from);
            }
        }
        Ok(())
    }

    async fn inter_node_ack_impl(
        &self,
        from: NodeId,
        ack: InterNodeAck,
    ) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(LeaderState::AddingMember(start_time, request, members)) => {
                let mut map = members.clone();
                if ack.ok {
                    map.remove(&from);
                }

                if map.is_empty() {
                    info!("Received all acknowledgements from member nodes about new addition");
                    self.mutate_state(NodeStatus::Ready).await;
                } else {
                    // save the new map and keep processing, we haven't received all ack's yet
                    self.mutate_state(NodeStatus::Leading(LeaderState::AddingMember(
                        start_time,
                        request.clone(),
                        map,
                    )))
                    .await;
                    return Ok(());
                }

                let mut config_guard = self.state.config.write().await;
                // received all responses or some edges timed out handling removal cmd
                self.storage
                    .add_quorum_member(crate::storage::MemberInformation {
                        node_id: config_guard.group_size.into(),
                        contact_information: request.contact_info,
                        public_key: request.public_key,
                    })
                    .await?;

                config_guard.group_size += 1;
            }
            NodeStatus::Leading(LeaderState::RemovingMember(start_time, request, members)) => {
                let mut map = members.clone();
                if ack.ok {
                    map.remove(&from);
                }

                if map.is_empty() {
                    info!("Received all acknowledgements from member nodes about member removal");
                    self.mutate_state(NodeStatus::Ready).await;
                } else {
                    // save the new map and keep processing, we haven't received all ack's yet
                    self.mutate_state(NodeStatus::Leading(LeaderState::RemovingMember(
                        start_time, request, map,
                    )))
                    .await;
                    return Ok(());
                }

                // received all responses or some edges timed out handling removal cmd
                self.storage.remove_quorum_member(request).await?;

                let mut config_guard = self.state.config.write().await;
                if config_guard.node_id > request {
                    // the "member" node that was removed was below our node id, and therefore our id will be decremented
                    config_guard.node_id -= 1;
                }
                config_guard.group_size -= 1;
            }
            _ => {
                // ignore ack
            }
        }
        Ok(())
    }

    /// Try and generate a commitment signature with the partial shards that were collected
    async fn try_generate_commitment(
        &self,
        start_time: tokio::time::Instant,
        request: VerifyRequest<H>,
        map: HashMap<NodeId, Option<VerifyResponse<H>>>,
    ) -> Result<bool, QuorumOperationError> {
        let group_size = self.state.config.read().await.group_size;
        let num_required_shards = Crypto::shards_required(group_size).into();

        // identify which nodes replied with their shard, meaning they approved of the changes
        let positives = map
            .iter()
            .map(|(_, oshard)| oshard.clone().map(|shard| shard.encrypted_quorum_key_shard))
            .flatten()
            .filter_map(|a| a.map(|payload| crate::crypto::EncryptedQuorumKeyShard { payload }))
            .collect::<Vec<_>>();
        // Do we have enough to try and generate a commitment?
        if positives.len() >= num_required_shards {
            let previous_hash = request.previous_hash;

            // we have enough shards to attempt a reconstruction
            let mut last_err = None;
            // Try all combinations of the shard collection, in case we don't have the right combination
            for combination in positives.iter().combinations(num_required_shards) {
                let v = combination.into_iter().cloned().collect::<Vec<_>>();
                match self
                    .crypto
                    .generate_commitment::<H>(v, request.epoch, previous_hash, request.new_hash)
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

        // some nodes didn't reply in time
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
        // all nodes replied, but we couldn't generate a commitment meaning they didn't agree
        // on the changes
        if map.len() == group_size as usize {
            // We have received responses from everyone, and were unable to generate a commitment. We can just exit and not sign-off on the changes
            info!("Distributed verification of the changes resulted in a proof which is unverified. Verification failed.");
            return Ok(true);
        }

        // not enough shards to generate a commitment, keep collecting
        Ok(false)
    }

    /// Broadcast to a specific set of nodes
    async fn specific_broadcast<MsgBuilder>(
        &self,
        message_builder: MsgBuilder,
        nodes: Vec<NodeId>,
    ) -> Result<Vec<Option<InterNodeMessage<H>>>, QuorumOperationError>
    where
        MsgBuilder: Fn(NodeId) -> InterNodeMessage<H>,
    {
        let mut tasks = vec![];
        for node_id in nodes {
            let self_clone = self.clone();
            let message = message_builder(node_id);
            let serialized_msg = message.serialize()?;
            let nonce = self
                .state
                .nonce_manager
                .get_next_outgoing_nonce(node_id)
                .await;
            let e_msg = self.encrypt_message(node_id, serialized_msg, nonce).await?;

            let future: tokio::task::JoinHandle<Result<Option<_>, QuorumOperationError>> =
                tokio::spawn(async move {
                    let response = self_clone
                        .comms
                        .send_and_maybe_receive(
                            e_msg,
                            Some(tokio::time::Duration::from_secs(
                                DISTRIBUTED_PROCESSING_TIMEOUT_SEC,
                            )),
                        )
                        .await?;
                    if let Some(r_msg) = response {
                        let decrypted = self_clone.decrypt_message(r_msg).await?;
                        let inm =
                            InterNodeMessage::<H>::try_deserialize(decrypted.serialized_message)?;
                        Ok(Some(inm))
                    } else {
                        Ok(None)
                    }
                });
            tasks.push(future);
        }
        let results = futures::future::join_all(tasks)
            .await
            .into_iter()
            .map(|joined| match joined {
                Ok(Ok(o_message)) => o_message,
                Ok(Err(err)) => {
                    warn!("Error receiving broadcast result from node {}", err);
                    None
                }
                Err(_) => {
                    warn!("Error joining tokio task");
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(results)
    }

    /// Broadcast to all the nodes in the quorum, optionally "except" the current node (self)
    async fn broadcast<MsgBuilder>(
        &self,
        message_builder: MsgBuilder,
        skip_self: bool,
    ) -> Result<Vec<Option<InterNodeMessage<H>>>, QuorumOperationError>
    where
        MsgBuilder: Fn(NodeId) -> InterNodeMessage<H>,
    {
        let config_guard = self.state.config.read().await;
        let group_size = config_guard.group_size;
        let this_node_id = config_guard.node_id;

        let mut nodes = vec![];
        for node_id in 0..group_size as NodeId {
            if !skip_self || node_id != this_node_id {
                nodes.push(node_id);
            }
        }

        self.specific_broadcast(message_builder, nodes).await
    }

    /// Timer-based operations, without a "real" node-based message implemented
    async fn timer_tick(&self) -> Result<(), QuorumOperationError> {
        match self.get_state().await {
            NodeStatus::Leading(l_state) => match l_state {
                LeaderState::ProcessingVerification(tick, args, _) => {
                    if tokio::time::Instant::now() - tick
                        >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                    {
                        info!(
                            "Verification of epoch {} timed out, reverting to base state",
                            args.epoch
                        );
                        self.mutate_state(NodeStatus::Ready).await;
                    }
                }
                LeaderState::ProcessingAddition(tick, args, _) => {
                    if tokio::time::Instant::now() - tick
                        >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                    {
                        info!(
                            "Adding node {} timed out, reverting to base state",
                            args.contact_info
                        );
                        self.mutate_state(NodeStatus::Ready).await;
                    }
                }
                LeaderState::AddingMember(tick, args, _) => {
                    if tokio::time::Instant::now() - tick
                        >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                    {
                        info!(
                            "Adding node {} timed out, reverting to base state",
                            args.contact_info
                        );
                        self.mutate_state(NodeStatus::Ready).await;
                    }
                }
                LeaderState::ProcessingRemoval(tick, args, _) => {
                    if tokio::time::Instant::now() - tick
                        >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                    {
                        info!(
                            "Removing member id {} timed out, reverting to base state",
                            args.node_id
                        );
                        self.mutate_state(NodeStatus::Ready).await;
                    }
                }
                LeaderState::RemovingMember(tick, args, _) => {
                    if tokio::time::Instant::now() - tick
                        >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                    {
                        info!(
                            "Removing member id {} timed out, reverting to base state",
                            args
                        );
                        self.mutate_state(NodeStatus::Ready).await;
                    }
                }
            },
            NodeStatus::Following(w_state) => {
                match w_state {
                    WorkerState::TestingAddMember(start_time, leader, args, _) => {
                        if tokio::time::Instant::now() - start_time
                            >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                        {
                            info!(
                                "Timeout testing a potential new member, returning \"Fail\" result to leader"
                            );
                            // Disapprove the node's addition since we couldn't contact it
                            let reply =
                                InterNodeMessage::<H>::AddNodeTestResult(AddNodeTestResult {
                                    contact_info: args.contact_info.clone(),
                                    encrypted_quorum_key_shard: None,
                                });
                            let s_reply = reply.serialize()?;
                            let nonce = self
                                .state
                                .nonce_manager
                                .get_next_outgoing_nonce(leader)
                                .await;
                            let e_msg = self.encrypt_message(leader, s_reply, nonce).await?;
                            // for this case, a "reply" will be async received
                            let _ = self.comms.send_and_maybe_receive(e_msg, None).await?;
                            self.mutate_state(NodeStatus::Following(
                                WorkerState::WaitingOnMemberAddResult(
                                    tokio::time::Instant::now(),
                                    args,
                                ),
                            ))
                            .await;
                        }
                    }
                    WorkerState::WaitingOnMemberAddResult(start_time, _) => {
                        if tokio::time::Instant::now() - start_time
                            >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                        {
                            info!("Timeout waiting on the leader to transmit shards back to the edges, reverting to base state");
                            self.mutate_state(NodeStatus::Ready).await;
                        }
                    }
                    WorkerState::TestingRemoveMember(start_time, leader, args, _) => {
                        if tokio::time::Instant::now() - start_time
                            >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                        {
                            info!("Timeout trying to remove member from the quorum. Node assumed uncontactable");
                            // approve the node removal, since we couldn't contact it
                            let reply =
                                InterNodeMessage::<H>::RemoveNodeTestResult(RemoveNodeTestResult {
                                    offending_member: args.node_id,
                                    encrypted_quorum_key_shard: Some(
                                        self.crypto.retrieve_qk_shard(leader).await?.payload,
                                    ),
                                });
                            let s_reply = reply.serialize()?;
                            let nonce = self
                                .state
                                .nonce_manager
                                .get_next_outgoing_nonce(leader)
                                .await;
                            let e_msg = self.encrypt_message(leader, s_reply, nonce).await?;
                            // for this case, a "reply" will be async received
                            let _ = self.comms.send_and_maybe_receive(e_msg, None).await?;
                            self.mutate_state(NodeStatus::Following(
                                WorkerState::WaitingOnMemberRemoveResult(
                                    tokio::time::Instant::now(),
                                    args,
                                ),
                            ))
                            .await;
                        }
                    }
                    WorkerState::WaitingOnMemberRemoveResult(start_time, _) => {
                        if tokio::time::Instant::now() - start_time
                            >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                        {
                            info!("Timeout waiting on the leader to transmit shards back to the edges, reverting to base state");
                            // Fail member removal
                            self.mutate_state(NodeStatus::Ready).await;
                        }
                    }
                    WorkerState::TestingNode(start_time, node_id, _) => {
                        if tokio::time::Instant::now() - start_time
                            >= tokio::time::Duration::from_secs(DISTRIBUTED_PROCESSING_TIMEOUT_SEC)
                        {
                            info!("Timeout waiting on the node under test to reply. Triggering node removal request");
                            self.mutate_state(NodeStatus::Ready).await;

                            // Push a request to try and remove the node in the future
                            let mut m_queue = self.state.message_queue.write().await;
                            m_queue.push(NodeMessage::Public(PublicNodeMessage::Remove(
                                RemoveMemberRequest { node_id },
                            )));
                        }
                    }
                    _ => {
                        // timer-tick ignore
                    }
                }
            }
            _ => {
                // timer-tick ignore
            }
        }
        Ok(())
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
