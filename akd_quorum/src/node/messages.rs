// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module defines the inter-node and external messages which the quorum handles that are
//! not defined within the AKD crate.

use crate::comms::NodeId;

// ===========================================================
// Inter node messages
// ===========================================================
pub(crate) mod inter_node {
    use akd::proof_structs::AppendOnlyProof;
    use protobuf::Message;

    use crate::comms::NodeId;
    use std::convert::TryInto;

    macro_rules! deserialize_wrapper {
        ($obj:expr) => {
            {
                let result =
                    protobuf::parse_from_bytes::<crate::proto::inter_node::InterNodeMessage>($obj).map_err(|err| {
                        crate::comms::CommunicationError::Serialization(
                            format!("Failed to deserialize inter-node message wrapper\n**Protobuf error**\n{}", err),
                        )
                    })?;
                if !result.has_message_type() {
                    return Err(crate::comms::CommunicationError::Serialization("Decoded InterNodeMessage has no message type".to_string()));
                }
                if !result.has_payload() {
                    return Err(crate::comms::CommunicationError::Serialization("Decoded InterNodeMessage has no payload".to_string()));
                }
                result
            }
        };
    }

    macro_rules! deserialize_arm_helper {
        ($obj:expr, $type:ty) => {
            {
                let result = protobuf::parse_from_bytes::<$type>($obj).map_err(|err| {
                    crate::comms::CommunicationError::Serialization(
                        format!("Failed to deserialize {} inter-node message payload\n**Protobuf error**\n{}", stringify!($type), err),
                    )
                })?;
                (&result).try_into()?
            }
        }
    }

    /// Represents the messages which could be transmitted between nodes
    #[derive(Clone)]
    pub(crate) enum InterNodeMessage<H>
    where
        H: winter_crypto::Hasher + Clone,
    {
        InterNodeAck(InterNodeAck),
        VerifyRequest(VerifyRequest<H>),
        VerifyResponse(VerifyResponse<H>),
        AddNodeInit(AddNodeInit),
        AddNodeTestResult(AddNodeTestResult),
        AddNodeResult(AddNodeResult),
        NewNodeTest(NewNodeTest<H>),
        NewNodeTestResult(NewNodeTestResult),
        RemoveNodeInit(RemoveNodeInit),
        RemoveNodeTestResult(RemoveNodeTestResult),
        RemoveNodeResult(RemoveNodeResult),
        TimerTick,
    }

    impl<H> InterNodeMessage<H>
    where
        H: winter_crypto::Hasher + Clone,
    {
        /// Try and deserialize an InterNodeMessage from raw bytes
        pub(crate) fn try_deserialize(
            bytes: Vec<u8>,
        ) -> Result<InterNodeMessage<H>, crate::comms::CommunicationError> {
            let wrapper = deserialize_wrapper!(&bytes);
            match wrapper.get_message_type() {
                crate::proto::inter_node::InterNodeMessage_MessageType::INTER_NODE_ACK => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::InterNodeAck
                    );
                    Ok(InterNodeMessage::<H>::InterNodeAck(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::VERIFY_REQUEST => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::VerifyRequest
                    );
                    Ok(InterNodeMessage::<H>::VerifyRequest(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::VERIFY_RESPONSE => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::VerifyResponse
                    );
                    Ok(InterNodeMessage::<H>::VerifyResponse(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::ADD_NODE_INIT => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::AddNodeInit
                    );
                    Ok(InterNodeMessage::<H>::AddNodeInit(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::ADD_NODE_TEST_RESULT => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::AddNodeTestResult
                    );
                    Ok(InterNodeMessage::<H>::AddNodeTestResult(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::ADD_NODE_RESULT => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::AddNodeResult
                    );
                    Ok(InterNodeMessage::<H>::AddNodeResult(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::NEW_NODE_TEST => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::NewNodeTest
                    );
                    Ok(InterNodeMessage::<H>::NewNodeTest(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::NEW_NODE_TEST_RESULT => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::NewNodeTestResult
                    );
                    Ok(InterNodeMessage::<H>::NewNodeTestResult(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::REMOVE_NODE_INIT => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::RemoveNodeInit
                    );
                    Ok(InterNodeMessage::<H>::RemoveNodeInit(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::REMOVE_NODE_TEST_RESULT => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::RemoveNodeTestResult
                    );
                    Ok(InterNodeMessage::<H>::RemoveNodeTestResult(inner))
                }
                crate::proto::inter_node::InterNodeMessage_MessageType::REMOVE_NODE_RESULT => {
                    let inner = deserialize_arm_helper!(
                        wrapper.get_payload(),
                        crate::proto::inter_node::RemoveNodeResult
                    );
                    Ok(InterNodeMessage::<H>::RemoveNodeResult(inner))
                }
                // forward compat in case proto's are added but handling logic is not updated
                #[allow(unreachable_patterns)]
                other => Err(crate::comms::CommunicationError::Serialization(format!(
                    "Value {} in an unsupported inter-node message type",
                    other as u64
                ))),
            }
        }

        pub(crate) fn serialize(self) -> Result<Vec<u8>, crate::comms::CommunicationError> {
            let (message_type, payload) = match self {
                Self::InterNodeAck(internal) => {
                    let typed: crate::proto::inter_node::InterNodeAck = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::INTER_NODE_ACK,
                        typed.write_to_bytes()?,
                    )
                }
                Self::VerifyRequest(internal) => {
                    let typed: crate::proto::inter_node::VerifyRequest = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::VERIFY_REQUEST,
                        typed.write_to_bytes()?,
                    )
                }
                Self::VerifyResponse(internal) => {
                    let typed: crate::proto::inter_node::VerifyResponse = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::VERIFY_RESPONSE,
                        typed.write_to_bytes()?,
                    )
                }
                Self::AddNodeInit(internal) => {
                    let typed: crate::proto::inter_node::AddNodeInit = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::ADD_NODE_INIT,
                        typed.write_to_bytes()?,
                    )
                }
                Self::AddNodeTestResult(internal) => {
                    let typed: crate::proto::inter_node::AddNodeTestResult = internal.try_into()?;
                    (crate::proto::inter_node::InterNodeMessage_MessageType::ADD_NODE_TEST_RESULT, typed.write_to_bytes()?)
                }
                Self::AddNodeResult(internal) => {
                    let typed: crate::proto::inter_node::AddNodeResult = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::ADD_NODE_RESULT,
                        typed.write_to_bytes()?,
                    )
                }
                Self::NewNodeTest(internal) => {
                    let typed: crate::proto::inter_node::NewNodeTest = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::NEW_NODE_TEST,
                        typed.write_to_bytes()?,
                    )
                }
                Self::NewNodeTestResult(internal) => {
                    let typed: crate::proto::inter_node::NewNodeTestResult = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::NEW_NODE_TEST_RESULT,
                        typed.write_to_bytes()?,
                    )
                }
                Self::RemoveNodeInit(internal) => {
                    let typed: crate::proto::inter_node::RemoveNodeInit = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::REMOVE_NODE_INIT,
                        typed.write_to_bytes()?,
                    )
                }
                Self::RemoveNodeTestResult(internal) => {
                    let typed: crate::proto::inter_node::RemoveNodeTestResult =
                        internal.try_into()?;
                    (crate::proto::inter_node::InterNodeMessage_MessageType::REMOVE_NODE_TEST_RESULT, typed.write_to_bytes()?)
                }
                Self::RemoveNodeResult(internal) => {
                    let typed: crate::proto::inter_node::RemoveNodeResult = internal.try_into()?;
                    (
                        crate::proto::inter_node::InterNodeMessage_MessageType::REMOVE_NODE_RESULT,
                        typed.write_to_bytes()?,
                    )
                }
                Self::TimerTick => (
                    crate::proto::inter_node::InterNodeMessage_MessageType::INTER_NODE_ACK,
                    vec![],
                ),
            };
            let mut msg = crate::proto::inter_node::InterNodeMessage::new();
            msg.set_message_type(message_type);
            msg.set_payload(payload);
            Ok(msg.write_to_bytes()?)
        }
    }

    impl<H> std::fmt::Debug for InterNodeMessage<H>
    where
        H: winter_crypto::Hasher + Clone,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InterNodeAck(_arg0) => f.debug_tuple("InterNodeAck").finish(),
                Self::VerifyRequest(_arg0) => f.debug_tuple("VerifyRequest").finish(),
                Self::VerifyResponse(_arg0) => f.debug_tuple("VerifyResponse").finish(),
                Self::AddNodeInit(_arg0) => f.debug_tuple("AddNodeInit").finish(),
                Self::AddNodeTestResult(_arg0) => f.debug_tuple("AddNodeTestResult").finish(),
                Self::AddNodeResult(_arg0) => f.debug_tuple("AddNodeResult").finish(),
                Self::NewNodeTest(_arg0) => f.debug_tuple("NewNodeTest").finish(),
                Self::NewNodeTestResult(_arg0) => f.debug_tuple("NewNodeTestResult").finish(),
                Self::RemoveNodeInit(_arg0) => f.debug_tuple("RemoveNodeInit").finish(),
                Self::RemoveNodeTestResult(_arg0) => f.debug_tuple("RemoveNodeTestResult").finish(),
                Self::RemoveNodeResult(_arg0) => f.debug_tuple("RemoveNodeResult").finish(),
                Self::TimerTick => f.debug_tuple("TimerTick").finish(),
            }
        }
    }

    // ****************************************
    // Inter node acknowledgement
    // ****************************************

    /// Represents a message which can be ack'd via
    /// an inter-node ack message (below)
    #[derive(Clone)]
    pub(crate) enum AckableMessage {
        AddNodeResult(AddNodeResult),
        RemoveNodeResult(RemoveNodeResult),
    }

    /// A basic request acknowledgement with no
    /// specific information. Helpful for replies
    /// that just require "was ok or not". Optional
    /// error message can be supplied
    #[derive(Clone)]
    pub(crate) struct InterNodeAck {
        pub(crate) ok: bool,
        pub(crate) err: Option<String>,
        pub(crate) ackd_msg: AckableMessage,
    }

    impl InterNodeAck {
        pub(crate) fn fake_ack(ok: bool, add: bool) -> Self {
            Self {
                ok,
                err: None,
                ackd_msg: match add {
                    true => AckableMessage::AddNodeResult(AddNodeResult {
                        encrypted_quorum_key_shard: None,
                        new_member: crate::storage::MemberInformation {
                            node_id: 0,
                            public_key: vec![],
                            contact_information: crate::comms::ContactInformation {
                                ip_address: "1.1.1.1".to_string(),
                                port: 80,
                            },
                        },
                    }),
                    false => AckableMessage::RemoveNodeResult(RemoveNodeResult {
                        encrypted_quorum_key_shard: None,
                        offending_member: 0,
                    }),
                },
            }
        }
    }

    // ****************************************
    // Verify a proof
    // ****************************************

    /// A request to verify a given append-only proof of the key directory
    /// initated by a leader process
    #[derive(Clone)]
    pub(crate) struct VerifyRequest<H>
    where
        H: winter_crypto::Hasher + Clone,
    {
        pub(crate) append_only_proof: akd::proof_structs::AppendOnlyProof<H>,
        pub(crate) previous_hash: H::Digest,
        pub(crate) new_hash: H::Digest,
        pub(crate) epoch: u64,
    }
    /// Response to a verification request, which if verified, includes
    /// the encrypted shard of this quorum key and the hash which was verified,
    /// encrypted with the requesting node's public key
    #[derive(Clone)]
    pub(crate) struct VerifyResponse<H>
    where
        H: winter_crypto::Hasher + Clone,
    {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
        pub(crate) verified_hash: H::Digest,
    }

    // ****************************************
    // Add a node
    // ****************************************

    /// A request to enroll a new member into the quorum. Includes
    /// the new member's public key for encrypted communications and
    /// the contact information (ip/port) for socket communcation
    #[derive(Clone)]
    pub(crate) struct AddNodeInit {
        pub(crate) public_key: Vec<u8>,
        pub(crate) contact_info: crate::comms::ContactInformation,
    }
    /// If enrollment test is successful from the edge node, this
    /// returns the quorum key shard, encrypted with the request leader's
    /// public key, which will eventually be utilized to generate
    /// new shard components and distributed to the membership
    #[derive(Clone)]
    pub(crate) struct AddNodeTestResult {
        pub(crate) contact_info: crate::comms::ContactInformation,
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
    }
    /// Request to change the quorum membership for the additional
    /// node which may have passed muster. If successful, this will
    /// contain the new encrypted quorum key shard, encrypted with
    /// the RECIPIENT's public key and additionally the new member's
    /// information
    #[derive(Clone)]
    pub(crate) struct AddNodeResult {
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
        pub(crate) new_member: crate::storage::MemberInformation,
    }

    /// The request that goes to a "new" node to verify the provided proof
    /// material. Every node has logic to handle this, however it is only
    /// required for new node testing and won't be called once the node is
    /// enrolled in a quorum membership
    #[derive(Clone)]
    pub(crate) struct NewNodeTest<H>
    where
        H: winter_crypto::Hasher,
    {
        pub(crate) requesters_public_key: Vec<u8>,
        // doesn't need reply contact information, since will simply use
        // existing TCP channel
        pub(crate) previous_hash: H::Digest,
        pub(crate) new_hash: H::Digest,
        pub(crate) test_proof: AppendOnlyProof<H>,
    }

    /// Result from the new potential node, which is being tested
    #[derive(Clone)]
    pub(crate) struct NewNodeTestResult {
        pub(crate) test_pass: bool,
    }

    // ****************************************
    // Remove a node
    // ****************************************

    /// Initiates a request to remove the specified node either due to
    /// non-compliance or non-functionality. Nodes cannot be removed upon
    /// generic request. Quorum membership can only GROW upon request, not
    /// shrink. Shrinkage only occurs on failure scenarios or detectable faults
    #[derive(Clone)]
    pub(crate) struct RemoveNodeInit {
        pub(crate) node_id: NodeId,
    }
    /// Each edge node will "test" the member to be removed, and if they deem
    /// it in non-compliance (or non-contactable), then they will return their
    /// portion of the quorum key shard, encrypted with the initiating user's
    /// public key to signify that they agree with a membership modification.
    #[derive(Clone)]
    pub(crate) struct RemoveNodeTestResult {
        pub(crate) offending_member: NodeId,
        pub(crate) encrypted_quorum_key_shard: Option<Vec<u8>>,
    }
    /// If enough nodes are unable to contact the offending member or deem the
    /// node to be non-compliant with the quorum's protocols, then new shards excluding
    /// the offending node will be generated and the offending node will be removed
    /// from the quorum computations
    #[derive(Clone)]
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
#[derive(Clone)]
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
#[derive(Clone)]
pub struct EnrollMemberRequest {
    /// The new potential node's public key
    pub public_key: Vec<u8>,
    /// The new node's open contact information to receive test information
    pub contact_information: crate::comms::ContactInformation,
}

/// Request to remove the specified member. If a quorum of other nodes can be achieved
/// which agree that the member in question should be removed (is unreachable or is
/// computing invalid proofs) then the leader can reconstruct the quorum key and regenerate
/// shards for the remaining nodes.
#[derive(Clone)]
pub struct RemoveMemberRequest {
    /// The id of the node to attempt to remove
    pub node_id: crate::comms::NodeId,
}

// ===========================================================
// Node Message
// ===========================================================

/// Public node messages which are received externally to the quorum
#[derive(Clone)]
pub enum PublicNodeMessage<H>
where
    H: winter_crypto::Hasher,
{
    /// Verify changes
    Verify(VerifyChangesRequest<H>),
    /// Enroll a member
    Enroll(EnrollMemberRequest),
    /// Remove a member
    Remove(RemoveMemberRequest),
}

#[derive(Clone)]
pub(crate) enum NodeMessage<H>
where
    H: winter_crypto::Hasher + Clone,
{
    Public(PublicNodeMessage<H>),
    Internal(NodeId, inter_node::InterNodeMessage<H>),
    TestNode,
}
