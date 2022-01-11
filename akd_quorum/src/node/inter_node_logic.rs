// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module is the specific message handling logic for the different message inter-node
//! messages

use std::collections::HashMap;

use crate::comms::NodeId;
use crate::node::messages::inter_node::*;
use crate::QuorumOperationError;

/// The states and state memory
pub(crate) enum NodeStates<H>
where
    H: winter_crypto::Hasher,
{
    /// (ALL) Ready for anything
    Ready,

    /// (LEADER) Beginning verification (request args)
    StartVerficiation(VerifyRequest<H>), // Next = WaitingEdgeVerficiation

    /// (WORKER) Processing a verification (leader, request args)
    ProcessingVerification(NodeId, VerifyRequest<H>), // Next = Ready

    /// (LEADER) Waiting on edge verifications (request args, including self-verification)
    WaitingEdgeVerifications(VerifyRequest<H>, HashMap<NodeId, Option<VerifyResponse<H>>>), // Next = SignatureGeneration

    /// (LEADER) Generating signatures (request args, the list of nodes who agreed | the
    /// list of nodes who didn't agree | nodes who didn't respond and should be
    /// attempted to be removed)
    SignatureGeneration(VerifyRequest<H>, Vec<NodeId>, Vec<NodeId>, Vec<NodeId>), // Next = Ready

    /// (LEADER) Initialization of new member flow (node public key & contact information)
    StartAddingMember(AddNodeInit), // Next = WaitingEdgeMemberTests

    /// (WORKER) Member is processing the potential to add a new member
    /// 1. Node is contactable
    /// 2. Node correctly performs a validation
    ProcessingMemberAddition(AddNodeInit),
    // TODO:
}

fn handle_message<H>(message: InterNodeMessage<H>) -> Result<(), QuorumOperationError>
where
    H: winter_crypto::Hasher,
{
    match message {
        InterNodeMessage::InterNodeAck(inter_node_ack) => {}
        InterNodeMessage::VerifyRequest(verify_request) => {}
        InterNodeMessage::VerifyResponse(verify_response) => {}
        InterNodeMessage::AddNodeInit(add_node_inint) => {}
        InterNodeMessage::AddNodeTestResult(add_node_test_result) => {}
        InterNodeMessage::AddNodeResult(add_node_result) => {}
        InterNodeMessage::RemoveNodeInit(remove_node_init) => {}
        InterNodeMessage::RemoveNodeTestResult(remove_node_test_result) => {}
        InterNodeMessage::RemoveNodeResult(remove_node_result) => {}
        _ => unimplemented!(),
    }
    Ok(())
}
