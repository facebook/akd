// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module is the specific message handling logic for the different message inter-node
//! messages

use crate::comms::NodeId;
use crate::node::messages::inter_node::*;

use std::collections::HashMap;

/// The states a leader goes through
#[derive(Clone)]
pub(crate) enum LeaderState<H>
where
    H: winter_crypto::Hasher + Clone,
{
    // ================================
    // Verification States
    // ================================
    /// Processing a verification, waiting on responses. Args: (start_time, request, test_results)
    ProcessingVerification(
        tokio::time::Instant,
        VerifyRequest<H>,
        HashMap<NodeId, Option<VerifyResponse<H>>>,
    ), // NEXT = N/A

    // ================================
    // Member addition states
    // ================================
    /// Waiting on the "votes" from the workers on whether the node can be added to the quorum. Args: (start_time, request, test_results)
    ProcessingAddition(
        tokio::time::Instant,
        AddNodeInit,
        HashMap<NodeId, AddNodeTestResult>,
    ), // NEXT = AddingMember

    /// New encrypted shards to be transmitted to the edges. Args: (start_time, request, new_crypto_shards)
    AddingMember(
        tokio::time::Instant,
        AddNodeInit,
        HashMap<NodeId, crate::crypto::EncryptedQuorumKeyShard>,
    ), // NEXT = N/A

    // ================================
    // Member removal states
    // ================================
    /// Waiting on the "votes" from the workers whether the node should be removed from the quorum. Args: (start_time, request, test_results)
    ProcessingRemoval(
        tokio::time::Instant,
        RemoveNodeInit,
        HashMap<NodeId, RemoveNodeTestResult>,
    ), // NEXT = RemovingMember

    /// Removing a member from the quorum, transmitting the new shards to the edge. Args: (start_time, node_to_remove, new_crypto_shards)
    RemovingMember(
        tokio::time::Instant,
        NodeId,
        HashMap<NodeId, crate::crypto::EncryptedQuorumKeyShard>,
    ), // NEXT = N/A
}

/// The states a quorum worker (non-leader) goes through
#[derive(Clone)]
pub(crate) enum WorkerState<H>
where
    H: winter_crypto::Hasher + Clone,
{
    /// Verifying an AKD change. Args: (leader, request)
    Verifying(NodeId, VerifyRequest<H>), // NEXT = N/A

    /// Testing a member for an addition operation. Args: (start_time, leader, member info)
    TestingAddMember(tokio::time::Instant, NodeId, AddNodeInit, bool), // NEXT = WaitingOnMemberAddResult

    /// Waiting on the addition result from the leader. Args: (start_time, request)
    WaitingOnMemberAddResult(tokio::time::Instant, AddNodeInit), // NEXT = N/A

    /// Testing a member for a removal operation. Args: (start_time, leader, member info)
    TestingRemoveMember(tokio::time::Instant, NodeId, RemoveNodeInit, bool), // NEXT = WaitingOnMemberRemoveResult

    /// Waiting on the removal result from the leader. Args: (start_time, request)
    WaitingOnMemberRemoveResult(tokio::time::Instant, RemoveNodeInit), // NEXT = N/A

    /// Testing another node, not for addition or removal, but in the regular process
    /// (start_time, node_under_test, should_test_pass)
    TestingNode(tokio::time::Instant, NodeId, bool),
}

/// The status of a node
#[derive(Clone)]
pub(crate) enum NodeStatus<H>
where
    H: winter_crypto::Hasher + Clone,
{
    /// (ALL) Ready for anything
    Ready,

    /// Node is "leading" an operation
    Leading(LeaderState<H>),

    /// Node is a worker in an operation
    Following(WorkerState<H>),
}
