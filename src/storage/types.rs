// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::node_state::NodeLabel;
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Hash, Clone, Copy)]
pub enum StorageType {
    Azks = 1,
    HistoryTreeNode = 2,
    HistoryNodeState = 3,
    HistoryChildState = 4,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct VkdKey(pub String);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct Values(pub String);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct UserState {
    pub(crate) plaintext_val: Values, // This needs to be the plaintext value, to discuss
    pub(crate) version: u64,          // to discuss
    pub(crate) label: NodeLabel,
    pub(crate) epoch: u64,
}

impl UserState {
    pub(crate) fn new(plaintext_val: Values, version: u64, label: NodeLabel, epoch: u64) -> Self {
        UserState {
            plaintext_val,
            version,
            label,
            epoch,
        }
    }
}

impl evmap::ShallowCopy for UserState {
    unsafe fn shallow_copy(&self) -> std::mem::ManuallyDrop<Self> {
        std::mem::ManuallyDrop::new(self.clone())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct UserData {
    pub(crate) states: Vec<UserState>,
}

pub enum UserStateRetrievalFlag {
    SpecificVersion(u64),
    SpecificEpoch(u64),
    LeqEpoch(u64),
    MaxEpoch,
    MaxVersion,
    MinEpoch,
    MinVersion,
}

// == New Data Retrieval Logic == //

// pub(crate) enum DbRecord<H, S> {
//     Azks(crate::append_only_zks::Azks<H, S>),
//     HistoryTreeNode(crate::history_tree_node::HistoryTreeNode<H, S>),
//     HistoryNodeState(crate::node_state::HistoryNodeState<H, S>),
//     HistoryChildState(crate::node_state::HistoryChildState<H, S>),
// }
