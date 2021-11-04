// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Various storage and representation related types

use crate::node_state::NodeLabel;
use serde::{Deserialize, Serialize};
use winter_crypto::Hasher;

/// Various elements that can be stored
#[derive(PartialEq, Eq, Debug, Hash, Clone, Copy)]
pub enum StorageType {
    /// Azks
    Azks = 1,
    /// HistoryTreeNode
    HistoryTreeNode = 2,
    /// HistoryNodeState
    HistoryNodeState = 3,
    // UserState
    UserState = 4,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Username(pub String);

/// The types of values used in the key-value pairs of a VKD
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct Values(pub String);


/// State for a value at a given version for that key
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserStateKey(pub String, pub u64);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct ValueState {
    pub(crate) plaintext_val: Values, // This needs to be the plaintext value, to discuss
    pub(crate) version: u64,          // to discuss
    pub(crate) label: NodeLabel,
    pub(crate) epoch: u64,
    pub(crate) username: Username,
}

impl crate::storage::Storable for UserState {
    type Key = UserStateKey;

    fn data_type() -> StorageType {
        StorageType::UserState
    }

    fn get_id(&self) -> UserStateKey {
        UserStateKey(self.username.0.clone(), self.epoch)
    }
}


impl UserState {
    pub(crate) fn new(
        username: Username,
        plaintext_val: Values,
        version: u64,
        label: NodeLabel,
        epoch: u64,
    ) -> Self {
        UserState {
            plaintext_val,
            version,
            label,
            epoch,
            username,
        }
    }
}

impl evmap::ShallowCopy for ValueState {
    unsafe fn shallow_copy(&self) -> std::mem::ManuallyDrop<Self> {
        std::mem::ManuallyDrop::new(self.clone())
    }
}

/// Data associated with a given key. That is all the states at the various epochs
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct KeyData {
    pub(crate) states: Vec<ValueState>,
}

/// Used to retrieve a value's state, for a given key
pub enum ValueStateRetrievalFlag {
    /// Specific version
    SpecificVersion(u64),
    /// State at particular ep
    SpecificEpoch(u64),
    /// State at epoch less than equal to given ep
    LeqEpoch(u64),
    /// State at the latest epoch
    MaxEpoch,
    /// State at the latest version
    MaxVersion,
    /// State at the earliest epoch
    MinEpoch,
    /// Earliest version
    MinVersion,
}

// == New Data Retrieval Logic == //

// This needs to be PUBLIC public, since anyone implementing a data-layer will need
// to be able to access this and all the internal types
pub enum DbRecord<H: Hasher + Sync + Send> {
    Azks(crate::append_only_zks::Azks<H>),
    HistoryTreeNode(crate::history_tree_node::HistoryTreeNode<H>),
    HistoryNodeState(crate::node_state::HistoryNodeState<H>),
    UserState(crate::storage::types::UserState),
}
