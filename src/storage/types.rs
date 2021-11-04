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
    /// ValueState
    ValueState = 4,
}

/// The keys for this key-value store
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct AkdKey(pub String);

/// The types of values used in the key-value pairs of a VKD
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct Values(pub String);

/// State for a value at a given version for that key
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValueStateKey(pub String, pub u64);

/// The state of the value for a given key, starting at a particular epoch.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct ValueState {
    pub(crate) plaintext_val: Values, // This needs to be the plaintext value, to discuss
    pub(crate) version: u64,          // to discuss
    pub(crate) label: NodeLabel,
    pub(crate) epoch: u64,
    pub(crate) username: AkdKey,
}

impl crate::storage::Storable for ValueState {
    type Key = ValueStateKey;

    fn data_type() -> StorageType {
        StorageType::ValueState
    }

    fn get_id(&self) -> ValueStateKey {
        ValueStateKey(self.username.0.clone(), self.epoch)
    }
}

impl ValueState {
    pub(crate) fn new(
        username: AkdKey,
        plaintext_val: Values,
        version: u64,
        label: NodeLabel,
        epoch: u64,
    ) -> Self {
        ValueState {
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

/// This needs to be PUBLIC public, since anyone implementing a data-layer will need
/// to be able to access this and all the internal types
pub enum DbRecord<H: Hasher + Sync + Send> {
    /// An Azks
    Azks(crate::append_only_zks::Azks<H>),
    /// A HistoryTreeNode
    HistoryTreeNode(crate::history_tree_node::HistoryTreeNode<H>),
    /// A HistoryNodeState
    HistoryNodeState(crate::node_state::HistoryNodeState<H>),
    /// The state of the value for a particular key.
    ValueState(crate::storage::types::ValueState),
}
