// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Various storage and representation related types

use crate::append_only_zks::Azks;
use crate::history_tree_node::{HistoryTreeNode, NodeType};
use crate::node_state::{HistoryChildState, HistoryNodeState, NodeLabel, NodeStateKey};
use crate::storage::Storable;
use crate::ARITY;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

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
pub struct AkdLabel(pub String);

/// The types of value used in the key-value pairs of a AKD
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct AkdValue(pub String);

/// State for a value at a given version for that key
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValueStateKey(pub String, pub u64);

/// The state of the value for a given key, starting at a particular epoch.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct ValueState {
    /// The plaintext value of the user information in the directory
    pub plaintext_val: AkdValue, // This needs to be the plaintext value, to discuss
    /// The version of the user's value-state
    pub version: u64, // to discuss
    /// The Node Label
    pub label: NodeLabel,
    /// The epoch this value state was published in
    pub epoch: u64,
    /// The username associated to this value state (username + epoch is the record key)
    pub username: AkdLabel,
}

impl crate::storage::Storable for ValueState {
    type Key = ValueStateKey;

    fn data_type() -> StorageType {
        StorageType::ValueState
    }

    fn get_id(&self) -> ValueStateKey {
        ValueStateKey(self.username.0.clone(), self.epoch)
    }

    fn get_full_binary_key_id(key: &ValueStateKey) -> Vec<u8> {
        let mut result = vec![StorageType::ValueState as u8];
        result.extend_from_slice(&key.1.to_be_bytes());
        result.extend_from_slice(key.0.as_bytes());

        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<ValueStateKey, String> {
        if bin.len() < 10 {
            return Err("Not enough bytes to form a proper key".to_string());
        }
        let epoch_bytes: [u8; 8] = bin[1..=8].try_into().expect("Slice with incorrect length");
        let epoch = u64::from_be_bytes(epoch_bytes);
        if let Ok(username) = std::str::from_utf8(&bin[9..]) {
            Ok(ValueStateKey(username.to_string(), epoch))
        } else {
            Err("Invalid string format".to_string())
        }
    }
}

impl ValueState {
    pub(crate) fn new(
        username: AkdLabel,
        plaintext_val: AkdValue,
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

/// Data associated with a given key. That is all the states at the various epochs
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(bound = "")]
pub struct KeyData {
    /// The vector of states of key data for a given AkdLabel
    pub states: Vec<ValueState>,
}

/// Used to retrieve a value's state, for a given key
#[derive(std::fmt::Debug, Clone, Copy)]
pub enum ValueStateRetrievalFlag {
    /// Specific version
    SpecificVersion(u64),
    /// State at particular ep
    SpecificEpoch(u64),
    /// State at epoch less than equal to given ep
    LeqEpoch(u64),
    /// State at the latest epoch
    MaxEpoch,
    /// State at the earliest epoch
    MinEpoch,
}

// == New Data Retrieval Logic == //

/// This needs to be PUBLIC public, since anyone implementing a data-layer will need
/// to be able to access this and all the internal types
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DbRecord {
    /// An Azks
    Azks(Azks),
    /// A HistoryTreeNode
    HistoryTreeNode(HistoryTreeNode),
    /// A HistoryNodeState
    HistoryNodeState(HistoryNodeState),
    /// The state of the value for a particular key.
    ValueState(ValueState),
}

impl Clone for DbRecord {
    fn clone(&self) -> Self {
        match &self {
            DbRecord::Azks(azks) => DbRecord::Azks(azks.clone()),
            DbRecord::HistoryNodeState(state) => DbRecord::HistoryNodeState(state.clone()),
            DbRecord::HistoryTreeNode(node) => DbRecord::HistoryTreeNode(node.clone()),
            DbRecord::ValueState(state) => DbRecord::ValueState(state.clone()),
        }
    }
}

impl DbRecord {
    pub(crate) fn get_full_binary_id(&self) -> Vec<u8> {
        match &self {
            DbRecord::Azks(azks) => azks.get_full_binary_id(),
            DbRecord::HistoryNodeState(state) => state.get_full_binary_id(),
            DbRecord::HistoryTreeNode(node) => node.get_full_binary_id(),
            DbRecord::ValueState(state) => state.get_full_binary_id(),
        }
    }

    /* Data Layer Builders */

    /// Build an azks instance from the properties
    pub fn build_azks(latest_epoch: u64, num_nodes: u64) -> Azks {
        Azks {
            latest_epoch,
            num_nodes,
        }
    }

    /// Build a history tree node from the properties
    pub fn build_history_tree_node(
        label_val: u64,
        label_len: u32,
        birth_epoch: u64,
        last_epoch: u64,
        parent_label_val: u64,
        parent_label_len: u32,
        node_type: u8,
    ) -> HistoryTreeNode {
        HistoryTreeNode {
            label: NodeLabel::new(label_val, label_len),
            birth_epoch,
            last_epoch,
            parent: NodeLabel::new(parent_label_val, parent_label_len),
            node_type: NodeType::from_u8(node_type),
        }
    }

    /// Build a history node state from the properties
    pub fn build_history_node_state(
        value: Vec<u8>,
        child_states: [Option<HistoryChildState>; ARITY],
        label_len: u32,
        label_val: u64,
        epoch: u64,
    ) -> HistoryNodeState {
        HistoryNodeState {
            value,
            child_states,
            key: NodeStateKey(NodeLabel::new(label_val, label_len), epoch),
        }
    }

    /// Build a history child state from the properties
    pub fn build_history_child_state(
        label_len: u32,
        label_val: u64,
        hash_val: Vec<u8>,
        epoch_version: u64,
    ) -> HistoryChildState {
        HistoryChildState {
            label: NodeLabel::new(label_val, label_len),
            hash_val,
            epoch_version,
        }
    }

    /// Build a user state from the properties
    pub fn build_user_state(
        username: String,
        plaintext_val: String,
        version: u64,
        label_len: u32,
        label_val: u64,
        epoch: u64,
    ) -> ValueState {
        ValueState {
            plaintext_val: AkdValue(plaintext_val),
            version,
            label: NodeLabel::new(label_val, label_len),
            epoch,
            username: AkdLabel(username),
        }
    }
}
