// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Various storage and representation related types

use crate::node_state::NodeLabel;
use crate::storage::Storable;
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
pub struct AkdKey(pub String);

/// The types of values used in the key-value pairs of a AKD
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

    fn get_full_binary_key_id(key: &ValueStateKey) -> Vec<u8> {
        let mut result = vec![StorageType::ValueState as u8];
        let epoch_bytes = key.1.to_be_bytes();
        for byte in &epoch_bytes {
            result.push(*byte);
        }
        let uname_bytes = key.0.as_bytes();
        for byte in uname_bytes {
            result.push(*byte);
        }

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
    Azks(crate::append_only_zks::Azks),
    /// A HistoryTreeNode
    HistoryTreeNode(crate::history_tree_node::HistoryTreeNode),
    /// A HistoryNodeState
    HistoryNodeState(crate::node_state::HistoryNodeState),
    /// The state of the value for a particular key.
    ValueState(crate::storage::types::ValueState),
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
}
