// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Various storage and representation related types

use akd_core::AzksValue;

use crate::storage::Storable;
use crate::tree_node::{TreeNode, TreeNodeType, TreeNodeWithPreviousValue};
use crate::{AkdLabel, AkdValue};
use crate::{Azks, NodeLabel};
use std::convert::TryInto;

/// Various elements that can be stored
#[derive(PartialEq, Eq, Debug, Hash, Clone, Copy)]
pub enum StorageType {
    /// Azks
    Azks = 1,
    /// TreeNode
    TreeNode = 2,
    /// EOZ: HistoryNodeState = 3 was removed from here.
    /// Better to keep ValueState = 4 as is?
    /// ValueState
    ValueState = 4,
}

/// State for a value at a given version for that key
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct ValueStateKey(pub Vec<u8>, pub u64);

/// The state of the value for a given key, starting at a particular epoch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct ValueState {
    /// The plaintext value of the user information in the directory
    pub value: AkdValue, // The actual value
    /// The version of the user's value-state
    pub version: u64,
    /// The Node Label
    pub label: NodeLabel,
    /// The epoch this value state was published in
    pub epoch: u64,
    /// The username associated to this value state (username + epoch is the record key)
    pub username: AkdLabel,
}

impl akd_core::SizeOf for ValueState {
    fn size_of(&self) -> usize {
        self.value.size_of()
            + std::mem::size_of::<u64>()
            + self.label.size_of()
            + std::mem::size_of::<u64>()
            + self.username.size_of()
    }
}

impl crate::storage::Storable for ValueState {
    type StorageKey = ValueStateKey;

    fn data_type() -> StorageType {
        StorageType::ValueState
    }

    fn get_id(&self) -> ValueStateKey {
        ValueStateKey(self.username.to_vec(), self.epoch)
    }

    fn get_full_binary_key_id(key: &ValueStateKey) -> Vec<u8> {
        let mut result = vec![StorageType::ValueState as u8];
        result.extend_from_slice(&key.1.to_be_bytes());
        result.extend_from_slice(&key.0);

        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<ValueStateKey, String> {
        if bin.len() < 10 {
            return Err("Not enough bytes to form a proper key".to_string());
        }

        if bin[0] != StorageType::ValueState as u8 {
            return Err("Not a value state key".to_string());
        }

        let epoch_bytes: [u8; 8] = bin[1..=8].try_into().expect("Slice with incorrect length");
        let epoch = u64::from_be_bytes(epoch_bytes);
        Ok(ValueStateKey(bin[9..].to_vec(), epoch))
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
            value: plaintext_val,
            version,
            label,
            epoch,
            username,
        }
    }
}

/// Data associated with a given key. That is all the states at the various epochs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
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
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[allow(clippy::large_enum_variant)]
pub enum DbRecord {
    /// An Azks
    Azks(Azks),
    /// A TreeNode
    TreeNode(TreeNodeWithPreviousValue),
    /// The state of the value for a particular key.
    ValueState(ValueState),
}

impl akd_core::SizeOf for DbRecord {
    fn size_of(&self) -> usize {
        match &self {
            DbRecord::Azks(azks) => azks.size_of(),
            DbRecord::TreeNode(node) => node.size_of(),
            DbRecord::ValueState(state) => state.size_of(),
        }
    }
}

impl Clone for DbRecord {
    fn clone(&self) -> Self {
        match &self {
            DbRecord::Azks(azks) => DbRecord::Azks(azks.clone()),
            DbRecord::TreeNode(node) => DbRecord::TreeNode(node.clone()),
            DbRecord::ValueState(state) => DbRecord::ValueState(state.clone()),
        }
    }
}

impl DbRecord {
    /// Compte a serialized id from the record's fields. This id is useful to use as key
    /// in key-value stores.
    pub fn get_full_binary_id(&self) -> Vec<u8> {
        match &self {
            DbRecord::Azks(azks) => azks.get_full_binary_id(),
            DbRecord::TreeNode(node) => node.get_full_binary_id(),
            DbRecord::ValueState(state) => state.get_full_binary_id(),
        }
    }

    /// Returns the priority in which a record type in a transaction should be committed to storage.
    /// A smaller value indicates higher priority in being written first.
    /// An Azks record should always be updated last, so that any concurrent storage readers will
    /// not see an increase in the current epoch until every other record for the new epoch has
    /// been written to storage.
    pub(crate) fn transaction_priority(&self) -> u8 {
        match &self {
            DbRecord::Azks(_) => 2,
            _ => 1,
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

    #[allow(clippy::too_many_arguments)]
    /// Build a history tree node from the properties
    pub fn build_tree_node_with_previous_value(
        label_val: [u8; 32],
        label_len: u32,
        last_epoch: u64,
        least_descendant_ep: u64,
        parent_label_val: [u8; 32],
        parent_label_len: u32,
        node_type: u8,
        left_child: Option<NodeLabel>,
        right_child: Option<NodeLabel>,
        value: crate::Digest,
        p_last_epoch: Option<u64>,
        p_least_descendant_ep: Option<u64>,
        p_parent_label_val: Option<[u8; 32]>,
        p_parent_label_len: Option<u32>,
        p_node_type: Option<u8>,
        p_left_child: Option<NodeLabel>,
        p_right_child: Option<NodeLabel>,
        p_value: Option<crate::Digest>,
    ) -> TreeNodeWithPreviousValue {
        let label = NodeLabel::new(label_val, label_len);
        let p_node = match (
            p_last_epoch,
            p_least_descendant_ep,
            p_parent_label_val,
            p_parent_label_len,
            p_node_type,
            p_value,
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => Some(TreeNode {
                label,
                last_epoch: a,
                min_descendant_epoch: b,
                parent: NodeLabel::new(c, d),
                node_type: TreeNodeType::from_u8(e),
                left_child: p_left_child,
                right_child: p_right_child,
                hash: AzksValue(f),
            }),
            _ => None,
        };
        TreeNodeWithPreviousValue {
            label,
            latest_node: TreeNode {
                label,
                last_epoch,
                min_descendant_epoch: least_descendant_ep,
                parent: NodeLabel::new(parent_label_val, parent_label_len),
                node_type: TreeNodeType::from_u8(node_type),
                left_child,
                right_child,
                hash: AzksValue(value),
            },
            previous_node: p_node,
        }
    }

    /// Build a user state from the properties
    pub fn build_user_state(
        username: Vec<u8>,
        plaintext_val: Vec<u8>,
        version: u64,
        label_len: u32,
        label_val: [u8; 32],
        epoch: u64,
    ) -> ValueState {
        ValueState {
            value: AkdValue(plaintext_val),
            version,
            label: NodeLabel::new(label_val, label_len),
            epoch,
            username: AkdLabel(username),
        }
    }
}
