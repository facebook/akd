// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Storage module for a auditable key directory

use crate::append_only_zks::Azks;
use crate::errors::StorageError;
use crate::history_tree_node::{HistoryTreeNode, NodeType};
use crate::node_state::{HistoryChildState, HistoryNodeState, NodeLabel, NodeStateKey};
use crate::storage::types::{AkdLabel, AkdValue, DbRecord, StorageType, ValueState};
use crate::ARITY;

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::Send;

pub mod timed_cache;
pub mod transaction;
pub mod types;

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod memory;

pub mod tests;

/// Storable represents an _item_ which can be stored in the storage layer
pub trait Storable: Clone + Serialize + DeserializeOwned + Sync {
    /// This particular storage will have a key type
    type Key: Clone + Serialize + Eq + Hash + Send + Sync + std::fmt::Debug;

    /// Must return a valid storage type
    fn data_type() -> StorageType;

    /// Retrieve an instance of the id of this storable. The combination of the
    /// storable's StorageType and this id are _globally_ unique
    fn get_id(&self) -> Self::Key;

    /// Retrieve the full binary version of a key (for comparisons)
    fn get_full_binary_id(&self) -> Vec<u8> {
        Self::get_full_binary_key_id(&self.get_id())
    }

    /// Retrieve the full binary version of a key (for comparisons)
    fn get_full_binary_key_id(key: &Self::Key) -> Vec<u8>;

    /// Reformat a key from the full-binary specification
    fn key_from_full_binary(bin: &[u8]) -> Result<Self::Key, String>;
}

/// Updated storage layer with better support of asynchronous work and batched operations
#[async_trait]
pub trait Storage: Clone {
    /// Log some information about the cache (hit rate, etc)
    async fn log_metrics(&self, level: log::Level);

    /// Start a transaction in the storage layer
    async fn begin_transaction(&mut self) -> bool;

    /// Commit a transaction in the storage layer
    async fn commit_transaction(&mut self) -> Result<(), StorageError>;

    /// Rollback a transaction
    async fn rollback_transaction(&mut self) -> Result<(), StorageError>;

    /// Retrieve a flag determining if there is a transaction active
    async fn is_transaction_active(&self) -> bool;

    /// Set a record in the data layer
    async fn set(&self, record: DbRecord) -> Result<(), StorageError>;

    /// Set multiple records in transactional operation
    async fn batch_set(&self, records: Vec<DbRecord>) -> Result<(), StorageError>;

    /// Retrieve a stored record from the data layer
    async fn get<St: Storable>(&self, id: St::Key) -> Result<DbRecord, StorageError>;

    /// Retrieve the last epoch <= ```epoch_in_question``` where the node with ```node_key```
    /// was edited
    async fn get_epoch_lte_epoch(
        &self,
        node_label: crate::node_state::NodeLabel,
        epoch_in_question: u64,
    ) -> Result<u64, StorageError>;

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: Vec<St::Key>,
    ) -> Result<Vec<DbRecord>, StorageError>;

    /* User data searching */

    /// Retrieve the user data for a given user
    async fn get_user_data(
        &self,
        username: &types::AkdLabel,
    ) -> Result<types::KeyData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::AkdLabel,
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<types::ValueState, StorageError>;

    /// Retrieve the user -> state version mapping in bulk. This is the same as get_user_states but with less data retrieved from the storage layer
    async fn get_user_state_versions(
        &self,
        keys: &[types::AkdLabel],
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<types::AkdLabel, u64>, StorageError>;

    /* Data Layer Builders */

    /*
    pub latest_epoch: u64,
    pub num_nodes: u64, // The size of the tree
    _s: PhantomData<S>,
    _h: PhantomData<H>,
    */
    /// Build an azks instance from the properties
    fn build_azks(latest_epoch: u64, num_nodes: u64) -> Azks {
        Azks {
            latest_epoch,
            num_nodes,
        }
    }

    /*
    pub label: NodeLabel,
    pub epochs: Vec<u64>,
    pub parent: NodeLabel,
    // Just use usize and have the 0th position be empty and that can be the parent of root. This makes things simpler.
    pub node_type: NodeType,
    // Note that the NodeType along with the parent/children being options
    // allows us to use this struct to represent child and parent nodes as well.
    pub(crate) _s: PhantomData<S>,
    pub(crate) _h: PhantomData<H>,
    */
    /// Build a history tree node from the properties
    fn build_history_tree_node(
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

    /*
    pub struct NodeStateKey(pub(crate) NodeLabel, pub(crate) usize);

    pub value: Vec<u8>,
    pub child_states: Vec<HistoryChildState<H, S>>,
    */
    /// Build a history node state from the properties
    fn build_history_node_state(
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

    /*
    pub(crate) plaintext_val: AkdValue, // This needs to be the plaintext value, to discuss
    pub(crate) version: u64,          // to discuss
    pub(crate) label: NodeLabel,
    pub(crate) epoch: u64,
    */
    /// Build a user state from the properties
    fn build_user_state(
        username: Vec<u8>,
        plaintext_val: Vec<u8>,
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
