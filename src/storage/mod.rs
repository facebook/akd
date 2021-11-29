// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Storage module for a auditable key directory

use crate::errors::StorageError;
use crate::storage::types::{DbRecord, StorageType};
use crate::ARITY;

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::Send;

// This holds the types used in the storage layer
pub mod tests;
pub mod transaction;
pub mod types;

use crate::storage::transaction::Transaction;

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod memory;
pub mod mysql;

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

/// Represents the storage layer for the AKD (with associated configuration if necessary)
///
/// Each storage layer operation can be considered atomic (i.e. if function fails, it will not leave
/// partial state pending)
#[async_trait]
pub trait V1Storage: Clone {
    // ======= Abstract Functions ======= //

    /// Set a key/value pair in the storage layer
    async fn set(
        &self,
        pos: String,
        data_type: StorageType,
        val: &[u8],
    ) -> Result<(), StorageError>;

    /// Retrieve a value given a key from the storage layer
    async fn get(&self, pos: String, data_type: StorageType) -> Result<Vec<u8>, StorageError>;

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all(
        &self,
        data_type: StorageType,
        num: Option<usize>,
    ) -> Result<Vec<Vec<u8>>, StorageError>;

    /// Add a user state element to the associated user
    async fn append_user_state(
        &self,
        username: &types::AkdKey,
        value: &types::ValueState,
    ) -> Result<(), StorageError>;

    /// Adds user states to storage
    async fn append_user_states(
        &self,
        values: Vec<(types::AkdKey, types::ValueState)>,
    ) -> Result<(), StorageError>;

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &types::AkdKey)
        -> Result<types::KeyData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::AkdKey,
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<types::ValueState, StorageError>;

    // ========= Defined logic ========= //

    /// Store a "Storable" instance in the storage layer
    async fn store<T: Storable>(&self, key: T::Key, value: &T) -> Result<(), StorageError> {
        let k: String = hex::encode(bincode::serialize(&key).unwrap());
        match bincode::serialize(&value) {
            Err(_) => Err(StorageError::SerializationError),
            Ok(serialized) => self.set(k, T::data_type(), &serialized).await,
        }
    }

    /// Retrieve a "Storable" instance from the storage layer
    async fn retrieve<T: Storable>(&self, key: T::Key) -> Result<T, StorageError> {
        let k: String = hex::encode(bincode::serialize(&key).unwrap());
        let got = self.get(k, T::data_type()).await?;
        match bincode::deserialize(&got) {
            Err(_) => Err(StorageError::SerializationError),
            Ok(result) => Ok(result),
        }
    }

    /// Retrieve all the "Storables" in the database. (optional) Limit to "num" results
    async fn retrieve_all<T: Storable>(&self, num: Option<usize>) -> Result<Vec<T>, StorageError> {
        let got = self.get_all(T::data_type(), num).await?;
        let mut results = Vec::new();

        for item in got.into_iter() {
            match bincode::deserialize(&item) {
                Err(_) => {
                    return Err(StorageError::SerializationError);
                }
                Ok(result) => {
                    results.push(result);
                }
            }
        }

        Ok(results)
    }
}

/// Updated storage layer with better support of asynchronous work and batched operations
#[async_trait]
pub trait V2Storage: Clone {
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

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: Vec<St::Key>,
    ) -> Result<Vec<DbRecord>, StorageError>;

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all<St: Storable>(
        &self,
        num: Option<usize>,
    ) -> Result<Vec<DbRecord>, StorageError>;

    /* User data searching */

    /// Add a user state element to the associated user
    async fn append_user_state(&self, value: &types::ValueState) -> Result<(), StorageError>;

    /// Append user states to the storage medium
    async fn append_user_states(&self, values: Vec<types::ValueState>) -> Result<(), StorageError>;

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &types::AkdKey)
        -> Result<types::KeyData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::AkdKey,
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<types::ValueState, StorageError>;

    /// Retrieve all user states for the provided users (batch get user states)
    async fn get_user_states(
        &self,
        usernames: &[types::AkdKey],
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<types::AkdKey, types::ValueState>, StorageError>;

    /// Retrieve the user -> state version mapping in bulk. This is the same as get_user_states but with less data retrieved from the storage layer
    async fn get_user_state_versions(
        &self,
        keys: &[types::AkdKey],
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<types::AkdKey, u64>, StorageError>;

    /* Data Layer Builders */

    /*
    pub azks_id: [u8; 32],
    pub root: usize,
    pub latest_epoch: u64,
    pub num_nodes: usize, // The size of the tree
    _s: PhantomData<S>,
    _h: PhantomData<H>,
    */
    /// Build an azks instance from the properties
    fn build_azks(root: u64, latest_epoch: u64, num_nodes: u64) -> crate::append_only_zks::Azks {
        crate::append_only_zks::Azks {
            root,
            latest_epoch,
            num_nodes,
        }
    }

    /*
    pub azks_id: [u8; 32],
    pub label: NodeLabel,
    pub location: usize,
    pub epochs: Vec<u64>,
    pub parent: usize,
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
        location: u64,
        epochs: Vec<u64>,
        parent: u64,
        node_type: u8,
    ) -> crate::history_tree_node::HistoryTreeNode {
        crate::history_tree_node::HistoryTreeNode {
            label: crate::node_state::NodeLabel {
                val: label_val,
                len: label_len,
            },
            location,
            epochs,
            parent,
            node_type: crate::history_tree_node::NodeType::from_u8(node_type),
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
        child_states: [Option<crate::node_state::HistoryChildState>; ARITY],
        label_len: u32,
        label_val: u64,
        epoch: u64,
    ) -> crate::node_state::HistoryNodeState {
        crate::node_state::HistoryNodeState {
            value,
            child_states,
            key: crate::node_state::NodeStateKey(
                crate::node_state::NodeLabel {
                    val: label_val,
                    len: label_len,
                },
                epoch,
            ),
        }
    }

    /*
    pub(crate) plaintext_val: Values, // This needs to be the plaintext value, to discuss
    pub(crate) version: u64,          // to discuss
    pub(crate) label: NodeLabel,
    pub(crate) epoch: u64,
    */
    /// Build a user state from the properties
    fn build_user_state(
        username: String,
        plaintext_val: String,
        version: u64,
        label_len: u32,
        label_val: u64,
        epoch: u64,
    ) -> crate::storage::types::ValueState {
        crate::storage::types::ValueState {
            plaintext_val: crate::storage::types::Values(plaintext_val),
            version,
            label: crate::node_state::NodeLabel {
                val: label_val,
                len: label_len,
            },
            epoch,
            username: crate::storage::types::AkdKey(username),
        }
    }
}

/// V2Storage wrapper over a V1Storage implementation
pub struct V2FromV1StorageWrapper<S: V1Storage> {
    /// The V1Storage data layer
    pub db: S,
    trans: Transaction,
}

impl<S: V1Storage> V2FromV1StorageWrapper<S> {
    /// Instantiate a new V2->V1 Storage Wrapper instance
    pub fn new(storage: S) -> Self {
        Self {
            db: storage,
            trans: Transaction::new(),
        }
    }
}

impl<S: V1Storage> Clone for V2FromV1StorageWrapper<S> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            // transactions are not clonable (i.e. cannot be shared across or memory locations). To share a transaction, borrow the storage layer
            trans: Transaction::new(),
        }
    }
}

unsafe impl<S: V1Storage> Send for V2FromV1StorageWrapper<S> {}
unsafe impl<S: V1Storage> Sync for V2FromV1StorageWrapper<S> {}

// Auto-converter for V1Storage ->  V2Storage (i.e. auto-upgrader)
impl<S: V1Storage + Send + Sync> From<S> for V2FromV1StorageWrapper<S> {
    fn from(storage: S) -> Self {
        Self::new(storage)
    }
}

#[async_trait]
impl<S: V1Storage + Send + Sync> V2Storage for V2FromV1StorageWrapper<S> {
    /// Log some information about the cache (hit rate, etc)
    async fn log_metrics(&self, _level: log::Level) {}

    /// Start a transaction in the storage layer
    async fn begin_transaction(&mut self) -> bool {
        self.trans.begin_transaction().await
    }

    /// Commit a transaction in the storage layer
    async fn commit_transaction(&mut self) -> Result<(), StorageError> {
        // this retrieves all the trans operations, and "de-activates" the transaction flag
        let ops = self.trans.commit_transaction().await?;
        self.batch_set(ops).await
    }

    /// Rollback a transaction
    async fn rollback_transaction(&mut self) -> Result<(), StorageError> {
        self.trans.rollback_transaction().await?;
        Ok(())
    }

    /// Retrieve a flag determining if there is a transaction active
    async fn is_transaction_active(&self) -> bool {
        self.trans.is_transaction_active().await
    }

    /// V1Storage a record in the data layer
    async fn set(&self, record: DbRecord) -> Result<(), StorageError> {
        if self.is_transaction_active().await {
            self.trans.set(&record).await;
            return Ok(());
        }

        let (k, serialized, ty) = match record {
            DbRecord::Azks(azks) => (
                hex::encode(bincode::serialize(&azks.get_id()).unwrap()),
                bincode::serialize(&azks),
                StorageType::Azks,
            ),
            DbRecord::HistoryNodeState(state) => (
                hex::encode(bincode::serialize(&state.get_id()).unwrap()),
                bincode::serialize(&state),
                StorageType::HistoryNodeState,
            ),
            DbRecord::HistoryTreeNode(node) => (
                hex::encode(bincode::serialize(&node.get_id()).unwrap()),
                bincode::serialize(&node),
                StorageType::HistoryTreeNode,
            ),
            DbRecord::ValueState(state) => (
                hex::encode(bincode::serialize(&state.get_id()).unwrap()),
                bincode::serialize(&state),
                StorageType::ValueState,
            ),
        };

        match serialized {
            Err(_) => Err(StorageError::SerializationError),
            Ok(serialized) => self.db.set(k, ty, &serialized).await,
        }
    }

    async fn batch_set(&self, records: Vec<DbRecord>) -> Result<(), StorageError> {
        for record in records.into_iter() {
            self.set(record).await?
        }
        Ok(())
    }

    /// Retrieve a stored record from the data layer
    async fn get<St: Storable>(&self, id: St::Key) -> Result<DbRecord, StorageError> {
        if self.is_transaction_active().await {
            if let Some(result) = self.trans.get::<St>(&id).await {
                // there's a transacted item, return that one since it's "more up to date"
                return Ok(result);
            }
        }

        let k: String = hex::encode(bincode::serialize(&id).unwrap());
        match St::data_type() {
            StorageType::Azks => {
                let got = self.db.get(k, StorageType::Azks).await?;
                match bincode::deserialize(&got) {
                    Err(_) => Err(StorageError::SerializationError),
                    Ok(result) => Ok(DbRecord::Azks(result)),
                }
            }
            StorageType::HistoryNodeState => {
                let got = self.db.get(k, StorageType::HistoryNodeState).await?;
                match bincode::deserialize(&got) {
                    Err(_) => Err(StorageError::SerializationError),
                    Ok(result) => Ok(DbRecord::HistoryNodeState(result)),
                }
            }
            StorageType::HistoryTreeNode => {
                let got = self.db.get(k, StorageType::HistoryTreeNode).await?;
                match bincode::deserialize(&got) {
                    Err(_) => Err(StorageError::SerializationError),
                    Ok(result) => Ok(DbRecord::HistoryTreeNode(result)),
                }
            }
            StorageType::ValueState => {
                let got = self.db.get(k, StorageType::ValueState).await?;
                match bincode::deserialize(&got) {
                    Err(_) => Err(StorageError::SerializationError),
                    Ok(result) => Ok(DbRecord::ValueState(result)),
                }
            }
        }
    }

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: Vec<St::Key>,
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut map = Vec::new();
        for key in ids.into_iter() {
            map.push(self.get::<St>(key).await?);
        }
        Ok(map)
    }

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all<St: Storable>(
        &self,
        num: Option<usize>,
    ) -> Result<Vec<DbRecord>, StorageError> {
        let datatype = St::data_type();
        let got = self.db.get_all(datatype, num).await?;
        let list = got.iter().fold(Vec::new(), |mut acc, item| {
            match datatype {
                StorageType::Azks => {
                    if let Ok(item) = bincode::deserialize(item) {
                        acc.push(DbRecord::Azks(item));
                    }
                }
                StorageType::HistoryNodeState => {
                    if let Ok(item) = bincode::deserialize(item) {
                        acc.push(DbRecord::HistoryNodeState(item))
                    }
                }
                StorageType::HistoryTreeNode => {
                    if let Ok(item) = bincode::deserialize(item) {
                        acc.push(DbRecord::HistoryTreeNode(item))
                    }
                }
                StorageType::ValueState => {
                    if let Ok(item) = bincode::deserialize(item) {
                        acc.push(DbRecord::ValueState(item))
                    }
                }
            }
            acc
        });

        if self.is_transaction_active().await {
            // check transacted objects
            let mut updated = vec![];
            for item in list.into_iter() {
                match &item {
                    DbRecord::Azks(azks) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::append_only_zks::Azks>(&azks.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                    DbRecord::HistoryNodeState(state) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::node_state::HistoryNodeState>(&state.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                    DbRecord::HistoryTreeNode(node) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::history_tree_node::HistoryTreeNode>(&node.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                    DbRecord::ValueState(state) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::storage::types::ValueState>(&state.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                }
                updated.push(item);
            }
            Ok(updated)
        } else {
            Ok(list)
        }
    }

    /// Add a user state element to the associated user
    async fn append_user_state(&self, value: &types::ValueState) -> Result<(), StorageError> {
        self.set(DbRecord::ValueState(value.clone())).await
    }

    async fn append_user_states(&self, values: Vec<types::ValueState>) -> Result<(), StorageError> {
        for item in values.into_iter() {
            self.set(DbRecord::ValueState(item)).await?;
        }
        Ok(())
    }

    /// Retrieve the user data for a given user
    async fn get_user_data(
        &self,
        username: &types::AkdKey,
    ) -> Result<types::KeyData, StorageError> {
        let all = self
            .get_all::<crate::storage::types::ValueState>(None)
            .await?;
        let mut results = vec![];
        for item in all.into_iter() {
            if let DbRecord::ValueState(state) = item {
                if state.username == *username {
                    results.push(state);
                }
            }
        }
        // return ordered by epoch (from smallest -> largest)
        results.sort_by(|a, b| a.epoch.cmp(&b.epoch));

        Ok(types::KeyData { states: results })
    }

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::AkdKey,
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<types::ValueState, StorageError> {
        let intermediate = self.get_user_data(username).await?.states;
        match flag {
            types::ValueStateRetrievalFlag::MaxEpoch =>
            // retrieve by max epoch
            {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                    return Ok(value.clone());
                }
            }
            types::ValueStateRetrievalFlag::MinEpoch =>
            // retrieve by min epoch
            {
                if let Some(value) = intermediate.iter().min_by(|a, b| a.epoch.cmp(&b.epoch)) {
                    return Ok(value.clone());
                }
            }
            _ =>
            // search for specific property
            {
                let mut tracked_epoch = 0u64;
                let mut tracker = None;
                for kvp in intermediate.iter() {
                    match flag {
                        types::ValueStateRetrievalFlag::SpecificVersion(version)
                            if version == kvp.version =>
                        {
                            return Ok(kvp.clone())
                        }
                        types::ValueStateRetrievalFlag::LeqEpoch(epoch) if epoch == kvp.epoch => {
                            return Ok(kvp.clone());
                        }
                        types::ValueStateRetrievalFlag::LeqEpoch(epoch) if kvp.epoch < epoch => {
                            match tracked_epoch {
                                0u64 => {
                                    tracked_epoch = kvp.epoch;
                                    tracker = Some(kvp.clone());
                                }
                                other_epoch => {
                                    if kvp.epoch > other_epoch {
                                        tracker = Some(kvp.clone());
                                        tracked_epoch = kvp.epoch;
                                    }
                                }
                            }
                        }
                        types::ValueStateRetrievalFlag::SpecificEpoch(epoch)
                            if epoch == kvp.epoch =>
                        {
                            return Ok(kvp.clone())
                        }
                        _ => continue,
                    }
                }

                if let Some(r) = tracker {
                    return Ok(r);
                }
            }
        }
        Err(StorageError::GetError(String::from("Not found")))
    }

    async fn get_user_states(
        &self,
        usernames: &[types::AkdKey],
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<types::AkdKey, types::ValueState>, StorageError> {
        let mut map = HashMap::new();
        for username in usernames.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(types::AkdKey(result.username.0.clone()), result);
            }
        }
        Ok(map)
    }

    async fn get_user_state_versions(
        &self,
        keys: &[types::AkdKey],
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<types::AkdKey, u64>, StorageError> {
        let mut map = HashMap::new();
        for username in keys.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(types::AkdKey(result.username.0.clone()), result.version);
            }
        }
        Ok(map)
    }
}
