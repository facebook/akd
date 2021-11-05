// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Storage module for a auditable key directory

use crate::errors::StorageError;
use crate::storage::types::{DbRecord, StorageType};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::marker::{PhantomData, Send};
use winter_crypto::Hasher;

// This holds the types used in the storage layer
pub mod tests;
pub mod types;

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod memory;
pub mod mysql;

/// Storable represents an _item_ which can be stored in the storage layer
pub trait Storable: Clone + Serialize + DeserializeOwned + Sync {
    /// This particular storage will have a key type
    type Key: Clone + Serialize + Eq + std::hash::Hash + Send + Sync;

    /// Must return a valid storage type
    fn data_type() -> StorageType;

    /// FIXME: Needs docs
    fn get_id(&self) -> Self::Key;
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

/// FIXME: Needs docs
#[async_trait]
pub trait V2Storage: Clone {
    /// V1Storage a record in the data layer
    async fn set<H: Hasher + Sync + Send>(&self, record: DbRecord<H>) -> Result<(), StorageError>;

    /// Set multiple records in transactional operation
    async fn batch_set<H: Hasher + Sync + Send>(
        &self,
        records: Vec<DbRecord<H>>,
    ) -> Result<(), StorageError>;

    /// Retrieve a stored record from the data layer
    async fn get<H: Hasher + Sync + Send, St: Storable>(
        &self,
        id: St::Key,
    ) -> Result<DbRecord<H>, StorageError>;

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all<H: Hasher + Sync + Send, St: Storable>(
        &self,
        num: Option<usize>,
    ) -> Result<Vec<DbRecord<H>>, StorageError>;

    /* User data searching */

    /// Add a user state element to the associated user
    async fn append_user_state<H: Hasher + Sync + Send>(
        &self,
        value: &types::ValueState,
    ) -> Result<(), StorageError>;

    /// Adds user states
    async fn append_user_states<H: Hasher + Sync + Send>(
        &self,
        values: Vec<types::ValueState>,
    ) -> Result<(), StorageError>;

    /// Retrieve the user data for a given user
    async fn get_user_data<H: Hasher + Sync + Send>(
        &self,
        username: &types::AkdKey,
    ) -> Result<types::KeyData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state<H: Hasher + Sync + Send>(
        &self,
        username: &types::AkdKey,
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<types::ValueState, StorageError>;

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
    fn build_azks<H>(
        root: usize,
        latest_epoch: u64,
        num_nodes: usize,
    ) -> crate::append_only_zks::Azks<H> {
        crate::append_only_zks::Azks::<H> {
            root,
            latest_epoch,
            num_nodes,
            _h: PhantomData,
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
    fn build_history_tree_node<H>(
        label_val: u64,
        label_len: u32,
        location: usize,
        epochs: Vec<u64>,
        parent: usize,
        node_type: u8,
    ) -> crate::history_tree_node::HistoryTreeNode<H> {
        crate::history_tree_node::HistoryTreeNode::<H> {
            label: crate::node_state::NodeLabel {
                val: label_val,
                len: label_len,
            },
            location,
            epochs,
            parent,
            node_type: crate::history_tree_node::NodeType::from_u8(node_type),
            _h: PhantomData,
        }
    }

    /*HistoryNodeState(crate::node_state::HistoryNodeState<H, S>),*/

    // /*
    // pub dummy_marker: DummyChildState,
    // pub location: usize,
    // pub label: NodeLabel,
    // pub hash_val: Vec<u8>,
    // pub epoch_version: u64,
    // pub(crate) _h: PhantomData<H>,
    // pub(crate) _s: PhantomData<S>,
    // */
    // /// Build a history child state from the properties
    // fn build_history_child_state<H>(dummy_marker: u8, location: usize, label_val: u64, label_len: u32, hash_val: Vec<u8>, epoch_version: u64)
    // -> crate::node_state::HistoryChildState::<H> {
    //     crate::node_state::HistoryChildState::<H> {
    //         dummy_marker: crate::node_state::DummyChildState::from_u8(dummy_marker),
    //         location,
    //         label: crate::node_state::NodeLabel { val: label_val, len: label_len },
    //         hash_val,
    //         epoch_version,
    //         _h: PhantomData,
    //     }
    // }

    /*
    pub struct NodeStateKey(pub(crate) NodeLabel, pub(crate) usize);

    pub value: Vec<u8>,
    pub child_states: Vec<HistoryChildState<H, S>>,
    */
    /// Build a history node state from the properties
    fn build_history_node_state<H>(
        value: Vec<u8>,
        child_states: Vec<crate::node_state::HistoryChildState<H>>,
        label_len: u32,
        label_val: u64,
        epoch: u64,
    ) -> crate::node_state::HistoryNodeState<H> {
        crate::node_state::HistoryNodeState::<H> {
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

// ===  V2Storage wrapper over V1Storage === //
/// FIXME: needs docs
pub struct V2FromV1StorageWrapper<S: V1Storage> {
    /// FIXME: Needs docs
    pub db: S,
}

impl<S: V1Storage> V2FromV1StorageWrapper<S> {
    /// FIXME: Needs docs
    pub fn new(storage: S) -> Self {
        Self { db: storage }
    }
}

impl<S: V1Storage> Clone for V2FromV1StorageWrapper<S> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
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
    /// V1Storage a record in the data layer
    async fn set<H: Hasher + Sync + Send>(&self, record: DbRecord<H>) -> Result<(), StorageError> {
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

    async fn batch_set<H: Hasher + Sync + Send>(
        &self,
        records: Vec<DbRecord<H>>,
    ) -> Result<(), StorageError> {
        for record in records.into_iter() {
            self.set::<H>(record).await?
        }
        Ok(())
    }

    /// Retrieve a stored record from the data layer
    async fn get<H: Hasher + Sync + Send, St: Storable>(
        &self,
        id: St::Key,
    ) -> Result<DbRecord<H>, StorageError> {
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

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all<H: Hasher + Sync + Send, St: Storable>(
        &self,
        num: Option<usize>,
    ) -> Result<Vec<DbRecord<H>>, StorageError> {
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
        Ok(list)
    }

    /// Add a user state element to the associated user
    async fn append_user_state<H: Hasher + Sync + Send>(
        &self,
        value: &types::ValueState,
    ) -> Result<(), StorageError> {
        self.set::<H>(DbRecord::ValueState(value.clone())).await
    }

    async fn append_user_states<H: Hasher + Sync + Send>(
        &self,
        values: Vec<types::ValueState>,
    ) -> Result<(), StorageError> {
        for item in values.into_iter() {
            self.set::<H>(DbRecord::ValueState(item)).await?;
        }
        Ok(())
    }

    /// Retrieve the user data for a given user
    async fn get_user_data<H: Hasher + Sync + Send>(
        &self,
        username: &types::AkdKey,
    ) -> Result<types::KeyData, StorageError> {
        let all = self
            .get_all::<H, crate::storage::types::ValueState>(None)
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
    async fn get_user_state<H: Hasher + Sync + Send>(
        &self,
        username: &types::AkdKey,
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<types::ValueState, StorageError> {
        let intermediate = self.get_user_data::<H>(username).await?.states;
        match flag {
            types::ValueStateRetrievalFlag::MaxEpoch =>
            // retrieve by max epoch
            {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                    return Ok(value.clone());
                }
            }
            types::ValueStateRetrievalFlag::MaxVersion =>
            // retrieve the max version
            {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.version.cmp(&b.version)) {
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
            types::ValueStateRetrievalFlag::MinVersion =>
            // retrieve the min version
            {
                if let Some(value) = intermediate.iter().min_by(|a, b| a.version.cmp(&b.version)) {
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
}
