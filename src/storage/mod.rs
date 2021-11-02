// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

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
    type Key: Clone + Serialize + Eq + std::hash::Hash + Send + Sync;

    /// Must return a valid storage type
    fn data_type() -> StorageType;
}

/// Represents the storage layer for SEEMless (with associated configuration if necessary)
///
/// Each storage layer operation can be considered atomic (i.e. if function fails, it will not leave
/// partial state pending)
#[async_trait]
pub trait Storage: Clone {
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
        username: &types::Username,
        value: &types::UserState,
    ) -> Result<(), StorageError>;

    async fn append_user_states(
        &self,
        values: Vec<(types::Username, types::UserState)>,
    ) -> Result<(), StorageError>;

    /// Retrieve the user data for a given user
    async fn get_user_data(
        &self,
        username: &types::Username,
    ) -> Result<types::UserData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::Username,
        flag: types::UserStateRetrievalFlag,
    ) -> Result<types::UserState, StorageError>;

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

#[async_trait]
pub trait NewStorage: Clone {
    /// Storage a record in the data layer
    async fn set<H: Hasher + Sync + Send, St: Storable>(
        &self,
        id: St::Key,
        record: DbRecord<H>,
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

    /// Add a user state element to the associated user
    async fn append_user_state(
        &self,
        username: &types::Username,
        value: &types::UserState,
    ) -> Result<(), StorageError>;

    async fn append_user_states(
        &self,
        values: Vec<(types::Username, types::UserState)>,
    ) -> Result<(), StorageError>;

    /// Retrieve the user data for a given user
    async fn get_user_data(
        &self,
        username: &types::Username,
    ) -> Result<types::UserData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::Username,
        flag: types::UserStateRetrievalFlag,
    ) -> Result<types::UserState, StorageError>;

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
    ) -> crate::node_state::HistoryNodeState<H> {
        crate::node_state::HistoryNodeState::<H> {
            value,
            child_states,
        }
    }
}

// === NewStorage wrapper over Storage === //
pub struct NewStorageWrapper<S: Storage> {
    pub db: S,
}

impl<S: Storage> NewStorageWrapper<S> {
    pub fn new(storage: S) -> Self {
        Self {
            db: storage,
        }
    }
}

impl<S: Storage> Clone for NewStorageWrapper<S> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

unsafe impl<S: Storage> Send for NewStorageWrapper<S> {}
unsafe impl<S: Storage> Sync for NewStorageWrapper<S> {}

#[async_trait]
impl<S: Storage + Send + Sync> NewStorage for NewStorageWrapper<S> {
    /// Storage a record in the data layer
    async fn set<H: Hasher + Sync + Send, St: Storable>(
        &self,
        id: St::Key,
        record: DbRecord<H>,
    ) -> Result<(), StorageError> {
        let k: String = hex::encode(bincode::serialize(&id).unwrap());

        let serialized = match record {
            DbRecord::Azks(azks) => bincode::serialize(&azks),
            DbRecord::HistoryNodeState(state) => bincode::serialize(&state),
            DbRecord::HistoryTreeNode(node) => bincode::serialize(&node),
        };

        match serialized {
            Err(_) => Err(StorageError::SerializationError),
            Ok(serialized) => self.db.set(k, St::data_type(), &serialized).await,
        }
    }

    /// Retrieve a stored record from the data layer
    async fn get<H: Hasher + Sync + Send, St: Storable>(
        &self,
        id: St::Key,
    ) -> Result<DbRecord<H>, StorageError> {
        let k: String = hex::encode(bincode::serialize(&id).unwrap());
        match St::data_type() {
            StorageType::Azks => {
                let got = self.db.get(k, St::data_type()).await?;
                match bincode::deserialize(&got) {
                    Err(_) => Err(StorageError::SerializationError),
                    Ok(result) => Ok(DbRecord::Azks(result)),
                }
            }
            StorageType::HistoryNodeState => {
                let got = self.db.get(k, St::data_type()).await?;
                match bincode::deserialize(&got) {
                    Err(_) => Err(StorageError::SerializationError),
                    Ok(result) => Ok(DbRecord::HistoryNodeState(result)),
                }
            }
            StorageType::HistoryTreeNode => {
                let got = self.db.get(k, St::data_type()).await?;
                match bincode::deserialize(&got) {
                    Err(_) => Err(StorageError::SerializationError),
                    Ok(result) => Ok(DbRecord::HistoryTreeNode(result)),
                }
            }
        }
    }

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all<H: Hasher + Sync + Send, St: Storable>(
        &self,
        num: Option<usize>,
    ) -> Result<Vec<DbRecord<H>>, StorageError> {
        let got = self.db.get_all(St::data_type(), num).await?;
        let list = got.iter().fold(Vec::new(), |mut acc, item| {
            match St::data_type() {
                StorageType::Azks => if let Ok(item) = bincode::deserialize(item) {
                    acc.push(DbRecord::Azks(item));
                },
                StorageType::HistoryNodeState => if let Ok(item) = bincode::deserialize(item) {
                    acc.push(DbRecord::HistoryNodeState(item))
                },
                StorageType::HistoryTreeNode => if let Ok(item) = bincode::deserialize(item) {
                    acc.push(DbRecord::HistoryTreeNode(item))
                },
            }
            acc
        });
        Ok(list)
    }

    /// Add a user state element to the associated user
    async fn append_user_state(
        &self,
        username: &types::Username,
        value: &types::UserState,
    ) -> Result<(), StorageError> {
        self.db.append_user_state(username, value).await
    }

    async fn append_user_states(
        &self,
        values: Vec<(types::Username, types::UserState)>,
    ) -> Result<(), StorageError> {
        self.db.append_user_states(values).await
    }

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &types::Username) -> Result<types::UserData, StorageError> {
        self.db.get_user_data(username).await
    }

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::Username,
        flag: types::UserStateRetrievalFlag,
    ) -> Result<types::UserState, StorageError> {
        self.db.get_user_state(username, flag).await
    }
}
