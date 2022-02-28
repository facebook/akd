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
#[cfg(feature = "serde")]
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

#[cfg(feature = "public-tests")]
pub mod tests;

/// Storable represents an _item_ which can be stored in the storage layer
#[cfg(feature = "serde")]
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

#[cfg(not(feature = "serde"))]
pub trait Storable: Clone + Sync {
    /// This particular storage will have a key type
    type Key: Clone + Eq + Hash + Send + Sync + std::fmt::Debug;

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

    /// Retrieve a record from the data layer, ignoring any caching or transaction pending
    async fn get_direct<St: Storable>(&self, id: St::Key) -> Result<DbRecord, StorageError>;

    /// Flush the caching of objects (if present)
    async fn flush_cache(&self);

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
}
