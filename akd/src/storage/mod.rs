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
#[cfg(feature = "serde_serialization")]
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

#[cfg(any(test, feature = "public-tests"))]
pub mod tests;

/// Storable represents an _item_ which can be stored in the storage layer
#[cfg(feature = "serde_serialization")]
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

/// Storable represents an _item_ which can be stored in the storage layer
#[cfg(not(feature = "serde_serialization"))]
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

/// Storage layer with support for asynchronous work and batched operations
#[async_trait]
pub trait Storage: Clone {
    /// Log some information about the cache (hit rate, etc)
    async fn log_metrics(&self, level: log::Level);

    /// Start a transaction in the storage layer
    async fn begin_transaction(&self) -> bool;

    /// Commit a transaction in the storage layer
    async fn commit_transaction(&self) -> Result<(), StorageError>;

    /// Rollback a transaction
    async fn rollback_transaction(&self) -> Result<(), StorageError>;

    /// Retrieve a flag determining if there is a transaction active
    async fn is_transaction_active(&self) -> bool;

    /// Set a record in the data layer
    async fn set(&self, record: DbRecord) -> Result<(), StorageError>;

    /// Set multiple records in transactional operation
    async fn batch_set(&self, records: Vec<DbRecord>) -> Result<(), StorageError>;

    /// Retrieve a stored record from the data layer
    async fn get<St: Storable>(&self, id: &St::Key) -> Result<DbRecord, StorageError>;

    /// Retrieve a record from the data layer, ignoring any caching or transaction pending
    async fn get_direct<St: Storable>(&self, id: &St::Key) -> Result<DbRecord, StorageError>;

    /// Flush the caching of objects (if present)
    async fn flush_cache(&self);

    /// Convert the given value state's into tombstones, replacing the plaintext value with
    /// the tombstone key array
    async fn tombstone_value_states(
        &self,
        keys: &[types::ValueStateKey],
    ) -> Result<(), StorageError>;

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(&self, ids: &[St::Key])
        -> Result<Vec<DbRecord>, StorageError>;

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
        usernames: &[types::AkdLabel],
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<types::AkdLabel, (u64, types::AkdValue)>, StorageError>;
}

/// Optional storage layer utility functions for debug and test purposes
#[async_trait]
pub trait StorageUtil: Storage {
    /// Retrieves all stored records of a given type from the data layer, ignoring any caching or transaction pending
    async fn batch_get_type_direct<St: Storable>(&self) -> Result<Vec<DbRecord>, StorageError>;

    /// Retrieves all stored records from the data layer, ignoring any caching or transaction pending
    async fn batch_get_all_direct(&self) -> Result<Vec<DbRecord>, StorageError>;
}
