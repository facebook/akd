// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Storage module for a auditable key directory

use crate::errors::StorageError;
use crate::storage::types::{DbRecord, StorageType};
use crate::{AkdLabel, AkdValue};

use async_trait::async_trait;
#[cfg(feature = "serde_serialization")]
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::{Send, Sync};

pub mod cache;
pub mod transaction;
pub mod types;

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod manager;
pub mod memory;

pub use manager::StorageManager;

#[cfg(any(test, feature = "public_tests"))]
pub mod tests;

/// Denotes the "state" when a batch_set is being called in the data layer
pub enum DbSetState {
    /// Being called as part of a transaction commit operation
    TransactionCommit,
    /// Being called as a general, in-line operation
    General,
}

/// Storable represents an _item_ which can be stored in the storage layer
#[cfg(feature = "serde_serialization")]
pub trait Storable: Clone + Serialize + DeserializeOwned + Sync + 'static {
    /// This particular storage will have a key type
    type StorageKey: Clone + Serialize + Eq + Hash + Send + Sync + std::fmt::Debug;

    /// Must return a valid storage type
    fn data_type() -> StorageType;

    /// Retrieve an instance of the id of this storable. The combination of the
    /// storable's StorageType and this id are _globally_ unique
    fn get_id(&self) -> Self::StorageKey;

    /// Retrieve the full binary version of a key (for comparisons)
    fn get_full_binary_id(&self) -> Vec<u8> {
        Self::get_full_binary_key_id(&self.get_id())
    }

    /// Retrieve the full binary version of a key (for comparisons)
    fn get_full_binary_key_id(key: &Self::StorageKey) -> Vec<u8>;

    /// Reformat a key from the full-binary specification
    fn key_from_full_binary(bin: &[u8]) -> Result<Self::StorageKey, String>;
}

/// Storable represents an _item_ which can be stored in the storage layer
#[cfg(not(feature = "serde_serialization"))]
pub trait Storable: Clone + Sync + 'static {
    /// This particular storage will have a key type
    type StorageKey: Clone + Eq + Hash + Send + Sync + std::fmt::Debug;

    /// Must return a valid storage type
    fn data_type() -> StorageType;

    /// Retrieve an instance of the id of this storable. The combination of the
    /// storable's StorageType and this id are _globally_ unique
    fn get_id(&self) -> Self::StorageKey;

    /// Retrieve the full binary version of a key (for comparisons)
    fn get_full_binary_id(&self) -> Vec<u8> {
        Self::get_full_binary_key_id(&self.get_id())
    }

    /// Retrieve the full binary version of a key (for comparisons)
    fn get_full_binary_key_id(key: &Self::StorageKey) -> Vec<u8>;

    /// Reformat a key from the full-binary specification
    fn key_from_full_binary(bin: &[u8]) -> Result<Self::StorageKey, String>;
}

/// A database implementation backing storage for the AKD
#[async_trait]
pub trait Database: Send + Sync {
    /// Set a record in the database
    async fn set(&self, record: DbRecord) -> Result<(), StorageError>;

    /// Set multiple records in the database with a minimal set of operations
    async fn batch_set(
        &self,
        records: Vec<DbRecord>,
        state: DbSetState,
    ) -> Result<(), StorageError>;

    /// Retrieve a stored record from the database
    async fn get<St: Storable>(&self, id: &St::StorageKey) -> Result<DbRecord, StorageError>;

    /// Retrieve a batch of records by id from the database
    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::StorageKey],
    ) -> Result<Vec<DbRecord>, StorageError>;

    /* User data searching */

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &AkdLabel) -> Result<types::KeyData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<types::ValueState, StorageError>;

    /// Retrieve the user -> state version mapping in bulk. This is the same as get_user_states but with less data retrieved from the storage layer
    async fn get_user_state_versions(
        &self,
        usernames: &[AkdLabel],
        flag: types::ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError>;
}

/// Optional storage layer utility functions for debug and test purposes
#[async_trait]
pub trait StorageUtil: Database {
    /// Retrieves all stored records of a given type from the data layer, ignoring any caching or transaction pending
    async fn batch_get_type_direct<St: Storable>(&self) -> Result<Vec<DbRecord>, StorageError>;

    /// Retrieves all stored records from the data layer, ignoring any caching or transaction pending
    async fn batch_get_all_direct(&self) -> Result<Vec<DbRecord>, StorageError>;
}
