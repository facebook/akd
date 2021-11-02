// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Storage module for a verifiable key directory

use crate::errors::StorageError;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

// This holds the types used in the storage layer
pub mod tests;
pub mod types;

// use types::{DbRecord, StorageType};
use types::StorageType;

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod memory;
pub mod mysql;

/// Storable represents an _item_ which can be stored in the storage layer
pub trait Storable: Clone + Serialize + DeserializeOwned + Sync {
    /// This particular storage will have a key type
    type Key: Clone + Serialize + Eq + std::hash::Hash + std::marker::Send;

    /// Must return a valid storage type
    fn data_type() -> StorageType;
}

/// Represents the storage layer for the VKD (with associated configuration if necessary)
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
        username: &types::VkdKey,
        value: &types::ValueState,
    ) -> Result<(), StorageError>;

    /// Adds user states to storage
    async fn append_user_states(
        &self,
        values: Vec<(types::VkdKey, types::ValueState)>,
    ) -> Result<(), StorageError>;

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &types::VkdKey)
        -> Result<types::KeyData, StorageError>;

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &types::VkdKey,
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

// #[async_trait]
// pub(crate) trait NewStorage: Clone {
//     async fn set<H, S>(&self, record: DbRecord<H, S>) -> Result<(), StorageError>;

//     async fn get<H, S>(&self, record_type: StorageType) -> Result<DbRecord<H, S>, StorageError>;
// }
