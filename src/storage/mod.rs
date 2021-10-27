// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use tokio::runtime::Runtime;

// This holds the types used in the storage layer
pub mod tests;
pub mod types;

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod memory;
pub mod mysql;

/// Storable represents an _item_ which can be stored in the storage layer
pub trait Storable: Clone + Serialize + DeserializeOwned {
    type Key: Clone + Serialize + Eq + std::hash::Hash + std::marker::Send;

    /// Must return a unique String identifier for this struct
    fn identifier() -> String;
}

/// Represents the storage layer for SEEMless (with associated configuration if necessary)
///
/// Each storage layer operation can be considered atomic (i.e. if function fails, it will not leave
/// partial state pending)
pub trait Storage: Clone {
    // ======= Abstract Functions ======= //

    /// Set a key/value pair in the storage layer
    fn set(&self, pos: String, val: &[u8]) -> Result<(), StorageError>;

    /// Retrieve a value given a key from the storage layer
    fn get(&self, pos: String) -> Result<Vec<u8>, StorageError>;

    /// Add a user state element to the associated user
    fn append_user_state(
        &self,
        username: &types::Username,
        value: &types::UserState,
    ) -> Result<(), StorageError>;

    fn append_user_states(
        &self,
        values: Vec<(types::Username, types::UserState)>,
    ) -> Result<(), StorageError>;

    /// Retrieve the user data for a given user
    fn get_user_data(&self, username: &types::Username) -> Result<types::UserData, StorageError>;

    /// Retrieve a specific state for a given user
    fn get_user_state(
        &self,
        username: &types::Username,
        flag: types::UserStateRetrievalFlag,
    ) -> Result<types::UserState, StorageError>;

    // ========= Defined logic ========= //

    /// Store a "Storable" instance in the storage layer
    fn store<T: Storable>(&self, key: T::Key, value: &T) -> Result<(), StorageError> {
        let k = format!(
            "{}:{}",
            T::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        let serialized =
            bincode::serialize(&value).map_err(|_| StorageError::SerializationError)?;
        self.set(k, &serialized)
    }

    /// Retrieve a "Storable" instance from the storage layer
    fn retrieve<T: Storable>(&self, key: T::Key) -> Result<T, StorageError> {
        let k = format!(
            "{}:{}",
            T::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        let got = self.get(k)?;
        bincode::deserialize(&got).map_err(|_| StorageError::SerializationError)
    }
}

/// Represents the storage layer for SEEMless (with associated configuration if necessary)
///
/// Each storage layer operation can be considered atomic (i.e. if function fails, it will not leave
/// partial state pending)
#[async_trait]
pub trait AsyncStorage: Clone {
    // ======= Abstract Functions ======= //

    /// Set a key/value pair in the storage layer
    async fn set(&self, pos: String, val: &[u8]) -> Result<(), StorageError>;

    /// Retrieve a value given a key from the storage layer
    async fn get(&self, pos: String) -> Result<Vec<u8>, StorageError>;

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
    // fn store<T: Storable>(&self, key: T::Key, value: &T) -> Result<(), StorageError> {
    fn store<T: Storable>(
        &self,
        key: T::Key,
        value: &T,
    ) -> Box<dyn std::future::Future<Output = Result<(), StorageError>> + '_> {
        let k: String = format!(
            "{}:{}",
            T::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );

        let serialized = bincode::serialize(&value).map_err(|_| StorageError::SerializationError);
        Box::new(async move {
            match serialized {
                Ok(value) => self.set(k, &value).await,
                Err(other) => Err(other),
            }
        })
    }

    /// Retrieve a "Storable" instance from the storage layer
    fn retrieve<T: Storable>(
        &self,
        key: T::Key,
    ) -> Box<dyn std::future::Future<Output = Result<T, StorageError>> + '_> {
        let k: String = format!(
            "{}:{}",
            T::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        Box::new(async move {
            let got = self.get(k).await?;
            bincode::deserialize(&got).map_err(|_| StorageError::SerializationError)
        })
    }
}

// Wrapper around asynchronous storage to a synchronous model
pub struct SynchronousStorageWrapper<S> {
    storage: S,
    runtime: Runtime,
}

impl<S: AsyncStorage> SynchronousStorageWrapper<S> {
    pub fn new(s: &S) -> Self {
        Self {
            storage: s.clone(),
            runtime: Runtime::new().unwrap(),
        }
    }
}

impl<S: AsyncStorage> Clone for SynchronousStorageWrapper<S> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            runtime: Runtime::new().unwrap(),
        }
    }
}

impl<S: AsyncStorage> Storage for SynchronousStorageWrapper<S> {
    /// Set a key/value pair in the storage layer
    fn set(&self, pos: String, val: &[u8]) -> Result<(), StorageError> {
        self.runtime.block_on(self.storage.set(pos, val))
    }

    /// Retrieve a value given a key from the storage layer
    fn get(&self, pos: String) -> Result<Vec<u8>, StorageError> {
        self.runtime.block_on(self.storage.get(pos))
    }

    /// Add a user state element to the associated user
    fn append_user_state(
        &self,
        username: &types::Username,
        value: &types::UserState,
    ) -> Result<(), StorageError> {
        self.runtime
            .block_on(self.storage.append_user_state(username, value))
    }

    fn append_user_states(
        &self,
        values: Vec<(types::Username, types::UserState)>,
    ) -> Result<(), StorageError> {
        self.runtime
            .block_on(self.storage.append_user_states(values))
    }

    /// Retrieve the user data for a given user
    fn get_user_data(&self, username: &types::Username) -> Result<types::UserData, StorageError> {
        self.runtime.block_on(self.storage.get_user_data(username))
    }

    /// Retrieve a specific state for a given user
    fn get_user_state(
        &self,
        username: &types::Username,
        flag: types::UserStateRetrievalFlag,
    ) -> Result<types::UserState, StorageError> {
        self.runtime
            .block_on(self.storage.get_user_state(username, flag))
    }
}
