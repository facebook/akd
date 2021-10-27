// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use serde::{de::DeserializeOwned, Serialize};

// This holds the types used in the storage layer
pub mod tests;
pub mod types;

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod memory;
pub mod mysql;

/// Storable represents an _item_ which can be stored in the storage layer
pub trait Storable<S: Storage>: Clone + Serialize + DeserializeOwned {
    type Key: Clone + Serialize + Eq + std::hash::Hash;

    /// Must return a unique String identifier for this struct
    fn identifier() -> String;

    fn retrieve(storage: &S, key: Self::Key) -> Result<Self, StorageError> {
        let k = format!(
            "{}:{}",
            Self::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        let got: Vec<u8> = storage.get(k)?;
        bincode::deserialize(&got).map_err(|_| StorageError::SerializationError)
    }

    fn store(storage: &S, key: Self::Key, value: &Self) -> Result<(), StorageError> {
        let k = format!(
            "{}:{}",
            Self::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        storage.set(k, &bincode::serialize(&value).unwrap())
    }
}

/// Represents the storage layer for SEEMless (with associated configuration if necessary)
///
/// Each storage layer operation can be considered atomic (i.e. if function fails, it will not leave
/// partial state pending)
pub trait Storage: Clone {
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
}
