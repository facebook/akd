// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::StorageError;
use serde::{de::DeserializeOwned, Serialize};

pub trait Storable<S: Storage>: Clone + Serialize + DeserializeOwned {
    type Key: Clone + Serialize + Eq + std::hash::Hash;

    /// Must return a unique String identifier for this struct
    fn identifier() -> String;

    fn retrieve(key: Self::Key) -> Result<Self, StorageError> {
        let k = format!(
            "{}:{}",
            Self::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        bincode::deserialize(&hex::decode(S::get(k)?).unwrap()).map_err(|_| StorageError::GetError)
    }

    fn store(key: Self::Key, value: &Self) -> Result<(), StorageError> {
        let k = format!(
            "{}:{}",
            Self::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        S::set(k, hex::encode(&bincode::serialize(&value).unwrap()))
    }
}

pub trait Storage {
    fn set(pos: String, val: String) -> Result<(), StorageError>;
    fn get(pos: String) -> Result<String, StorageError>;
}
