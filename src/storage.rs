// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::StorageError;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;

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

    fn retrieve_cache(
        cache: &mut HashMap<Self::Key, Self>,
        key: Self::Key,
    ) -> Result<Self, StorageError> {
        match cache.get(&key) {
            None => {
                let value = Self::retrieve(key.clone())?;
                cache.insert(key, value.clone());
                Ok(value)
            }
            Some(value) => Ok(value.clone()),
        }
    }

    fn store_cache(
        cache: &mut HashMap<Self::Key, Self>,
        key: Self::Key,
        value: &Self,
    ) -> Result<(), StorageError> {
        cache.insert(key, value.clone());
        Ok(())
    }

    fn commit_cache(cache: &HashMap<Self::Key, Self>) -> Result<(), StorageError> {
        // FIXME: introduce a batch API for Storage
        for (key, value) in cache {
            Self::store(key.clone(), value)?;
        }
        Ok(())
    }
}

pub trait Storage {
    fn set(pos: String, val: String) -> Result<(), StorageError>;
    fn get(pos: String) -> Result<String, StorageError>;
}
