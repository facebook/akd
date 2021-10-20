// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use serde::{de::DeserializeOwned, Serialize};

/*
Various implementations supported by the library are imported here and usable at various checkpoints
*/
pub mod memory;
pub mod xdb;

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
        let got = storage.get(k);
        bincode::deserialize(&hex::decode(got?).unwrap()).map_err(|_| StorageError::GetError)
    }

    fn store(storage: &S, key: Self::Key, value: &Self) -> Result<(), StorageError> {
        let k = format!(
            "{}:{}",
            Self::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        storage.set(k, hex::encode(&bincode::serialize(&value).unwrap()))
    }
}

/// Represents the storage layer for SEEMless (with associated configuration if necessary)
pub trait Storage : Clone {
    /// Set a key/value pair in the storage layer
    fn set(&self, pos: String, val: String) -> Result<(), StorageError>;
    /// Retrieve a value given a key from the storage layer
    fn get(&self, pos: String) -> Result<String, StorageError>;
}

// ========= Database Tests ========== //
#[cfg(test)]
mod tests {
    use crate::storage::Storage;
    use crate::storage::memory::*;

    #[test]
    fn test_get_and_set_item() {
        // Test the various DB implementations
        let db = InMemoryDatabase::new();
        test_get_and_set_item_helper(&db);

        let db = InMemoryDbWithCache::new();
        test_get_and_set_item_helper(&db);
    }

    fn test_get_and_set_item_helper<S: Storage>(storage: &S) {

        let set_result = storage.set("key".to_string(), "value".to_string());
        assert_eq!(Ok(()), set_result);

        assert_eq!(Ok("value".to_string()), storage.get("key".to_string()));
    }

}
