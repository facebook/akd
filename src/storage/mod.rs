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
        bincode::deserialize(&got).map_err(|_| StorageError::GetError)
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
pub trait Storage: Clone {
    /// Set a key/value pair in the storage layer
    fn set(&self, pos: String, val: &[u8]) -> Result<(), StorageError>;
    /// Retrieve a value given a key from the storage layer
    fn get(&self, pos: String) -> Result<Vec<u8>, StorageError>;
}

// ========= Database Tests ========== //
#[cfg(test)]
mod tests {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    use crate::storage::memory::*;
    use crate::storage::mysql::*;
    use crate::storage::Storage;

    #[test]
    fn test_get_and_set_item() {
        // Test the various DB implementations
        let db = InMemoryDatabase::new();
        test_get_and_set_item_helper(&db);

        let db = InMemoryDbWithCache::new();
        test_get_and_set_item_helper(&db);

        if MySqlDatabase::test_guard() {
            let xdb = MySqlDatabase::new(
                "localhost",
                "default",
                Option::from("root"),
                Option::from("example"),
                Option::from(8001),
            );
            test_get_and_set_item_helper(&xdb);

            // clean the test infra
            if let Err(mysql::Error::MySqlError(error)) = xdb.test_cleanup() {
                println!(
                    "ERROR: Failed to clean MySQL test database with error {}",
                    error
                );
            }
        } else {
            println!("WARN: Skipping MySQL test due to test guard noting that the docker container appears to not be running.");
        }
    }

    fn test_get_and_set_item_helper<S: Storage>(storage: &S) {
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        let value: Vec<u8> = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect::<String>()
            .as_bytes()
            .to_vec();

        let set_result = storage.set(rand_string.clone(), &value);
        assert_eq!(Ok(()), set_result);

        let storage_bytes = storage.get(rand_string);
        assert_eq!(Ok(value), storage_bytes);
    }
}
