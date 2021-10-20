// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::collections::HashMap;
use std::sync::Mutex;
use crate::errors::StorageError;
use crate::storage::Storage;
use lazy_static::lazy_static;

// ===== Basic In-Memory database ==== //

lazy_static! {
    static ref IN_MEMORY_DB: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Debug)]
pub(crate) struct InMemoryDatabase(());

impl InMemoryDatabase {
    pub fn new () -> InMemoryDatabase {
        InMemoryDatabase(())
    }
}

impl Storage for InMemoryDatabase {
    fn set(&self, pos: String, value: String) -> Result<(), StorageError> {
        // TODO: We may not be able to do this...
        let mut hashmap = IN_MEMORY_DB.lock().unwrap();
        hashmap.insert(pos, value);
        Ok(())
    }

    fn get(&self, pos: String) -> Result<String, StorageError> {
        let hashmap = IN_MEMORY_DB.lock().unwrap();
        hashmap.get(&pos).cloned().ok_or(StorageError::GetError)
    }
}

impl Clone for InMemoryDatabase {
    fn clone(&self) -> InMemoryDatabase {
        InMemoryDatabase::new()
    }
}

// ===== In-Memory database w/caching ==== //

lazy_static! {
    static ref CACHE_DB: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref CACHE_CACHE: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref CACHE_STATS: Mutex<HashMap<String, usize>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Debug)]
pub struct InMemoryDbWithCache(());

impl InMemoryDbWithCache {
    pub fn new() -> InMemoryDbWithCache {
        InMemoryDbWithCache(())
    }

    pub fn clear_stats(&self) {
        // Flush cache to db

        let mut cache = CACHE_CACHE.lock().unwrap();

        let mut db = CACHE_DB.lock().unwrap();
        for (key, val) in cache.iter() {
            db.insert(key.clone(), val.clone());
        }

        cache.clear();

        let mut stats = CACHE_STATS.lock().unwrap();
        stats.clear();
    }

    pub fn print_stats(&self) {
        println!("Statistics collected:");
        println!("---------------------");

        let stats = CACHE_STATS.lock().unwrap();
        for (key, val) in stats.iter() {
            println!("{}: {}", key, val);
        }

        println!("---------------------");
    }

    pub fn print_hashmap_distribution(&self) {
        println!("Cache distribution of length of entries (in bytes):");
        println!("---------------------");

        let cache = CACHE_CACHE.lock().unwrap();

        let mut distribution: HashMap<usize, usize> = HashMap::new();

        for (_, val) in cache.iter() {
            let len = val.len();

            let counter = distribution.entry(len).or_insert(0);
            *counter += 1;
        }

        let mut sorted_keys: Vec<usize> = distribution.keys().cloned().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            println!("{}: {}", key, distribution[&key]);
        }
        println!("---------------------");
        println!("Cache number of elements: {}", cache.len());
        println!("---------------------");
    }

}

impl Storage for InMemoryDbWithCache {
    fn set(&self, pos: String, value: String) -> Result<(), StorageError> {
        let mut stats = CACHE_STATS.lock().unwrap();
        let calls_to_cache_set = stats.entry(String::from("calls_to_cache_set")).or_insert(0);
        *calls_to_cache_set += 1;

        let mut cache = CACHE_CACHE.lock().unwrap();
        cache.insert(pos.clone(), value.clone());

        Ok(())
    }

    fn get(&self, pos: String) -> Result<String, StorageError> {
        let mut stats = CACHE_STATS.lock().unwrap();

        let cache = &mut CACHE_CACHE.lock().unwrap();
        let calls_to_cache_get = stats.entry(String::from("calls_to_cache_get")).or_insert(0);
        *calls_to_cache_get += 1;

        match cache.get(&pos) {
            Some(value) => Ok(value.clone()),
            None => {
                let calls_to_db_get = stats.entry(String::from("calls_to_db_get")).or_insert(0);
                *calls_to_db_get += 1;

                let db = CACHE_DB.lock().unwrap();
                let value = db
                    .get(&pos)
                    .map(|v| v.clone())
                    .ok_or(StorageError::GetError)?;

                cache.insert(pos, value.clone());
                Ok(value)
            }
        }
    }
}

impl Clone for InMemoryDbWithCache {
    fn clone(&self) -> InMemoryDbWithCache {
        InMemoryDbWithCache::new()
    }
}
