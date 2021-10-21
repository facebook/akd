// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use crate::storage::Storage;
use evmap::{ReadHandle, WriteHandle};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ===== Basic In-Memory database ==== //

#[derive(Debug)]
pub struct InMemoryDatabase {
    read_handle: ReadHandle<String, String>,
    write_handle: Arc<Mutex<WriteHandle<String, String>>>,
}

impl InMemoryDatabase {
    pub fn new() -> InMemoryDatabase {
        let (reader, writer) = evmap::new();
        InMemoryDatabase {
            read_handle: reader,
            write_handle: Arc::new(Mutex::new(writer)),
        }
    }
}

impl Default for InMemoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for InMemoryDatabase {
    fn clone(&self) -> InMemoryDatabase {
        InMemoryDatabase {
            read_handle: self.read_handle.clone(),
            write_handle: self.write_handle.clone(),
        }
    }
}

impl Storage for InMemoryDatabase {
    fn set(&self, pos: String, value: String) -> Result<(), StorageError> {
        let mut hashmap = self.write_handle.lock().unwrap();
        // evmap supports multi-values, so we need to clear the value if it's present and then set the new value
        hashmap.clear(pos.clone());
        hashmap.insert(pos, value);
        hashmap.refresh();
        Ok(())
    }

    fn get(&self, pos: String) -> Result<String, StorageError> {
        if let Some(intermediate) = self.read_handle.get(&pos) {
            if let Some(output) = intermediate.get_one() {
                return Ok(output.clone());
            }
        }
        Result::Err(StorageError::GetError)
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
    pub fn new() -> Self {
        Self(())
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
        sorted_keys.sort_unstable();

        for key in sorted_keys {
            println!("{}: {}", key, distribution[&key]);
        }
        println!("---------------------");
        println!("Cache number of elements: {}", cache.len());
        println!("---------------------");
    }
}

impl Default for InMemoryDbWithCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for InMemoryDbWithCache {
    fn set(&self, pos: String, value: String) -> Result<(), StorageError> {
        let mut stats = CACHE_STATS.lock().unwrap();
        let calls_to_cache_set = stats.entry(String::from("calls_to_cache_set")).or_insert(0);
        *calls_to_cache_set += 1;

        let mut cache = CACHE_CACHE.lock().unwrap();
        cache.insert(pos, value);

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
                let value = db.get(&pos).cloned().ok_or(StorageError::GetError)?;

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
