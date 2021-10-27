// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use crate::storage::types::{UserData, UserState, UserStateRetrievalFlag, Username};
use crate::storage::Storage;
use evmap::{ReadHandle, WriteHandle};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ===== Basic In-Memory database ==== //

#[derive(Debug)]
pub struct InMemoryDatabase {
    read_handle: ReadHandle<String, Vec<u8>>,
    write_handle: Arc<Mutex<WriteHandle<String, Vec<u8>>>>,
    user_data_read_handle: ReadHandle<Username, UserState>,
    user_data_write_handle: Arc<Mutex<WriteHandle<Username, UserState>>>,
}

impl InMemoryDatabase {
    pub fn new() -> InMemoryDatabase {
        let (reader, writer) = evmap::new();
        let (user_read, user_write) = evmap::new();
        InMemoryDatabase {
            read_handle: reader,
            write_handle: Arc::new(Mutex::new(writer)),
            user_data_read_handle: user_read,
            user_data_write_handle: Arc::new(Mutex::new(user_write)),
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
            user_data_read_handle: self.user_data_read_handle.clone(),
            user_data_write_handle: self.user_data_write_handle.clone(),
        }
    }
}

impl Storage for InMemoryDatabase {
    fn set(&self, pos: String, value: &[u8]) -> Result<(), StorageError> {
        let mut hashmap = self.write_handle.lock().unwrap();
        // evmap supports multi-values, so we need to clear the value if it's present and then set the new value
        hashmap.clear(pos.clone());
        hashmap.insert(pos, value.to_vec());
        hashmap.refresh();
        Ok(())
    }

    fn get(&self, pos: String) -> Result<Vec<u8>, StorageError> {
        if let Some(intermediate) = self.read_handle.get(&pos) {
            if let Some(output) = intermediate.get_one() {
                return Ok(output.clone());
            }
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }

    fn append_user_state(
        &self,
        username: &Username,
        value: &UserState,
    ) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        hashmap.insert(username.clone(), value.clone());
        hashmap.refresh();
        Ok(())
    }

    fn append_user_states(&self, values: Vec<(Username, UserState)>) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        for kvp in values {
            hashmap.insert(kvp.0.clone(), kvp.1.clone());
        }
        hashmap.refresh();
        Ok(())
    }

    fn get_user_data(&self, username: &Username) -> Result<UserData, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            let mut results = Vec::new();
            for kvp in intermediate.iter() {
                results.push(kvp.clone());
            }
            return Ok(UserData { states: results });
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }

    fn get_user_state(
        &self,
        username: &Username,
        flag: UserStateRetrievalFlag,
    ) -> Result<UserState, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            match flag {
                UserStateRetrievalFlag::MaxEpoch =>
                // retrieve by max epoch
                {
                    if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                UserStateRetrievalFlag::MaxVersion =>
                // retrieve the max version
                {
                    if let Some(value) =
                        intermediate.iter().max_by(|a, b| a.version.cmp(&b.version))
                    {
                        return Ok(value.clone());
                    }
                }
                UserStateRetrievalFlag::MinEpoch =>
                // retrieve by min epoch
                {
                    if let Some(value) = intermediate.iter().min_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                UserStateRetrievalFlag::MinVersion =>
                // retrieve the min version
                {
                    if let Some(value) =
                        intermediate.iter().min_by(|a, b| a.version.cmp(&b.version))
                    {
                        return Ok(value.clone());
                    }
                }
                _ =>
                // search for specific property
                {
                    for kvp in intermediate.iter() {
                        match flag {
                            UserStateRetrievalFlag::SpecificVersion(version)
                                if version == kvp.version =>
                            {
                                return Ok(kvp.clone())
                            }
                            UserStateRetrievalFlag::SpecificEpoch(epoch) if epoch == kvp.epoch => {
                                return Ok(kvp.clone())
                            }
                            _ => continue,
                        }
                    }
                }
            }
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }
}

// ===== In-Memory database w/caching ==== //

lazy_static! {
    static ref CACHE_DB: Mutex<HashMap<String, Vec<u8>>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref CACHE_CACHE: Mutex<HashMap<String, Vec<u8>>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref CACHE_STATS: Mutex<HashMap<String, usize>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Debug)]
pub struct InMemoryDbWithCache {
    user_data_read_handle: ReadHandle<Username, UserState>,
    user_data_write_handle: Arc<Mutex<WriteHandle<Username, UserState>>>,
}

impl InMemoryDbWithCache {
    pub fn new() -> Self {
        let (user_read, user_write) = evmap::new();
        Self {
            user_data_read_handle: user_read,
            user_data_write_handle: Arc::new(Mutex::new(user_write)),
        }
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
    fn set(&self, pos: String, value: &[u8]) -> Result<(), StorageError> {
        let mut stats = CACHE_STATS.lock().unwrap();
        let calls_to_cache_set = stats.entry(String::from("calls_to_cache_set")).or_insert(0);
        *calls_to_cache_set += 1;

        let mut cache = CACHE_CACHE.lock().unwrap();
        cache.insert(pos, value.to_vec());

        Ok(())
    }

    fn get(&self, pos: String) -> Result<Vec<u8>, StorageError> {
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
                    .cloned()
                    .ok_or_else(|| StorageError::GetError(String::from("Not found")))?;

                cache.insert(pos, value.clone());
                Ok(value)
            }
        }
    }

    fn append_user_state(
        &self,
        username: &Username,
        value: &UserState,
    ) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        hashmap.insert(username.clone(), value.clone());
        hashmap.refresh();
        Ok(())
    }

    fn append_user_states(&self, values: Vec<(Username, UserState)>) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        for kvp in values {
            hashmap.insert(kvp.0.clone(), kvp.1.clone());
        }
        hashmap.refresh();
        Ok(())
    }

    fn get_user_data(&self, username: &Username) -> Result<UserData, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            let mut results = Vec::new();
            for kvp in intermediate.iter() {
                results.push(kvp.clone());
            }
            return Ok(UserData { states: results });
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }
    fn get_user_state(
        &self,
        username: &Username,
        flag: UserStateRetrievalFlag,
    ) -> Result<UserState, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            match flag {
                UserStateRetrievalFlag::MaxEpoch =>
                // retrieve by max epoch
                {
                    if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                UserStateRetrievalFlag::MaxVersion =>
                // retrieve the max version
                {
                    if let Some(value) =
                        intermediate.iter().max_by(|a, b| a.version.cmp(&b.version))
                    {
                        return Ok(value.clone());
                    }
                }
                UserStateRetrievalFlag::MinEpoch =>
                // retrieve by min epoch
                {
                    if let Some(value) = intermediate.iter().min_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                UserStateRetrievalFlag::MinVersion =>
                // retrieve the min version
                {
                    if let Some(value) =
                        intermediate.iter().min_by(|a, b| a.version.cmp(&b.version))
                    {
                        return Ok(value.clone());
                    }
                }
                _ =>
                // search for specific property
                {
                    for kvp in intermediate.iter() {
                        match flag {
                            UserStateRetrievalFlag::SpecificVersion(version)
                                if version == kvp.version =>
                            {
                                return Ok(kvp.clone())
                            }
                            UserStateRetrievalFlag::SpecificEpoch(epoch) if epoch == kvp.epoch => {
                                return Ok(kvp.clone())
                            }
                            _ => continue,
                        }
                    }
                }
            }
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }
}

impl Clone for InMemoryDbWithCache {
    fn clone(&self) -> InMemoryDbWithCache {
        InMemoryDbWithCache::new()
    }
}
