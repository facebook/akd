// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.
//! This module contains various memory representations.
use crate::errors::StorageError;
use crate::storage::types::{AkdKey, KeyData, StorageType, ValueState, ValueStateRetrievalFlag};
use crate::storage::V1Storage;
use async_trait::async_trait;
use evmap::{ReadHandle, WriteHandle};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub mod newdb;

// ===== Basic In-Memory database ==== //

/// This struct represents a basic in-memory database.
#[derive(Debug)]
pub struct AsyncInMemoryDatabase {
    #[allow(clippy::type_complexity)]
    read_handle: ReadHandle<(StorageType, String), Vec<u8>>,
    #[allow(clippy::type_complexity)]
    write_handle: Arc<Mutex<WriteHandle<(StorageType, String), Vec<u8>>>>,
    user_data_read_handle: ReadHandle<AkdKey, ValueState>,
    user_data_write_handle: Arc<Mutex<WriteHandle<AkdKey, ValueState>>>,
}

unsafe impl Send for AsyncInMemoryDatabase {}
unsafe impl Sync for AsyncInMemoryDatabase {}

impl AsyncInMemoryDatabase {
    /// Creates a new in memory db
    pub fn new() -> Self {
        let (reader, writer) = evmap::new();
        let (user_read, user_write) = evmap::new();
        Self {
            read_handle: reader,
            write_handle: Arc::new(Mutex::new(writer)),
            user_data_read_handle: user_read,
            user_data_write_handle: Arc::new(Mutex::new(user_write)),
        }
    }
}

impl Default for AsyncInMemoryDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AsyncInMemoryDatabase {
    fn clone(&self) -> Self {
        Self {
            read_handle: self.read_handle.clone(),
            write_handle: self.write_handle.clone(),
            user_data_read_handle: self.user_data_read_handle.clone(),
            user_data_write_handle: self.user_data_write_handle.clone(),
        }
    }
}

#[async_trait]
impl V1Storage for AsyncInMemoryDatabase {
    async fn set(&self, pos: String, dt: StorageType, value: &[u8]) -> Result<(), StorageError> {
        let mut hashmap = self.write_handle.lock().unwrap();
        // evmap supports multi-values, so we need to clear the value if it's present and then set the new value
        hashmap.clear((dt, pos.clone()));
        hashmap.insert((dt, pos), value.to_vec());
        hashmap.refresh();
        Ok(())
    }

    async fn get(&self, pos: String, dt: StorageType) -> Result<Vec<u8>, StorageError> {
        if let Some(intermediate) = self.read_handle.get(&(dt, pos)) {
            if let Some(output) = intermediate.get_one() {
                return Ok(output.clone());
            }
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }

    async fn get_all(
        &self,
        data_type: StorageType,
        num: Option<usize>,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut results = Vec::new();
        if let Some(handle) = &self.read_handle.read() {
            for item in handle {
                let ((dt, _pos), v) = item;
                if *dt == data_type {
                    if let Some(output) = v.get_one() {
                        results.push(output.clone());
                        if let Some(limit) = num {
                            if results.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(results)
    }

    async fn append_user_state(
        &self,
        username: &AkdKey,
        value: &ValueState,
    ) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        hashmap.insert(username.clone(), value.clone());
        hashmap.refresh();
        Ok(())
    }

    async fn append_user_states(
        &self,
        values: Vec<(AkdKey, ValueState)>,
    ) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        for kvp in values {
            hashmap.insert(kvp.0.clone(), kvp.1.clone());
        }
        hashmap.refresh();
        Ok(())
    }

    async fn get_user_data(&self, username: &AkdKey) -> Result<KeyData, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            let mut results = Vec::new();
            for kvp in intermediate.iter() {
                results.push(kvp.clone());
            }
            return Ok(KeyData { states: results });
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }

    async fn get_user_state(
        &self,
        username: &AkdKey,
        flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            match flag {
                ValueStateRetrievalFlag::MaxEpoch =>
                // retrieve by max epoch
                {
                    if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                ValueStateRetrievalFlag::MaxVersion =>
                // retrieve the max version
                {
                    if let Some(value) =
                        intermediate.iter().max_by(|a, b| a.version.cmp(&b.version))
                    {
                        return Ok(value.clone());
                    }
                }
                ValueStateRetrievalFlag::MinEpoch =>
                // retrieve by min epoch
                {
                    if let Some(value) = intermediate.iter().min_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                ValueStateRetrievalFlag::MinVersion =>
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
                    let mut tracked_epoch = 0u64;
                    let mut tracker = None;
                    for kvp in intermediate.iter() {
                        match flag {
                            ValueStateRetrievalFlag::SpecificVersion(version)
                                if version == kvp.version =>
                            {
                                return Ok(kvp.clone())
                            }
                            ValueStateRetrievalFlag::LeqEpoch(epoch) if epoch == kvp.epoch => {
                                return Ok(kvp.clone());
                            }
                            ValueStateRetrievalFlag::LeqEpoch(epoch) if kvp.epoch < epoch => {
                                match tracked_epoch {
                                    0u64 => {
                                        tracked_epoch = kvp.epoch;
                                        tracker = Some(kvp.clone());
                                    }
                                    other_epoch => {
                                        if kvp.epoch > other_epoch {
                                            tracker = Some(kvp.clone());
                                            tracked_epoch = kvp.epoch;
                                        }
                                    }
                                }
                            }
                            ValueStateRetrievalFlag::SpecificEpoch(epoch) if epoch == kvp.epoch => {
                                return Ok(kvp.clone())
                            }
                            _ => continue,
                        }
                    }

                    if let Some(r) = tracker {
                        return Ok(r);
                    }
                }
            }
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }
}

// ===== In-Memory database w/caching ==== //

lazy_static! {
    static ref CACHE_DB: Mutex<HashMap<(StorageType, String), Vec<u8>>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref CACHE_CACHE: Mutex<HashMap<(StorageType, String), Vec<u8>>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref CACHE_STATS: Mutex<HashMap<String, usize>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

/// An in memory database with a cache, so serialization is done fewer times.
#[derive(Debug)]
pub struct AsyncInMemoryDbWithCache {
    user_data_read_handle: ReadHandle<AkdKey, ValueState>,
    user_data_write_handle: Arc<Mutex<WriteHandle<AkdKey, ValueState>>>,
}

unsafe impl Send for AsyncInMemoryDbWithCache {}
unsafe impl Sync for AsyncInMemoryDbWithCache {}

impl AsyncInMemoryDbWithCache {
    /// Creates a new in memory db with a cache
    pub fn new() -> Self {
        let (user_read, user_write) = evmap::new();
        Self {
            user_data_read_handle: user_read,
            user_data_write_handle: Arc::new(Mutex::new(user_write)),
        }
    }

    /// Flushes the cache and clearn any associated stats
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

    /// Prints db states
    pub fn print_stats(&self) {
        println!("Statistics collected:");
        println!("---------------------");

        let stats = CACHE_STATS.lock().unwrap();
        for (key, val) in stats.iter() {
            println!("{:?}: {}", key, val);
        }

        println!("---------------------");
    }

    /// Prints the distribution of the lengths of entries in a db
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

impl Default for AsyncInMemoryDbWithCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AsyncInMemoryDbWithCache {
    fn clone(&self) -> Self {
        Self {
            user_data_read_handle: self.user_data_read_handle.clone(),
            user_data_write_handle: self.user_data_write_handle.clone(),
        }
    }
}

#[async_trait]
impl V1Storage for AsyncInMemoryDbWithCache {
    async fn set(&self, pos: String, dt: StorageType, value: &[u8]) -> Result<(), StorageError> {
        let mut stats = CACHE_STATS.lock().unwrap();
        let calls_to_cache_set = stats.entry(String::from("calls_to_cache_set")).or_insert(0);
        *calls_to_cache_set += 1;

        let mut cache = CACHE_CACHE.lock().unwrap();
        cache.insert((dt, pos), value.to_vec());

        Ok(())
    }

    async fn get(&self, pos: String, dt: StorageType) -> Result<Vec<u8>, StorageError> {
        let mut stats = CACHE_STATS.lock().unwrap();

        let cache = &mut CACHE_CACHE.lock().unwrap();
        let calls_to_cache_get = stats.entry(String::from("calls_to_cache_get")).or_insert(0);
        *calls_to_cache_get += 1;

        match cache.get(&(dt, pos.clone())) {
            Some(value) => Ok(value.clone()),
            None => {
                let calls_to_db_get = stats.entry(String::from("calls_to_db_get")).or_insert(0);
                *calls_to_db_get += 1;

                let db = CACHE_DB.lock().unwrap();
                let value = db
                    .get(&(dt, pos.clone()))
                    .cloned()
                    .ok_or_else(|| StorageError::GetError(String::from("Not found")))?;

                cache.insert((dt, pos), value.clone());
                Ok(value)
            }
        }
    }

    async fn get_all(
        &self,
        data_type: StorageType,
        num: Option<usize>,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let cache = CACHE_CACHE.lock().unwrap();
        let db = CACHE_DB.lock().unwrap();

        let mut hashmap: HashMap<String, Vec<u8>> = HashMap::new();
        // go through the cache first
        for (key, v) in &*cache {
            if key.0 == data_type && !hashmap.contains_key(&key.1) {
                hashmap.insert(key.1.clone(), v.clone());
                if let Some(limit) = num {
                    if hashmap.keys().len() >= limit {
                        break;
                    }
                }
            }
        }
        for (key, v) in &*db {
            if key.0 == data_type && !hashmap.contains_key(&key.1) {
                hashmap.insert(key.1.clone(), v.clone());
                if let Some(limit) = num {
                    if hashmap.keys().len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(hashmap.values().cloned().collect())
    }

    async fn append_user_state(
        &self,
        username: &AkdKey,
        value: &ValueState,
    ) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        hashmap.insert(username.clone(), value.clone());
        hashmap.refresh();
        Ok(())
    }

    async fn append_user_states(
        &self,
        values: Vec<(AkdKey, ValueState)>,
    ) -> Result<(), StorageError> {
        let mut hashmap = self.user_data_write_handle.lock().unwrap();
        for kvp in values {
            hashmap.insert(kvp.0.clone(), kvp.1.clone());
        }
        hashmap.refresh();
        Ok(())
    }

    async fn get_user_data(&self, username: &AkdKey) -> Result<KeyData, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            let mut results = Vec::new();
            for kvp in intermediate.iter() {
                results.push(kvp.clone());
            }
            return Ok(KeyData { states: results });
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }
    async fn get_user_state(
        &self,
        username: &AkdKey,
        flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, StorageError> {
        if let Some(intermediate) = self.user_data_read_handle.get(username) {
            match flag {
                ValueStateRetrievalFlag::MaxEpoch =>
                // retrieve by max epoch
                {
                    if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                ValueStateRetrievalFlag::MaxVersion =>
                // retrieve the max version
                {
                    if let Some(value) =
                        intermediate.iter().max_by(|a, b| a.version.cmp(&b.version))
                    {
                        return Ok(value.clone());
                    }
                }
                ValueStateRetrievalFlag::MinEpoch =>
                // retrieve by min epoch
                {
                    if let Some(value) = intermediate.iter().min_by(|a, b| a.epoch.cmp(&b.epoch)) {
                        return Ok(value.clone());
                    }
                }
                ValueStateRetrievalFlag::MinVersion =>
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
                    let mut tracked_epoch = 0u64;
                    let mut tracker = None;
                    for kvp in intermediate.iter() {
                        match flag {
                            ValueStateRetrievalFlag::SpecificVersion(version)
                                if version == kvp.version =>
                            {
                                return Ok(kvp.clone())
                            }
                            ValueStateRetrievalFlag::LeqEpoch(epoch) if epoch == kvp.epoch => {
                                return Ok(kvp.clone());
                            }
                            ValueStateRetrievalFlag::LeqEpoch(epoch) if kvp.epoch < epoch => {
                                match tracked_epoch {
                                    0u64 => {
                                        tracked_epoch = kvp.epoch;
                                        tracker = Some(kvp.clone());
                                    }
                                    other_epoch => {
                                        if kvp.epoch > other_epoch {
                                            tracker = Some(kvp.clone());
                                            tracked_epoch = kvp.epoch;
                                        }
                                    }
                                }
                            }
                            ValueStateRetrievalFlag::SpecificEpoch(epoch) if epoch == kvp.epoch => {
                                return Ok(kvp.clone())
                            }
                            _ => continue,
                        }
                    }

                    if let Some(r) = tracker {
                        return Ok(r);
                    }
                }
            }
        }
        Result::Err(StorageError::GetError(String::from("Not found")))
    }
}
