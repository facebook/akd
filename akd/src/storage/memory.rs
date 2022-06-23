// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains an in-memory database for the AKD library as well as
//! an in-memory implementation which contains some caching implementations for
//! benchmarking

use crate::errors::StorageError;
use crate::storage::transaction::Transaction;
use crate::storage::types::{
    AkdLabel, AkdValue, DbRecord, KeyData, StorageType, ValueState, ValueStateKey,
    ValueStateRetrievalFlag,
};
use crate::storage::{Storable, Storage, StorageUtil};
use async_trait::async_trait;
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;

type Epoch = u64;
type UserValueMap = HashMap<Epoch, ValueState>;
type UserStates = HashMap<Vec<u8>, UserValueMap>;

// ===== Basic In-Memory database ==== //

/// This struct represents a basic in-memory database.
#[derive(Debug)]
pub struct AsyncInMemoryDatabase {
    db: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, DbRecord>>>,
    user_info: Arc<tokio::sync::RwLock<UserStates>>,
    trans: Transaction,
}

unsafe impl Send for AsyncInMemoryDatabase {}
unsafe impl Sync for AsyncInMemoryDatabase {}

impl AsyncInMemoryDatabase {
    /// Creates a new in memory db
    pub fn new() -> Self {
        Self {
            db: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            user_info: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            trans: Transaction::new(),
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
            db: self.db.clone(),
            user_info: self.user_info.clone(),
            trans: Transaction::new(),
        }
    }
}

#[async_trait]
impl Storage for AsyncInMemoryDatabase {
    async fn log_metrics(&self, level: log::Level) {
        let size = self.db.read().await;
        let msg = format!("InMemDb record count: {}", size.keys().len());

        match level {
            log::Level::Trace => trace!("{}", msg),
            log::Level::Debug => debug!("{}", msg),
            log::Level::Info => info!("{}", msg),
            log::Level::Warn => warn!("{}", msg),
            _ => error!("{}", msg),
        }
    }

    async fn begin_transaction(&self) -> bool {
        self.trans.begin_transaction().await
    }

    async fn commit_transaction(&self) -> Result<(), StorageError> {
        // this retrieves all the trans operations, and "de-activates" the transaction flag
        let ops = self.trans.commit_transaction().await?;
        self.batch_set(ops).await
    }

    async fn rollback_transaction(&self) -> Result<(), StorageError> {
        self.trans.rollback_transaction().await
    }

    async fn is_transaction_active(&self) -> bool {
        self.trans.is_transaction_active().await
    }

    async fn set(&self, record: DbRecord) -> Result<(), StorageError> {
        if self.is_transaction_active().await {
            self.trans.set(&record).await;
            return Ok(());
        }

        if let DbRecord::ValueState(value_state) = &record {
            let mut u_guard = self.user_info.write().await;
            let username = value_state.username.to_vec();
            match u_guard.get(&username) {
                Some(old_states) => {
                    let mut new_states = old_states.clone();
                    new_states.insert(value_state.epoch, value_state.clone());
                    u_guard.insert(username, new_states);
                }
                None => {
                    let mut new_map = HashMap::new();
                    new_map.insert(value_state.epoch, value_state.clone());
                    u_guard.insert(username, new_map);
                }
            }
        } else {
            let mut guard = self.db.write().await;
            guard.insert(record.get_full_binary_id(), record);
        }

        Ok(())
    }

    async fn batch_set(&self, records: Vec<DbRecord>) -> Result<(), StorageError> {
        let mut u_guard = self.user_info.write().await;
        let mut guard = self.db.write().await;

        for record in records.into_iter() {
            if let DbRecord::ValueState(value_state) = &record {
                let username = value_state.username.to_vec();
                match u_guard.get(&username) {
                    Some(old_states) => {
                        let mut new_states = old_states.clone();
                        new_states.insert(value_state.epoch, value_state.clone());
                        u_guard.insert(username, new_states);
                    }
                    None => {
                        let mut new_map = HashMap::new();
                        new_map.insert(value_state.epoch, value_state.clone());
                        u_guard.insert(username, new_map);
                    }
                }
            } else {
                guard.insert(record.get_full_binary_id(), record);
            }
        }
        Ok(())
    }

    /// Retrieve a stored record from the data layer
    async fn get<St: Storable>(&self, id: &St::Key) -> Result<DbRecord, StorageError> {
        if self.is_transaction_active().await {
            if let Some(result) = self.trans.get::<St>(id).await {
                // there's a transacted item, return that one since it's "more up to date"
                return Ok(result);
            }
        }
        self.get_direct::<St>(id).await
    }

    /// Retrieve a record from the data layer, ignoring any caching or transaction pending
    async fn get_direct<St: Storable>(&self, id: &St::Key) -> Result<DbRecord, StorageError> {
        let bin_id = St::get_full_binary_key_id(id);
        // if the request is for a value state, look in the value state set
        if St::data_type() == StorageType::ValueState {
            if let Ok(ValueStateKey(username, epoch)) = ValueState::key_from_full_binary(&bin_id) {
                let u_guard = self.user_info.read().await;
                if let Some(state) = (*u_guard).get(&username).cloned() {
                    if let Some(found) = state.get(&epoch) {
                        return Ok(DbRecord::ValueState(found.clone()));
                    }
                }
                return Err(StorageError::NotFound(format!("ValueState {:?}", id)));
            }
        }
        // fallback to regular get/set db
        let guard = self.db.read().await;
        if let Some(result) = (*guard).get(&bin_id).cloned() {
            Ok(result)
        } else {
            Err(StorageError::NotFound(format!(
                "{:?} {:?}",
                St::data_type(),
                id
            )))
        }
    }

    /// Flush the caching of objects (if present)
    async fn flush_cache(&self) {
        // no-op
    }

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::Key],
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut map = Vec::new();
        for key in ids.iter() {
            if let Ok(result) = self.get::<St>(key).await {
                map.push(result);
            }
            // swallow errors (i.e. not found)
        }
        Ok(map)
    }

    async fn tombstone_value_states(&self, keys: &[ValueStateKey]) -> Result<(), StorageError> {
        if keys.is_empty() {
            return Ok(());
        }

        let data = self.batch_get::<ValueState>(keys).await?;
        let mut new_data = vec![];
        for record in data {
            if let DbRecord::ValueState(value_state) = record {
                debug!(
                    "Tombstoning 0x{}",
                    hex::encode(value_state.username.to_vec())
                );

                new_data.push(DbRecord::ValueState(ValueState {
                    plaintext_val: crate::AkdValue(crate::TOMBSTONE.to_vec()),
                    ..value_state
                }));
            }
        }

        if !new_data.is_empty() {
            debug!("Tombstoning {} entries", new_data.len());
            self.batch_set(new_data).await?;
        }

        Ok(())
    }

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError> {
        let guard = self.user_info.read().await;
        if let Some(result) = guard.get(&username.0) {
            let mut results: Vec<ValueState> = result.values().cloned().collect::<Vec<_>>();
            // return ordered by epoch (from smallest -> largest)
            results.sort_by(|a, b| a.epoch.cmp(&b.epoch));

            Ok(KeyData { states: results })
        } else {
            Err(StorageError::NotFound(format!("ValueState {:?}", username)))
        }
    }

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, StorageError> {
        let intermediate = self.get_user_data(username).await?.states;
        match flag {
            ValueStateRetrievalFlag::MaxEpoch =>
            // retrieve by max epoch
            {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
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
        Err(StorageError::NotFound(format!("ValueState {:?}", username)))
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError> {
        let mut map = HashMap::new();
        for username in keys.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(
                    AkdLabel(result.username.to_vec()),
                    (result.version, AkdValue(result.plaintext_val.to_vec())),
                );
            }
        }
        Ok(map)
    }
}

#[async_trait]
impl StorageUtil for AsyncInMemoryDatabase {
    async fn batch_get_type_direct<St: Storable>(&self) -> Result<Vec<DbRecord>, StorageError> {
        let records = self
            .batch_get_all_direct()
            .await?
            .into_iter()
            .filter(|record| match record {
                DbRecord::Azks(_) => St::data_type() == StorageType::Azks,
                DbRecord::TreeNode(_) => St::data_type() == StorageType::TreeNode,
                DbRecord::ValueState(_) => St::data_type() == StorageType::ValueState,
            })
            .collect();

        Ok(records)
    }

    async fn batch_get_all_direct(&self) -> Result<Vec<DbRecord>, StorageError> {
        // get value states
        let u_guard = self.user_info.read().await;
        let u_records = u_guard
            .values()
            .cloned()
            .flat_map(|v| v.into_values())
            .map(DbRecord::ValueState);

        // get other records and collect
        let guard = self.db.read().await;
        let records = guard.values().cloned().chain(u_records).collect();

        Ok(records)
    }
}

// ===== In-Memory database w/caching (for benchmarking) ==== //

/// Represents an in-memory database with caching and metric calculation for benchmarking
#[derive(Debug)]
#[cfg(feature = "public-tests")]
pub struct AsyncInMemoryDbWithCache {
    db: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, DbRecord>>>,
    cache: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, DbRecord>>>,
    stats: Arc<tokio::sync::RwLock<HashMap<String, usize>>>,

    user_info: Arc<tokio::sync::RwLock<UserStates>>,
    trans: Transaction,
}

#[cfg(feature = "public-tests")]
unsafe impl Send for AsyncInMemoryDbWithCache {}
#[cfg(feature = "public-tests")]
unsafe impl Sync for AsyncInMemoryDbWithCache {}

#[cfg(feature = "public-tests")]
impl Default for AsyncInMemoryDbWithCache {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "public-tests")]
impl Clone for AsyncInMemoryDbWithCache {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            cache: self.cache.clone(),
            stats: self.stats.clone(),

            user_info: self.user_info.clone(),
            trans: Transaction::new(),
        }
    }
}
#[cfg(feature = "public-tests")]
impl AsyncInMemoryDbWithCache {
    /// Creates a new in memory db with caching
    pub fn new() -> Self {
        Self {
            db: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            stats: Arc::new(tokio::sync::RwLock::new(HashMap::new())),

            user_info: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            trans: Transaction::new(),
        }
    }

    /// Flushes the cache and clearn any associated stats
    pub async fn clear_stats(&self) {
        // Flush cache to db

        let mut cache = self.cache.write().await;

        let mut db = self.db.write().await;
        for (key, val) in cache.iter() {
            db.insert(key.clone(), val.clone());
        }

        cache.clear();

        let mut stats = self.stats.write().await;
        stats.clear();
    }

    /// Prints db states
    pub async fn print_stats(&self) {
        println!("Statistics collected:");
        println!("---------------------");

        let stats = self.stats.read().await;
        for (key, val) in stats.iter() {
            println!("{:?}: {}", key, val);
        }

        println!("---------------------");
    }

    /// Prints the distribution of the lengths of entries in a db
    pub async fn print_hashmap_distribution(&self) {
        println!("Cache distribution of length of entries (in bytes):");
        println!("---------------------");

        let cache = self.cache.read().await;

        let mut distribution: HashMap<usize, usize> = HashMap::new();

        for (_, val) in cache.iter() {
            if let Ok(len) = bincode::serialize(val).map(|item| item.len()) {
                let counter = distribution.entry(len).or_insert(0);
                *counter += 1;
            }
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
#[cfg(feature = "public-tests")]
#[async_trait]
impl Storage for AsyncInMemoryDbWithCache {
    async fn log_metrics(&self, level: log::Level) {
        let size = self.db.read().await;
        let cache_size = self.cache.read().await;
        let msg = format!(
            "InMemDbWCache record count: {}, cache count: {}",
            size.keys().len(),
            cache_size.keys().len()
        );

        match level {
            log::Level::Trace => trace!("{}", msg),
            log::Level::Debug => debug!("{}", msg),
            log::Level::Info => info!("{}", msg),
            log::Level::Warn => warn!("{}", msg),
            _ => error!("{}", msg),
        }
    }

    async fn begin_transaction(&self) -> bool {
        self.trans.begin_transaction().await
    }

    async fn commit_transaction(&self) -> Result<(), StorageError> {
        // this retrieves all the trans operations, and "de-activates" the transaction flag
        let ops = self.trans.commit_transaction().await?;
        self.batch_set(ops).await
    }

    async fn rollback_transaction(&self) -> Result<(), StorageError> {
        self.trans.rollback_transaction().await
    }

    async fn is_transaction_active(&self) -> bool {
        self.trans.is_transaction_active().await
    }

    async fn set(&self, record: DbRecord) -> Result<(), StorageError> {
        if self.is_transaction_active().await {
            self.trans.set(&record).await;
            return Ok(());
        }

        if let DbRecord::ValueState(value_state) = &record {
            let mut u_guard = self.user_info.write().await;
            let username = value_state.username.to_vec();
            match u_guard.get(&username) {
                Some(old_states) => {
                    let mut new_states = old_states.clone();
                    new_states.insert(value_state.epoch, value_state.clone());
                    u_guard.insert(username, new_states);
                }
                None => {
                    let mut new_map = HashMap::new();
                    new_map.insert(value_state.epoch, value_state.clone());
                    u_guard.insert(username, new_map);
                }
            }
        } else {
            let mut stats = self.stats.write().await;
            let calls = stats.entry(String::from("calls_to_cache_set")).or_insert(0);
            *calls += 1;

            let mut guard = self.cache.write().await;
            guard.insert(record.get_full_binary_id(), record);
        }

        Ok(())
    }

    async fn batch_set(&self, records: Vec<DbRecord>) -> Result<(), StorageError> {
        let mut u_guard = self.user_info.write().await;
        let mut stats = self.stats.write().await;
        let mut guard = self.cache.write().await;
        let calls = stats.entry(String::from("calls_to_cache_set")).or_insert(0);

        for record in records.into_iter() {
            if let DbRecord::ValueState(value_state) = &record {
                let username = value_state.username.to_vec();
                match u_guard.get(&username) {
                    Some(old_states) => {
                        let mut new_states = old_states.clone();
                        new_states.insert(value_state.epoch, value_state.clone());
                        u_guard.insert(username, new_states);
                    }
                    None => {
                        let mut new_map = HashMap::new();
                        new_map.insert(value_state.epoch, value_state.clone());
                        u_guard.insert(username, new_map);
                    }
                }
            } else {
                *calls += 1;
                guard.insert(record.get_full_binary_id(), record);
            }
        }
        Ok(())
    }

    async fn get<St: Storable>(&self, id: &St::Key) -> Result<DbRecord, StorageError> {
        if self.is_transaction_active().await {
            if let Some(result) = self.trans.get::<St>(id).await {
                // there's a transacted item, return that one since it's "more up to date"
                return Ok(result);
            }
        }
        self.get_direct::<St>(id).await
    }

    /// Retrieve a record from the data layer, ignoring any caching or transaction pending
    async fn get_direct<St: Storable>(&self, id: &St::Key) -> Result<DbRecord, StorageError> {
        let bin_id = St::get_full_binary_key_id(id);
        // if the request is for a value state, look in the value state set
        if St::data_type() == StorageType::ValueState {
            if let Ok(ValueStateKey(username, epoch)) = ValueState::key_from_full_binary(&bin_id) {
                let u_guard = self.user_info.read().await;
                if let Some(state) = (*u_guard).get(&username).cloned() {
                    if let Some(found) = state.get(&epoch) {
                        return Ok(DbRecord::ValueState(found.clone()));
                    }
                }
                return Err(StorageError::NotFound(format!("ValueState {:?}", id)));
            }
        }
        let mut stats = self.stats.write().await;
        let calls_to_cache_get = stats.entry(String::from("calls_to_cache_get")).or_insert(0);
        *calls_to_cache_get += 1;

        let mut cache = self.cache.write().await;
        match cache.get(&bin_id).cloned() {
            Some(value) => Ok(value),
            None => {
                // fallback to regular get/set db
                let guard = self.db.read().await;
                if let Some(result) = (*guard).get(&bin_id).cloned() {
                    // cache the item
                    cache.insert(bin_id, result.clone());

                    Ok(result)
                } else {
                    Err(StorageError::NotFound(format!(
                        "{:?} {:?}",
                        St::data_type(),
                        id
                    )))
                }
            }
        }
    }

    async fn flush_cache(&self) {
        // no-op
    }

    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::Key],
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut map = Vec::new();
        for key in ids.iter() {
            if let Ok(result) = self.get::<St>(key).await {
                map.push(result);
            }
            // swallow errors (i.e. not found)
        }
        Ok(map)
    }

    async fn tombstone_value_states(&self, keys: &[ValueStateKey]) -> Result<(), StorageError> {
        if keys.is_empty() {
            return Ok(());
        }

        let data = self.batch_get::<ValueState>(keys).await?;
        let mut new_data = vec![];
        for record in data {
            if let DbRecord::ValueState(value_state) = record {
                new_data.push(DbRecord::ValueState(ValueState {
                    plaintext_val: crate::AkdValue(crate::TOMBSTONE.to_vec()),
                    ..value_state
                }));
            }
        }

        if !new_data.is_empty() {
            self.batch_set(new_data).await?;
        }

        Ok(())
    }

    async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError> {
        let guard = self.user_info.read().await;
        if let Some(result) = guard.get(&username.0) {
            let mut results: Vec<ValueState> = result.values().cloned().collect();
            // return ordered by epoch (from smallest -> largest)
            results.sort_by(|a, b| a.epoch.cmp(&b.epoch));

            Ok(KeyData { states: results })
        } else {
            Err(StorageError::NotFound(format!("ValueState {:?}", username)))
        }
    }

    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, StorageError> {
        let intermediate = self.get_user_data(username).await?.states;
        match flag {
            ValueStateRetrievalFlag::MaxEpoch =>
            // retrieve by max epoch
            {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.epoch.cmp(&b.epoch)) {
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
        Err(StorageError::NotFound(format!("ValueState {:?}", username)))
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError> {
        let mut map = HashMap::new();
        for username in keys.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(
                    AkdLabel(result.username.to_vec()),
                    (result.version, AkdValue(result.plaintext_val.to_vec())),
                );
            }
        }
        Ok(map)
    }
}

#[cfg(feature = "public-tests")]
#[async_trait]
impl StorageUtil for AsyncInMemoryDbWithCache {
    async fn batch_get_type_direct<St: Storable>(&self) -> Result<Vec<DbRecord>, StorageError> {
        let records = self
            .batch_get_all_direct()
            .await?
            .into_iter()
            .filter(|record| match record {
                DbRecord::Azks(_) => St::data_type() == StorageType::Azks,
                DbRecord::TreeNode(_) => St::data_type() == StorageType::TreeNode,
                DbRecord::ValueState(_) => St::data_type() == StorageType::ValueState,
            })
            .collect();

        Ok(records)
    }

    async fn batch_get_all_direct(&self) -> Result<Vec<DbRecord>, StorageError> {
        // get value states
        let u_guard = self.user_info.read().await;
        let u_records = u_guard
            .values()
            .cloned()
            .flat_map(|v| v.into_values())
            .map(DbRecord::ValueState);

        // get other records and collect
        let guard = self.db.read().await;
        let records = guard.values().cloned().chain(u_records).collect();

        Ok(records)
    }
}
