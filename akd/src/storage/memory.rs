// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.
//! This module contains various memory representations.
use crate::errors::StorageError;
use crate::storage::transaction::Transaction;
use crate::storage::types::{
    AkdLabel, DbRecord, KeyData, StorageType, ValueState, ValueStateKey, ValueStateRetrievalFlag,
};
use crate::storage::{Storable, Storage};
use async_trait::async_trait;
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;

// ===== Basic In-Memory database ==== //

/// This struct represents a basic in-memory database.
#[derive(Debug)]
pub struct AsyncInMemoryDatabase {
    db: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, DbRecord>>>,
    user_info: Arc<tokio::sync::RwLock<HashMap<String, Vec<ValueState>>>>,
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

    async fn begin_transaction(&mut self) -> bool {
        self.trans.begin_transaction().await
    }

    async fn commit_transaction(&mut self) -> Result<(), StorageError> {
        // this retrieves all the trans operations, and "de-activates" the transaction flag
        let ops = self.trans.commit_transaction().await?;
        self.batch_set(ops).await
    }

    async fn rollback_transaction(&mut self) -> Result<(), StorageError> {
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
            let mut guard = self.user_info.write().await;
            let username = value_state.username.0.clone();
            guard
                .entry(username)
                .or_insert_with(Vec::new)
                .push(value_state.clone());
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
                let username = value_state.username.0.clone();
                u_guard
                    .entry(username)
                    .or_insert_with(Vec::new)
                    .push(value_state.clone());
            } else {
                guard.insert(record.get_full_binary_id(), record);
            }
        }
        Ok(())
    }

    /// Retrieve a stored record from the data layer
    async fn get<St: Storable>(&self, id: St::Key) -> Result<DbRecord, StorageError> {
        if self.is_transaction_active().await {
            if let Some(result) = self.trans.get::<St>(&id).await {
                // there's a transacted item, return that one since it's "more up to date"
                return Ok(result);
            }
        }
        let bin_id = St::get_full_binary_key_id(&id);
        // if the request is for a value state, look in the value state set
        if St::data_type() == StorageType::ValueState {
            if let Ok(ValueStateKey(username, epoch)) = ValueState::key_from_full_binary(&bin_id) {
                let u_guard = self.user_info.read().await;
                if let Some(state) = (*u_guard).get(&username).cloned() {
                    if let Some(item) = state.iter().find(|&x| x.epoch == epoch) {
                        return Ok(DbRecord::ValueState(item.clone()));
                    }
                }
                return Err(StorageError::GetData("Not found".to_string()));
            }
        }
        // fallback to regular get/set db
        let guard = self.db.read().await;
        if let Some(result) = (*guard).get(&bin_id).cloned() {
            Ok(result)
        } else {
            Err(StorageError::GetData("Not found".to_string()))
        }
    }

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: Vec<St::Key>,
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut map = Vec::new();
        for key in ids.into_iter() {
            if let Ok(result) = self.get::<St>(key).await {
                map.push(result);
            }
            // swallow errors (i.e. not found)
        }
        Ok(map)
    }

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError> {
        let guard = self.user_info.read().await;
        if let Some(result) = guard.get(&username.0) {
            let mut results: Vec<ValueState> = result.to_vec();
            // return ordered by epoch (from smallest -> largest)
            results.sort_by(|a, b| a.epoch.cmp(&b.epoch));

            Ok(KeyData { states: results })
        } else {
            Err(StorageError::GetData("Not found".to_string()))
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
        Err(StorageError::GetData(String::from("Not found")))
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, u64>, StorageError> {
        let mut map = HashMap::new();
        for username in keys.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(AkdLabel(result.username.0.clone()), result.version);
            }
        }
        Ok(map)
    }

    async fn get_epoch_lte_epoch(
        &self,
        node_label: crate::node_state::NodeLabel,
        epoch_in_question: u64,
    ) -> Result<u64, StorageError> {
        let ids = (0..=epoch_in_question)
            .map(|epoch| crate::node_state::NodeStateKey(node_label, epoch))
            .collect::<Vec<_>>();
        let data = self
            .batch_get::<crate::node_state::HistoryNodeState>(ids)
            .await?;
        let mut epochs = data
            .into_iter()
            .map(|item| {
                if let DbRecord::HistoryNodeState(state) = item {
                    state.key.1
                } else {
                    0u64
                }
            })
            .collect::<Vec<u64>>();
        // reverse sort
        epochs.sort_unstable_by(|a, b| b.cmp(a));

        // move through the epochs from largest to smallest, first one that's <= ```epoch_in_question```
        // and Bob's your uncle
        for item in epochs {
            if item <= epoch_in_question {
                return Ok(item);
            }
        }

        Err(StorageError::GetData(format!(
            "Node (val: {:?}, len: {}) did not exist <= epoch {}",
            node_label.val, node_label.len, epoch_in_question
        )))
    }
}

// ===== In-Memory database w/caching (for benchmarking) ==== //

/// Represents an in-memory database with caching and metric calculation for benchmarking
#[derive(Debug)]
pub struct AsyncInMemoryDbWithCache {
    db: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, DbRecord>>>,
    cache: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, DbRecord>>>,
    stats: Arc<tokio::sync::RwLock<HashMap<String, usize>>>,

    user_info: Arc<tokio::sync::RwLock<HashMap<String, Vec<ValueState>>>>,
    trans: Transaction,
}

unsafe impl Send for AsyncInMemoryDbWithCache {}
unsafe impl Sync for AsyncInMemoryDbWithCache {}

impl Default for AsyncInMemoryDbWithCache {
    fn default() -> Self {
        Self::new()
    }
}

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
            let len = bincode::serialize(val).map(|item| item.len()).unwrap();

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

    async fn begin_transaction(&mut self) -> bool {
        self.trans.begin_transaction().await
    }

    async fn commit_transaction(&mut self) -> Result<(), StorageError> {
        // this retrieves all the trans operations, and "de-activates" the transaction flag
        let ops = self.trans.commit_transaction().await?;
        self.batch_set(ops).await
    }

    async fn rollback_transaction(&mut self) -> Result<(), StorageError> {
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
            let mut guard = self.user_info.write().await;
            let username = value_state.username.0.clone();
            guard
                .entry(username)
                .or_insert_with(Vec::new)
                .push(value_state.clone());
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
                let username = value_state.username.0.clone();
                u_guard
                    .entry(username)
                    .or_insert_with(Vec::new)
                    .push(value_state.clone());
            } else {
                *calls += 1;
                guard.insert(record.get_full_binary_id(), record);
            }
        }
        Ok(())
    }

    async fn get<St: Storable>(&self, id: St::Key) -> Result<DbRecord, StorageError> {
        if self.is_transaction_active().await {
            if let Some(result) = self.trans.get::<St>(&id).await {
                // there's a transacted item, return that one since it's "more up to date"
                return Ok(result);
            }
        }

        let bin_id = St::get_full_binary_key_id(&id);
        // if the request is for a value state, look in the value state set
        if St::data_type() == StorageType::ValueState {
            if let Ok(ValueStateKey(username, epoch)) = ValueState::key_from_full_binary(&bin_id) {
                let u_guard = self.user_info.read().await;
                if let Some(state) = (*u_guard).get(&username).cloned() {
                    if let Some(item) = state.iter().find(|&x| x.epoch == epoch) {
                        return Ok(DbRecord::ValueState(item.clone()));
                    }
                }
                return Err(StorageError::GetData("Not found".to_string()));
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
                    Err(StorageError::GetData("Not found".to_string()))
                }
            }
        }
    }

    async fn batch_get<St: Storable>(
        &self,
        ids: Vec<St::Key>,
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut map = Vec::new();
        for key in ids.into_iter() {
            if let Ok(result) = self.get::<St>(key).await {
                map.push(result);
            }
            // swallow errors (i.e. not found)
        }
        Ok(map)
    }

    async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError> {
        let guard = self.user_info.read().await;
        if let Some(result) = guard.get(&username.0) {
            let mut results: Vec<ValueState> = result.to_vec();
            // return ordered by epoch (from smallest -> largest)
            results.sort_by(|a, b| a.epoch.cmp(&b.epoch));

            Ok(KeyData { states: results })
        } else {
            Err(StorageError::GetData("Not found".to_string()))
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
        Err(StorageError::GetData(String::from("Not found")))
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, u64>, StorageError> {
        let mut map = HashMap::new();
        for username in keys.iter() {
            if let Ok(result) = self.get_user_state(username, flag).await {
                map.insert(AkdLabel(result.username.0.clone()), result.version);
            }
        }
        Ok(map)
    }

    async fn get_epoch_lte_epoch(
        &self,
        node_label: crate::node_state::NodeLabel,
        epoch_in_question: u64,
    ) -> Result<u64, StorageError> {
        let ids = (0..=epoch_in_question)
            .map(|epoch| crate::node_state::NodeStateKey(node_label, epoch))
            .collect::<Vec<_>>();
        let data = self
            .batch_get::<crate::node_state::HistoryNodeState>(ids)
            .await?;
        let mut epochs = data
            .into_iter()
            .map(|item| {
                if let DbRecord::HistoryNodeState(state) = item {
                    state.key.1
                } else {
                    0u64
                }
            })
            .collect::<Vec<u64>>();
        // reverse sort
        epochs.sort_unstable_by(|a, b| b.cmp(a));

        // move through the epochs from largest to smallest, first one that's <= ```epoch_in_question```
        // and Bob's your uncle
        for item in epochs {
            if item <= epoch_in_question {
                return Ok(item);
            }
        }
        Err(StorageError::GetData(format!(
            "Node (val: {:?}, len: {}) did not exist <= epoch {}",
            node_label.val, node_label.len, epoch_in_question
        )))
    }
}
