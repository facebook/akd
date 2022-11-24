// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains an in-memory database for the AKD library as well as
//! an in-memory implementation which contains some caching implementations for
//! benchmarking

use crate::errors::StorageError;
use crate::storage::types::{
    AkdLabel, AkdValue, DbRecord, KeyData, StorageType, ValueState, ValueStateKey,
    ValueStateRetrievalFlag,
};
use crate::storage::{Database, Storable, StorageUtil};
use async_trait::async_trait;
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
}

unsafe impl Send for AsyncInMemoryDatabase {}
unsafe impl Sync for AsyncInMemoryDatabase {}

impl AsyncInMemoryDatabase {
    /// Creates a new in memory db
    pub fn new() -> Self {
        Self {
            db: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            user_info: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
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
        }
    }
}

#[async_trait]
impl Database for AsyncInMemoryDatabase {
    async fn set(&self, record: DbRecord) -> Result<(), StorageError> {
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

    async fn batch_set(
        &self,
        records: Vec<DbRecord>,
        _state: crate::storage::DbSetState,
    ) -> Result<(), StorageError> {
        if records.is_empty() {
            // nothing to do, save the cycles
            return Ok(());
        }
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
    async fn get<St: Storable>(&self, id: &St::StorageKey) -> Result<DbRecord, StorageError> {
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

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::StorageKey],
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
