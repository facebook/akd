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
    AkdKey, DbRecord, KeyData, StorageType, ValueState, ValueStateKey, ValueStateRetrievalFlag,
};
use crate::storage::{Storable, V2Storage};

use async_trait::async_trait;
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;

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
impl V2Storage for AsyncInMemoryDatabase {
    /// Log some information about the db
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

    /// Start a transaction in the storage layer
    async fn begin_transaction(&mut self) -> bool {
        self.trans.begin_transaction().await
    }

    /// Commit a transaction in the storage layer
    async fn commit_transaction(&mut self) -> Result<(), StorageError> {
        // this retrieves all the trans operations, and "de-activates" the transaction flag
        let ops = self.trans.commit_transaction().await?;
        self.batch_set(ops).await
    }

    /// Rollback a transaction
    async fn rollback_transaction(&mut self) -> Result<(), StorageError> {
        self.trans.rollback_transaction().await
    }

    /// Retrieve a flag determining if there is a transaction active
    async fn is_transaction_active(&self) -> bool {
        self.trans.is_transaction_active().await
    }

    /// V1Storage a record in the data layer
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
                return Err(StorageError::GetError("Not found".to_string()));
            }
        }
        // fallback to regular get/set db
        let guard = self.db.read().await;
        if let Some(result) = (*guard).get(&bin_id).cloned() {
            Ok(result)
        } else {
            Err(StorageError::GetError("Not found".to_string()))
        }
    }

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: Vec<St::Key>,
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut map = Vec::new();
        for key in ids.into_iter() {
            map.push(self.get::<St>(key).await?);
        }
        Ok(map)
    }

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all<St: Storable>(
        &self,
        num: Option<usize>,
    ) -> Result<Vec<DbRecord>, StorageError> {
        let mut list = vec![];

        if St::data_type() == StorageType::ValueState {
            let u_guard = self.user_info.read().await;
            for (_, item) in u_guard.iter() {
                for state in item.iter() {
                    let record = DbRecord::ValueState(state.clone());
                    list.push(record);
                    if let Some(count) = num {
                        if count > 0 && list.len() >= count {
                            break;
                        }
                    }
                }
                if let Some(count) = num {
                    if count > 0 && list.len() >= count {
                        break;
                    }
                }
            }
        } else {
            // fallback to generic lookup for all other data
            let guard = self.db.read().await;
            for (_, item) in guard.iter() {
                let ty = match &item {
                    DbRecord::Azks(_) => StorageType::Azks,
                    DbRecord::HistoryNodeState(_) => StorageType::HistoryNodeState,
                    DbRecord::HistoryTreeNode(_) => StorageType::HistoryTreeNode,
                    DbRecord::ValueState(_) => StorageType::ValueState,
                };
                if ty == St::data_type() {
                    list.push(item.clone());
                }

                if let Some(count) = num {
                    if count > 0 && list.len() >= count {
                        break;
                    }
                }
            }
        }

        if self.is_transaction_active().await {
            // check transacted objects
            let mut updated = vec![];
            for item in list.into_iter() {
                match &item {
                    DbRecord::Azks(azks) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::append_only_zks::Azks>(&azks.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                    DbRecord::HistoryNodeState(state) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::node_state::HistoryNodeState>(&state.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                    DbRecord::HistoryTreeNode(node) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::history_tree_node::HistoryTreeNode>(&node.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                    DbRecord::ValueState(state) => {
                        if let Some(matching) = self
                            .trans
                            .get::<crate::storage::types::ValueState>(&state.get_id())
                            .await
                        {
                            updated.push(matching);
                            continue;
                        }
                    }
                }
                updated.push(item);
            }
            Ok(updated)
        } else {
            Ok(list)
        }
    }

    /// Add a user state element to the associated user
    async fn append_user_state(&self, value: &ValueState) -> Result<(), StorageError> {
        self.set(DbRecord::ValueState(value.clone())).await
    }

    async fn append_user_states(&self, values: Vec<ValueState>) -> Result<(), StorageError> {
        let new_vec = values.into_iter().map(DbRecord::ValueState).collect();
        self.batch_set(new_vec).await
    }

    /// Retrieve the user data for a given user
    async fn get_user_data(&self, username: &AkdKey) -> Result<KeyData, StorageError> {
        let guard = self.user_info.read().await;
        if let Some(result) = guard.get(&username.0) {
            let mut results: Vec<ValueState> = result.to_vec();
            // return ordered by epoch (from smallest -> largest)
            results.sort_by(|a, b| a.epoch.cmp(&b.epoch));

            Ok(KeyData { states: results })
        } else {
            Err(StorageError::GetError("Not found".to_string()))
        }
    }

    /// Retrieve a specific state for a given user
    async fn get_user_state(
        &self,
        username: &AkdKey,
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
            ValueStateRetrievalFlag::MaxVersion =>
            // retrieve the max version
            {
                if let Some(value) = intermediate.iter().max_by(|a, b| a.version.cmp(&b.version)) {
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
                if let Some(value) = intermediate.iter().min_by(|a, b| a.version.cmp(&b.version)) {
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
        Err(StorageError::GetError(String::from("Not found")))
    }
}
