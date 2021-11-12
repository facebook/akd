// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements a basic async timed cache

use crate::storage::DbRecord;
use crate::storage::Storable;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) struct CachedItem {
    expiration: Instant,
    data: Vec<DbRecord>,
}

impl CachedItem {
    pub(crate) fn append_item(&mut self, item: DbRecord, life: Duration) {
        self.expiration = Instant::now() + life;
        self.data.push(item);
    }
}

/// Implements a basic cahce with timing information which automatically flushes
/// expired entries and removes them
pub(crate) struct TimedCache {
    map: Arc<tokio::sync::RwLock<HashMap<[u8; 64], CachedItem>>>,
    item_lifetime: Duration,
}

impl Clone for TimedCache {
    fn clone(&self) -> Self {
        TimedCache {
            map: self.map.clone(),
            item_lifetime: self.item_lifetime,
        }
    }
}

impl TimedCache {
    pub(crate) async fn clean(&self) {
        let now = Instant::now();
        let mut keys_to_flush = HashSet::new();
        let r_guard = self.map.read().await;
        for (key, value) in (*r_guard).iter() {
            if value.expiration < now {
                keys_to_flush.insert(key);
            }
        }

        // flush the expired items
        if !keys_to_flush.is_empty() {
            let mut rw_guard = self.map.write().await;
            for key in keys_to_flush {
                (*rw_guard).remove(key);
            }
        }
    }

    pub(crate) fn new(o_lifetime: Option<Duration>) -> Self {
        let lifetime = match o_lifetime {
            Some(life) if life > Duration::from_secs(1) => life,
            _ => Duration::from_millis(30000),
        };
        Self {
            map: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            item_lifetime: lifetime,
        }
    }

    pub(crate) async fn hit_test<St: Storable>(&self, key: &St::Key) -> Option<DbRecord> {
        self.clean().await;

        let cache_key = St::get_cache_key(key);
        let full_key = St::get_full_binary_key_id(key);

        let guard = self.map.read().await;
        let ptr: &HashMap<_, _> = &*guard;
        if let Some(result) = ptr.get(&cache_key) {
            for item in result.data.iter() {
                // retrieve the "cache bucket", and then find the matching inner item
                match &item {
                    DbRecord::Azks(azks) if azks.get_full_binary_id() == full_key => return Some(DbRecord::Azks(azks.clone())),
                    DbRecord::HistoryTreeNode(node) if node.get_full_binary_id() == full_key => return Some(DbRecord::HistoryTreeNode(node.clone())),
                    DbRecord::HistoryNodeState(state) if state.get_full_binary_id() == full_key => return Some(DbRecord::HistoryNodeState(state.clone())),
                    DbRecord::ValueState(value) if value.get_full_binary_id() == full_key => return Some(DbRecord::ValueState(value.clone())),
                    _ => {}
                }
            }
        }

        None
    }

    pub(crate) async fn put(
        &self,
        record: &DbRecord,
        flush_on_hit: bool,
    ) {
        self.clean().await;

        let mut guard = self.map.write().await;
        let key = record.cache_key();
        if flush_on_hit {
            // overwrite any existing items since a flush is requested
            let item = CachedItem{ expiration: Instant::now() + self.item_lifetime, data: vec![record.clone()]};
            (*guard).insert(key, item);
        } else {
            (*guard)
                .entry(key)
                .or_insert_with(|| CachedItem{ expiration: Instant::now() + self.item_lifetime, data: vec![] })
                .append_item(record.clone(), self.item_lifetime);
        }
    }

    pub(crate) async fn batch_put(&self, records: &[DbRecord]) {
        self.clean().await;

        let mut guard = self.map.write().await;
        let mut keys: Vec<[u8; 64]> = records
            .iter()
            .map(|i| i.cache_key())
            .collect();
        // remove duplicates
        let mut unique_keys = HashSet::new();
        keys.retain(|e| unique_keys.insert(*e));

        // clear the keys in this batch update
        for key in keys.into_iter() {
            if let std::collections::hash_map::Entry::Occupied(o) = (*guard).entry(key) {
                o.remove_entry();
            }
        }

        for record in records.iter() {
            let key = record.cache_key();
            (*guard).entry(key).or_insert_with(|| CachedItem {expiration: Instant::now() + self.item_lifetime, data: vec![]}).append_item(record.clone(), self.item_lifetime);
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn flush(&self) {
        let mut guard = self.map.write().await;
        (*guard).clear();
    }
}
