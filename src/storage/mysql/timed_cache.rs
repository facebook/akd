// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements a basic async timed cache

use crate::errors::StorageError;
use crate::storage::DbRecord;
use crate::storage::{Storable, StorageType};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct TimedBinaryItem {
    expiration: Instant,
    data: Vec<u8>,
}

pub(crate) struct CachedItem {
    items: Vec<TimedBinaryItem>,
}

impl CachedItem {
    pub(crate) fn empty() -> Self {
        Self::new(None, Duration::from_millis(1))
    }

    pub(crate) fn new(v: Option<Vec<u8>>, expire: Duration) -> Self {
        let expiration = Instant::now() + expire;
        match v {
            Some(i_value) => CachedItem {
                items: vec![TimedBinaryItem {
                    data: i_value,
                    expiration,
                }],
            },
            None => CachedItem { items: Vec::new() },
        }
    }

    pub(crate) fn append_item(&mut self, item: Vec<u8>, expire: Duration) {
        let expiration = Instant::now() + expire;
        self.items.push(TimedBinaryItem {
            data: item,
            expiration,
        });
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub(crate) struct CacheKey(StorageType, u64);

impl CacheKey {
    pub(crate) fn get_cache_key_for_record<H: winter_crypto::Hasher + Sync + Send>(
        record: &DbRecord<H>,
    ) -> Self {
        let mut s = std::collections::hash_map::DefaultHasher::new();
        let ty = match &record {
            DbRecord::Azks(azks) => {
                azks.get_id().hash(&mut s);
                StorageType::Azks
            }
            DbRecord::HistoryNodeState(state) => {
                state.get_id().hash(&mut s);
                StorageType::HistoryNodeState
            }
            DbRecord::HistoryTreeNode(node) => {
                node.get_id().hash(&mut s);
                StorageType::HistoryTreeNode
            }
            DbRecord::ValueState(value) => {
                value.get_id().hash(&mut s);
                StorageType::ValueState
            }
        };
        Self(ty, s.finish())
    }

    pub(crate) fn get_cache_key_for_storable<St: Storable>(key: &St::Key) -> CacheKey {
        let mut s = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut s);
        let ty = St::data_type();
        CacheKey(ty, s.finish())
    }
}

/// Implements a basic cahce with timing information which automatically flushes
/// expired entries and removes them
pub(crate) struct TimedCache {
    map: Arc<tokio::sync::RwLock<HashMap<CacheKey, CachedItem>>>,
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
            if value.items.iter().any(|x| x.expiration < now) {
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

    pub(crate) async fn hit_test<H: winter_crypto::Hasher + Sync + Send, St: Storable>(
        &self,
        key: &St::Key,
    ) -> Option<DbRecord<H>> {
        self.clean().await;

        let key_copy = key.clone();
        let cache_key = CacheKey::get_cache_key_for_storable::<St>(key);
        let guard = self.map.read().await;
        let ptr: &HashMap<_, _> = &*guard;
        if let Some(result) = ptr.get(&cache_key) {
            for item in result.items.iter() {
                if let Ok(decoded) = bincode::deserialize::<St>(&item.data) {
                    // compare the full item key
                    if decoded.get_id() == key_copy.clone() {
                        // CACHE HIT

                        // Now the fugly part, decode a 2nd time to assert the mastry of Rust's inability
                        // to cast objects to their underlying type without KNOWING full in advance what
                        // the type is.
                        match St::data_type() {
                            StorageType::Azks => {
                                if let Ok(decoded2) = bincode::deserialize::<
                                    crate::append_only_zks::Azks<H>,
                                >(&item.data)
                                {
                                    return Some(DbRecord::Azks::<H>(decoded2));
                                }
                            }
                            StorageType::HistoryNodeState => {
                                if let Ok(decoded2) = bincode::deserialize::<
                                    crate::node_state::HistoryNodeState<H>,
                                >(&item.data)
                                {
                                    return Some(DbRecord::HistoryNodeState::<H>(decoded2));
                                }
                            }
                            StorageType::HistoryTreeNode => {
                                if let Ok(decoded2) = bincode::deserialize::<
                                    crate::history_tree_node::HistoryTreeNode<H>,
                                >(&item.data)
                                {
                                    return Some(DbRecord::HistoryTreeNode::<H>(decoded2));
                                }
                            }
                            StorageType::ValueState => {
                                if let Ok(decoded2) = bincode::deserialize::<
                                    crate::storage::types::ValueState,
                                >(&item.data)
                                {
                                    return Some(DbRecord::ValueState::<H>(decoded2));
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub(crate) async fn put<H: winter_crypto::Hasher + Sync + Send>(
        &self,
        record: &DbRecord<H>,
        flush_on_hit: bool,
    ) -> Result<(), StorageError> {
        self.clean().await;

        let mut guard = self.map.write().await;
        let key = CacheKey::get_cache_key_for_record(record);
        let binary = match &record {
            DbRecord::Azks(azks) => bincode::serialize(azks),
            DbRecord::HistoryNodeState(state) => bincode::serialize(state),
            DbRecord::HistoryTreeNode(node) => bincode::serialize(node),
            DbRecord::ValueState(value) => bincode::serialize(value),
        };
        if let Ok(bin) = binary {
            // insert or replace the value (i.e. invalidate cache because of clash with hashcode)
            if flush_on_hit {
                (*guard).insert(key, CachedItem::new(Some(bin), self.item_lifetime));
            } else {
                // push a new entry into the cache list at the specified caching location
                (*guard)
                    .entry(key)
                    .or_insert_with(CachedItem::empty)
                    .append_item(bin, self.item_lifetime);
            }
            Ok(())
        } else {
            Err(StorageError::SerializationError)
        }
    }

    pub(crate) async fn batch_put<H: winter_crypto::Hasher + Sync + Send>(
        &self,
        records: &[DbRecord<H>],
    ) -> Result<(), StorageError> {
        self.clean().await;

        let mut guard = self.map.write().await;
        let mut keys: Vec<CacheKey> = records
            .iter()
            .map(|i| CacheKey::get_cache_key_for_record(i))
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
            let key = CacheKey::get_cache_key_for_record(record);

            let binary = match &record {
                DbRecord::Azks(azks) => bincode::serialize(azks),
                DbRecord::HistoryNodeState(state) => bincode::serialize(state),
                DbRecord::HistoryTreeNode(node) => bincode::serialize(node),
                DbRecord::ValueState(value) => bincode::serialize(value),
            };
            if let Ok(bin) = binary {
                // push a new entry into the cache list at the specified caching location
                (*guard)
                    .entry(key)
                    .or_insert_with(CachedItem::empty)
                    .append_item(bin, self.item_lifetime);
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn flush(&self) {
        let mut guard = self.map.write().await;
        (*guard).clear();
    }
}
