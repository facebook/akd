// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements a basic async timed cache

use crate::storage::DbRecord;
use crate::storage::Storable;
use log::debug;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

// item's live for 30s
const DEFAULT_ITEM_LIFETIME_MS: u64 = 30000;
// clean the cache every 15s
const CACHE_CLEAN_FREQUENCY_MS: u64 = 15000;

pub(crate) struct CachedItem {
    expiration: Instant,
    data: DbRecord,
}

/// Implements a basic cahce with timing information which automatically flushes
/// expired entries and removes them
pub(crate) struct TimedCache {
    map: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, CachedItem>>>,
    last_clean: Arc<tokio::sync::RwLock<Instant>>,
    item_lifetime: Duration,
}

impl Clone for TimedCache {
    fn clone(&self) -> Self {
        TimedCache {
            map: self.map.clone(),
            last_clean: self.last_clean.clone(),
            item_lifetime: self.item_lifetime,
        }
    }
}

impl TimedCache {
    async fn clean(&self) {
        let do_clean = {
            // we need the {} brackets in order to release the read lock, since we _may_ acquire a write lock shortly later
            *(self.last_clean.read().await) + Duration::from_millis(CACHE_CLEAN_FREQUENCY_MS)
                < Instant::now()
        };
        if do_clean {
            debug!("BEGIN clean cache");
            let now = Instant::now();
            let mut keys_to_flush = HashSet::new();

            let mut write = self.map.write().await;
            for (key, value) in write.iter() {
                if value.expiration < now {
                    keys_to_flush.insert(key.clone());
                }
            }
            if !keys_to_flush.is_empty() {
                for key in keys_to_flush.into_iter() {
                    write.remove(&key);
                }
            }
            debug!("END clean cache");

            // update last clean time
            *(self.last_clean.write().await) = Instant::now();
        }
    }

    pub(crate) fn new(o_lifetime: Option<Duration>) -> Self {
        let lifetime = match o_lifetime {
            Some(life) if life > Duration::from_secs(1) => life,
            _ => Duration::from_millis(DEFAULT_ITEM_LIFETIME_MS),
        };
        Self {
            map: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            last_clean: Arc::new(tokio::sync::RwLock::new(Instant::now())),
            item_lifetime: lifetime,
        }
    }

    pub(crate) async fn hit_test<St: Storable>(&self, key: &St::Key) -> Option<DbRecord> {
        self.clean().await;

        debug!("BEGIN cache retrieve {:?}", key);
        let full_key = St::get_full_binary_key_id(key);

        let guard = self.map.read().await;
        let ptr: &HashMap<_, _> = &*guard;
        debug!("END cache retrieve");
        if let Some(result) = ptr.get(&full_key) {
            if result.expiration > Instant::now() {
                return Some(result.data.clone());
            }
        }
        None
    }

    pub(crate) async fn put(&self, record: &DbRecord) {
        self.clean().await;

        debug!("BEGIN cache put");
        let mut guard = self.map.write().await;
        let key = record.get_full_binary_id();
        // overwrite any existing items since a flush is requested
        let item = CachedItem {
            expiration: Instant::now() + self.item_lifetime,
            data: record.clone(),
        };
        (*guard).insert(key, item);
        debug!("END cache put");
    }

    pub(crate) async fn batch_put(&self, records: &[DbRecord]) {
        self.clean().await;

        debug!("BEGIN cache put batch");
        let mut guard = self.map.write().await;
        for record in records.iter() {
            let key = record.get_full_binary_id();
            let item = CachedItem {
                expiration: Instant::now() + self.item_lifetime,
                data: record.clone(),
            };
            (*guard).insert(key, item);
        }
        debug!("END cache put batch");
    }

    #[allow(dead_code)]
    pub(crate) async fn flush(&self) {
        debug!("BEGIN cache flush");
        let mut guard = self.map.write().await;
        (*guard).clear();
        debug!("END cache flush");
    }
}
