// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements a basic async timed cache

use crate::storage::DbRecord;
use crate::storage::Storable;
use log::{debug, error, info, trace, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

// item's live for 30s
const DEFAULT_ITEM_LIFETIME_MS: u64 = 30000;
// clean the cache every 15s
const CACHE_CLEAN_FREQUENCY_MS: u64 = 15000;

struct CachedItem {
    expiration: Instant,
    data: DbRecord,
}

/// Implements a basic cahce with timing information which automatically flushes
/// expired entries and removes them
pub struct TimedCache {
    azks: Arc<tokio::sync::RwLock<Option<DbRecord>>>,
    map: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, CachedItem>>>,
    last_clean: Arc<tokio::sync::RwLock<Instant>>,
    can_clean: Arc<tokio::sync::RwLock<bool>>,
    item_lifetime: Duration,
    hit_count: Arc<tokio::sync::RwLock<u64>>,
}

impl TimedCache {
    /// Log cache access metrics along with size information
    pub async fn log_metrics(&self, level: log::Level) {
        let mut hit = self.hit_count.write().await;
        let hit_count = *hit;
        *hit = 0;
        let guard = self.map.read().await;
        let cache_size = (*guard).keys().len();
        let msg = format!(
            "Cache hit since last: {}, cached size: {} items",
            hit_count, cache_size
        );
        match level {
            log::Level::Trace => trace!("{}", msg),
            log::Level::Debug => debug!("{}", msg),
            log::Level::Info => info!("{}", msg),
            log::Level::Warn => warn!("{}", msg),
            _ => error!("{}", msg),
        }
    }
}

impl Clone for TimedCache {
    fn clone(&self) -> Self {
        TimedCache {
            azks: self.azks.clone(),
            map: self.map.clone(),
            last_clean: self.last_clean.clone(),
            can_clean: self.can_clean.clone(),
            item_lifetime: self.item_lifetime,
            hit_count: self.hit_count.clone(),
        }
    }
}

impl TimedCache {
    async fn clean(&self) {
        let can_clean_guard = self.can_clean.read().await;
        if !*can_clean_guard {
            // cleaning is disabled
            return;
        }

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

    /// Create a new timed cache instance. You can supply an optional item lifetime parameter
    /// or take the default (30s)
    pub fn new(o_lifetime: Option<Duration>) -> Self {
        let lifetime = match o_lifetime {
            Some(life) if life > Duration::from_secs(1) => life,
            _ => Duration::from_millis(DEFAULT_ITEM_LIFETIME_MS),
        };
        Self {
            azks: Arc::new(tokio::sync::RwLock::new(None)),
            map: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            last_clean: Arc::new(tokio::sync::RwLock::new(Instant::now())),
            can_clean: Arc::new(tokio::sync::RwLock::new(true)),
            item_lifetime: lifetime,
            hit_count: Arc::new(tokio::sync::RwLock::new(0)),
        }
    }

    /// Perform a hit-test of the cache for a given key. If successful, Some(record) will be returned
    pub async fn hit_test<St: Storable>(&self, key: &St::Key) -> Option<DbRecord> {
        self.clean().await;

        debug!("BEGIN cache retrieve {:?}", key);

        let full_key = St::get_full_binary_key_id(key);

        // special case for AZKS
        if full_key
            == crate::append_only_zks::Azks::get_full_binary_key_id(
                &crate::append_only_zks::DEFAULT_AZKS_KEY,
            )
        {
            // someone's requesting the AZKS object, return it from the special "cache" storage
            let record = self.azks.read().await.clone();
            debug!("END cache retrieve");
            if record.is_some() {
                *(self.hit_count.write().await) += 1;
            }
            // AZKS objects cannot expire, they need to be manually flushed, so we don't need
            // to check the expiration as below
            return record;
        }

        let guard = self.map.read().await;
        let ptr: &HashMap<_, _> = &*guard;
        debug!("END cache retrieve");
        if let Some(result) = ptr.get(&full_key) {
            *(self.hit_count.write().await) += 1;

            let ignore_clean = !*self.can_clean.read().await;
            // if we've disabled cache cleaning, we're in the middle
            // of an in-memory transaction and should ignore expiration
            // of cache items until this flag is disabled again
            if ignore_clean || result.expiration > Instant::now() {
                return Some(result.data.clone());
            }
        }
        None
    }

    /// Put an item into the cache
    pub async fn put(&self, record: &DbRecord) {
        self.clean().await;

        debug!("BEGIN cache put");
        let key = record.get_full_binary_id();

        // special case for AZKS
        if let DbRecord::Azks(azks_ref) = &record {
            let mut guard = self.azks.write().await;
            *guard = Some(DbRecord::Azks(azks_ref.clone()));
        } else {
            let mut guard = self.map.write().await;
            // overwrite any existing items since a flush is requested
            let item = CachedItem {
                expiration: Instant::now() + self.item_lifetime,
                data: record.clone(),
            };
            (*guard).insert(key, item);
        }
        debug!("END cache put");
    }

    /// Put a batch of items into the cache, utilizing a single write lock
    pub async fn batch_put(&self, records: &[DbRecord]) {
        self.clean().await;

        debug!("BEGIN cache put batch");
        let mut guard = self.map.write().await;
        for record in records.iter() {
            if let DbRecord::Azks(azks_ref) = &record {
                let mut azks_guard = self.azks.write().await;
                *azks_guard = Some(DbRecord::Azks(azks_ref.clone()));
            } else {
                let key = record.get_full_binary_id();
                let item = CachedItem {
                    expiration: Instant::now() + self.item_lifetime,
                    data: record.clone(),
                };
                (*guard).insert(key, item);
            }
        }
        debug!("END cache put batch");
    }

    /// Flush the cache
    pub async fn flush(&self) {
        debug!("BEGIN cache flush");
        let mut guard = self.map.write().await;
        (*guard).clear();
        let mut azks_guard = self.azks.write().await;
        *azks_guard = None;
        debug!("END cache flush");
    }

    /// Disable cache-cleaning (i.e. during a transaction)
    pub async fn disable_clean(&self) {
        debug!("Disabling MySQL object cache cleaning");
        let mut guard = self.can_clean.write().await;
        (*guard) = false;
    }

    /// Re-enable cache cleaning (i.e. when a transaction is over)
    pub async fn enable_clean(&self) {
        debug!("Enabling MySQL object cache cleaning");
        let mut guard = self.can_clean.write().await;
        (*guard) = true;
    }
}
