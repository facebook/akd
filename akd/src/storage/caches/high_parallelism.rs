// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements a higher-parallelism, async temporary cache for database
//! objects

use super::{
    CachedItem, CACHE_CLEAN_FREQUENCY_MS, DEFAULT_ITEM_LIFETIME_MS, DEFAULT_MEMORY_LIMIT_BYTES,
};
use crate::storage::DbRecord;
#[cfg(feature = "memory_pressure")]
use crate::storage::SizeOf;
use crate::storage::Storable;
use dashmap::DashMap;
use log::debug;
#[cfg(feature = "memory_pressure")]
use log::info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Implements a basic cahce with timing information which automatically flushes
/// expired entries and removes them
pub struct TimedCache {
    azks: Arc<tokio::sync::RwLock<Option<DbRecord>>>,
    map: Arc<DashMap<Vec<u8>, CachedItem>>,
    last_clean: Arc<tokio::sync::RwLock<Instant>>,
    can_clean: Arc<AtomicBool>,
    item_lifetime: Duration,
    memory_limit_bytes: usize,
}

impl TimedCache {
    /// Log cache access metrics along with size information
    pub async fn log_metrics(&self, _level: log::Level) {
        // in high-parallelism, we don't keep any metric counters to minimize thread locking
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
            memory_limit_bytes: self.memory_limit_bytes,
        }
    }
}

impl TimedCache {
    async fn clean(&self) {
        let can_clean = self.can_clean.load(Ordering::Relaxed);
        if !can_clean {
            // cleaning is disabled
            return;
        }

        let do_clean = {
            // we need the {} brackets in order to release the read lock, since we _may_ acquire a write lock shortly later
            *(self.last_clean.read().await) + Duration::from_millis(CACHE_CLEAN_FREQUENCY_MS)
                < Instant::now()
        };
        if do_clean {
            let mut last_clean_write = self.last_clean.write().await;
            debug!("BEGIN clean cache");

            let now = Instant::now();
            #[cfg(not(feature = "memory_pressure"))]
            self.map.retain(|_, v| v.expiration >= now);
            #[cfg(feature = "memory_pressure")]
            {
                let mut retained_size = 0;
                let mut retained_elements = 0f64;
                let mut removed = 0;
                self.map.retain(|k, v| {
                    if v.expiration >= now {
                        retained_size += k.len() + v.size_of();
                        retained_elements += 1.0;
                        true
                    } else {
                        removed += 1;
                        false
                    }
                });
                info!("Removed {} expired elements from the cache", removed);
                debug!("Retained cache size is {} bytes", retained_size);
                if retained_size > self.memory_limit_bytes {
                    debug!("BEGIN cache memory pressure clean");
                    info!("Retained cache size has exceeded the predefined limit, cleaning old entries");
                    // calculate the percentage we'd need to trim off to get to 100% utilization and take another 5%
                    let percent_clean =
                        0.05 + 1.0 - (self.memory_limit_bytes as f64) / (retained_size as f64);
                    // convert that to the number of items to delete based on the size of the dictionary
                    let num_clean = (retained_elements * percent_clean).round() as usize;
                    // sort the dict based on the oldest entries
                    let mut keys_and_expiration = self
                        .map
                        .iter()
                        .map(|kv| (kv.key().clone(), kv.value().expiration))
                        .collect::<Vec<_>>();
                    keys_and_expiration.sort_by(|(_, a), (_, b)| a.cmp(b));
                    // take those old entries, and remove them
                    for key in keys_and_expiration
                        .into_iter()
                        .take(num_clean)
                        .map(|(k, _)| k)
                    {
                        self.map.remove(&key);
                    }
                    debug!("END cache memory pressure clean")
                }
            }

            debug!("END clean cache");

            // update last clean time
            *last_clean_write = Instant::now();
        }
    }

    #[cfg(feature = "memory_pressure")]
    /// Measure the size of the underlying hashmap and storage utilized
    pub fn measure(&self) -> usize {
        self.map
            .iter()
            .map(|kv| kv.key().len() + kv.value().size_of())
            .sum()
    }

    /// Create a new timed cache instance. You can supply an optional item lifetime parameter
    /// or take the default (30s)
    pub fn new(o_lifetime: Option<Duration>, o_memory_limit_bytes: Option<usize>) -> Self {
        let lifetime = match o_lifetime {
            Some(life) if life > Duration::from_secs(1) => life,
            _ => Duration::from_millis(DEFAULT_ITEM_LIFETIME_MS),
        };
        let memory_limit_bytes: usize = o_memory_limit_bytes.unwrap_or(DEFAULT_MEMORY_LIMIT_BYTES);
        Self {
            azks: Arc::new(tokio::sync::RwLock::new(None)),
            map: Arc::new(DashMap::new()),
            last_clean: Arc::new(tokio::sync::RwLock::new(Instant::now())),
            can_clean: Arc::new(AtomicBool::new(true)),
            item_lifetime: lifetime,
            memory_limit_bytes,
        }
    }

    /// Perform a hit-test of the cache for a given key. If successful, Some(record) will be returned
    pub async fn hit_test<St: Storable>(&self, key: &St::StorageKey) -> Option<DbRecord> {
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

            // AZKS objects cannot expire, they need to be manually flushed, so we don't need
            // to check the expiration as below
            return record;
        }

        if let Some(result) = self.map.get(&full_key) {
            let ignore_clean = !self.can_clean.load(Ordering::Relaxed);
            // if we've disabled cache cleaning, we're in the middle
            // of an in-memory transaction and should ignore expiration
            // of cache items until this flag is disabled again
            if ignore_clean || result.expiration > Instant::now() {
                debug!("END cache retrieve");
                return Some(result.data.clone());
            }
        }
        debug!("END cache retrieve");
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
            let item = CachedItem {
                expiration: Instant::now() + self.item_lifetime,
                data: record.clone(),
            };
            self.map.insert(key, item);
        }
        debug!("END cache put");
    }

    /// Put a batch of items into the cache, utilizing a single write lock
    pub async fn batch_put(&self, records: &[DbRecord]) {
        self.clean().await;

        debug!("BEGIN cache put batch");
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
                self.map.insert(key, item);
            }
        }
        debug!("END cache put batch");
    }

    /// Flush the cache
    pub async fn flush(&self) {
        debug!("BEGIN cache flush");
        self.map.clear();
        let mut azks_guard = self.azks.write().await;
        *azks_guard = None;
        debug!("END cache flush");
    }

    /// Disable cache-cleaning (i.e. during a transaction)
    pub fn disable_clean(&self) {
        debug!("Disabling MySQL object cache cleaning");
        self.can_clean.store(false, Ordering::Relaxed);
    }

    /// Re-enable cache cleaning (i.e. when a transaction is over)
    pub fn enable_clean(&self) {
        debug!("Enabling MySQL object cache cleaning");
        self.can_clean.store(true, Ordering::Relaxed);
    }
}
