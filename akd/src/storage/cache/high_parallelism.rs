// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module implements a higher-parallelism, async temporary cache for database
//! objects

use super::{CachedItem, DEFAULT_CACHE_CLEAN_FREQUENCY_MS, DEFAULT_ITEM_LIFETIME_MS};
use crate::storage::DbRecord;
use crate::storage::Storable;
use akd_core::SizeOf;
use dashmap::DashMap;
#[cfg(not(feature = "runtime_metrics"))]
use log::debug;
use log::info;
#[cfg(feature = "runtime_metrics")]
use log::{debug, error, warn};

#[cfg(feature = "runtime_metrics")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Implements a basic cache with timing information which automatically flushes
/// expired entries and removes them
#[derive(Clone)]
pub struct TimedCache {
    azks: Arc<RwLock<Option<DbRecord>>>,
    map: Arc<DashMap<Vec<u8>, CachedItem>>,
    last_clean: Arc<RwLock<Instant>>,
    can_clean: Arc<AtomicBool>,
    item_lifetime: Duration,
    memory_limit_bytes: Option<usize>,
    clean_frequency: Duration,

    #[cfg(feature = "runtime_metrics")]
    hit_count: Arc<AtomicU64>,
}

impl TimedCache {
    /// Log cache access metrics along with size information
    pub fn log_metrics(&self, _level: log::Level) {
        #[cfg(feature = "runtime_metrics")]
        {
            let hit_count = self.hit_count.swap(0, Ordering::Relaxed);
            let cache_size = self.map.len();

            let msg = format!("Cache hit since last: {hit_count}, cached size: {cache_size} items");
            match _level {
                log::Level::Trace => println!("{msg}"),
                log::Level::Debug => debug!("{}", msg),
                log::Level::Info => info!("{}", msg),
                log::Level::Warn => warn!("{}", msg),
                _ => error!("{}", msg),
            }
        }
    }
}

impl TimedCache {
    async fn clean(&self) {
        if !self.can_clean.load(Ordering::Relaxed) {
            // cleaning is disabled
            return;
        }

        let do_clean = {
            // we need the {} brackets in order to release the read lock, since we _may_ acquire a write lock shortly later
            *(self.last_clean.read().await) + self.clean_frequency < Instant::now()
        };
        if do_clean {
            let mut last_clean_write = self.last_clean.write().await;

            let now = Instant::now();
            if let Some(memory_limit_bytes) = self.memory_limit_bytes {
                let mut retained_size = 0;
                let mut num_retained = 0u32;
                let mut num_removed = 0u32;
                self.map.retain(|k, v| {
                    if v.expiration >= now {
                        retained_size += k.len() + v.size_of();
                        num_retained += 1;
                        true
                    } else {
                        num_removed += 1;
                        false
                    }
                });

                info!("Removed {} expired elements from the cache", num_removed);
                debug!("Retained cache size is {} bytes", retained_size);

                if retained_size > memory_limit_bytes {
                    info!("Retained cache size has exceeded the predefined limit, cleaning old entries");
                    // calculate the percentage we'd need to trim off to get to 100% utilization and take another 5%
                    let percent_clean =
                        0.05 + 1.0 - (memory_limit_bytes as f64) / (retained_size as f64);
                    // convert that to the number of items to delete based on the size of the dictionary
                    let num_clean = ((num_retained as f64) * percent_clean).ceil() as usize;
                    // sort the dict based on the oldest entries
                    let mut keys_and_expiration = self
                        .map
                        .iter()
                        .map(|kv| (kv.key().clone(), kv.value().expiration))
                        .collect::<Vec<_>>();
                    keys_and_expiration.sort_by(|(_, a), (_, b)| a.cmp(b));
                    // take `num_clean` old entries and remove them
                    for key in keys_and_expiration
                        .into_iter()
                        .take(num_clean)
                        .map(|(k, _)| k)
                    {
                        self.map.remove(&key);
                    }

                    debug!("END cache memory pressure clean")
                }
            } else {
                // memory pressure analysis is disabled, simply utilize timed cache cleaning
                self.map.retain(|_, v| v.expiration >= now);
            }

            // update last clean time
            *last_clean_write = Instant::now();
        }
    }

    /// Create a new timed cache instance. You can supply an optional item lifetime parameter
    /// or take the default (30s) and an optional memory-pressure limit, where the cache will be
    /// cleaned if too much memory is being utilized
    pub fn new(
        o_lifetime: Option<Duration>,
        o_memory_limit_bytes: Option<usize>,
        o_clean_frequency: Option<Duration>,
    ) -> Self {
        let lifetime = match o_lifetime {
            Some(life) if life > Duration::from_millis(1) => life,
            _ => Duration::from_millis(DEFAULT_ITEM_LIFETIME_MS),
        };
        let clean_frequency = match o_clean_frequency {
            Some(frequency) if frequency > Duration::from_millis(1) => frequency,
            _ => Duration::from_millis(DEFAULT_CACHE_CLEAN_FREQUENCY_MS),
        };
        Self {
            azks: Arc::new(RwLock::new(None)),
            map: Arc::new(DashMap::new()),
            last_clean: Arc::new(RwLock::new(Instant::now())),
            can_clean: Arc::new(AtomicBool::new(true)),
            item_lifetime: lifetime,
            memory_limit_bytes: o_memory_limit_bytes,
            clean_frequency,

            #[cfg(feature = "runtime_metrics")]
            hit_count: Arc::new(AtomicU64::new(0u64)),
        }
    }

    /// Perform a hit-test of the cache for a given key. If successful, Some(record) will be returned
    pub async fn hit_test<St: Storable>(&self, key: &St::StorageKey) -> Option<DbRecord> {
        self.clean().await;

        let full_key = St::get_full_binary_key_id(key);

        // special case for AZKS
        if full_key
            == crate::append_only_zks::Azks::get_full_binary_key_id(
                &crate::append_only_zks::DEFAULT_AZKS_KEY,
            )
        {
            // someone's requesting the AZKS object, return it from the special "cache" storage
            let record = self.azks.read().await.clone();

            #[cfg(feature = "runtime_metrics")]
            self.hit_count.fetch_add(1, Ordering::Relaxed);

            // AZKS objects cannot expire, they need to be manually flushed, so we don't need
            // to check the expiration as below
            return record;
        }

        if let Some(result) = self.map.get(&full_key) {
            #[cfg(feature = "runtime_metrics")]
            self.hit_count.fetch_add(1, Ordering::Relaxed);

            let ignore_clean = !self.can_clean.load(Ordering::Relaxed);
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
    }

    /// Put a batch of items into the cache, utilizing a single write lock
    pub async fn batch_put(&self, records: &[DbRecord]) {
        self.clean().await;

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
    }

    /// Flush the cache
    pub async fn flush(&self) {
        self.map.clear();
        *(self.azks.write().await) = None;
    }

    /// Retrieve all of the cached items
    pub async fn get_all(&self) -> Vec<DbRecord> {
        self.clean().await;

        let mut items = vec![];
        if let Some(record) = self.azks.read().await.clone() {
            items.push(record);
        }
        for kv in self.map.iter() {
            items.push(kv.value().data.clone());
        }

        items
    }

    /// Disable cache-cleaning (i.e. during a transaction)
    pub fn disable_clean(&self) {
        debug!("Disabling cache cleaning");
        self.can_clean.store(false, Ordering::Relaxed);
    }

    /// Re-enable cache cleaning (i.e. when a transaction is over)
    pub fn enable_clean(&self) {
        debug!("Enabling cache cleaning");
        self.can_clean.store(true, Ordering::Relaxed);
    }
}
