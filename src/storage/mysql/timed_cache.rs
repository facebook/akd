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

const DEFAULT_ITEM_LIFETIME_MS: u64 = 30000;

pub(crate) struct CachedItem {
    expiration: Instant,
    data: DbRecord,
}

/// Implements a basic cahce with timing information which automatically flushes
/// expired entries and removes them
pub(crate) struct TimedCache {
    map: Arc<tokio::sync::RwLock<HashMap<Vec<u8>, CachedItem>>>,
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
    }

    pub(crate) fn new(o_lifetime: Option<Duration>) -> Self {
        let lifetime = match o_lifetime {
            Some(life) if life > Duration::from_secs(1) => life,
            _ => Duration::from_millis(DEFAULT_ITEM_LIFETIME_MS),
        };
        Self {
            map: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
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
            Some(result.data.clone())
        } else {
            None
        }
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
