// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module handles various types of caches supported in the AKD crate which are
//! helpful for caching storage results for faster re-access

use crate::storage::DbRecord;
use std::time::Instant;

/// item's live for 30s
pub(crate) const DEFAULT_ITEM_LIFETIME_MS: u64 = 30000;
/// clean the cache every 15s
pub(crate) const CACHE_CLEAN_FREQUENCY_MS: u64 = 15000;
/// Default memory limit in bytes ~ 1GB
pub(crate) const DEFAULT_MEMORY_LIMIT_BYTES: usize = 1024 * 1024 * 1024;

pub(crate) struct CachedItem {
    pub(crate) expiration: Instant,
    pub(crate) data: DbRecord,
}

impl super::SizeOf for CachedItem {
    fn size_of(&self) -> usize {
        // the size of an "Instant" varies based on the underlying implementation, so
        // we assume the largest which is 16 bytes on linux
        16 + self.data.size_of()
    }
}

// -------- sub modules -------- //

#[cfg(not(feature = "high_parallelism"))]
pub mod basic;
#[cfg(feature = "high_parallelism")]
pub mod high_parallelism;

// -------- cache exports -------- //

#[cfg(not(feature = "high_parallelism"))]
pub use basic::TimedCache;
#[cfg(feature = "high_parallelism")]
pub use high_parallelism::TimedCache;
