// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module handles the caching implementation and testing for a time-based cache
//! which supports memory pressure shedding

use crate::storage::DbRecord;
use std::time::Instant;

#[cfg(test)]
mod tests;

/// items live for 30s by default
pub(crate) const DEFAULT_ITEM_LIFETIME_MS: u64 = 30000;
/// clean the cache every 15s by default
pub(crate) const DEFAULT_CACHE_CLEAN_FREQUENCY_MS: u64 = 15000;

pub(crate) struct CachedItem {
    pub(crate) expiration: Instant,
    pub(crate) data: DbRecord,
}

impl akd_core::SizeOf for CachedItem {
    fn size_of(&self) -> usize {
        // the size of an "Instant" varies based on the underlying implementation, so
        // we assume the largest which is 16 bytes on linux
        16 + self.data.size_of()
    }
}

// -------- sub modules -------- //

pub mod high_parallelism;

// -------- cache exports -------- //

pub use high_parallelism::TimedCache;
