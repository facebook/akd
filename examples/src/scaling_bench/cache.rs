// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Generic database caching trait for scaling benchmarks.
//!
//! Implementations save and load populated directories to disk so that
//! subsequent benchmark runs skip the expensive setup phase.

use std::fs;
use std::path::{Path, PathBuf};

use akd_core::types::EpochHash;
use akd_traits::bench::BenchmarkSetup;
use async_trait::async_trait;

/// Trait for saving/loading benchmark directories to/from disk.
///
/// Implementors provide serialization logic specific to their directory type.
/// The associated `CacheHandle` type carries any extra state needed for
/// serialization (e.g. a database handle) that isn't accessible from the
/// directory alone.
#[async_trait]
pub(crate) trait BenchCache: BenchmarkSetup {
    /// Extra state needed to save the directory (e.g. a database handle).
    type CacheHandle: Send;

    /// Create a fresh directory, returning both the directory and a cache handle.
    async fn create_directory_with_handle() -> (Self::Directory, Self::CacheHandle);

    /// Save the directory state and epoch hashes to `path`.
    async fn save(handle: &Self::CacheHandle, epoch_hashes: &[EpochHash], path: &Path);

    /// Load a cached directory and epoch hashes from `path`.
    /// Returns `None` if the file doesn't exist or deserialization fails.
    async fn load(path: &Path) -> Option<(Self::Directory, Vec<EpochHash>)>;
}

/// Return the cache directory path.
pub(crate) fn cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target")
        .join("bench-cache")
}

/// Return the cache file path for a given directory size.
pub(crate) fn cache_path(size: usize) -> PathBuf {
    cache_dir().join(format!("kd-N{}.bin", size))
}

/// Clear all cached databases.
pub(crate) fn clear() {
    let dir = cache_dir();
    if dir.exists() {
        if let Err(e) = fs::remove_dir_all(&dir) {
            eprintln!("Warning: failed to clear cache directory: {}", e);
        } else {
            println!("Cleared cache directory: {}", dir.display());
        }
    } else {
        println!("No cache directory found at {}", dir.display());
    }
}
