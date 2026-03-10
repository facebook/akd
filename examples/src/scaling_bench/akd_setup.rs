// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! AKD (WhatsAppV1) implementation of [`BenchmarkSetup`] and [`BenchCache`].

use std::fs;
use std::path::Path;
use std::sync::Arc;

use akd::append_only_zks::AzksParallelismConfig;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::manager::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::types::DbRecord;
use akd::storage::{Database, StorageUtil};
use akd::{AkdLabel, AkdValue, Directory, EpochHash, WhatsAppV1Configuration};
use akd_traits::bench::BenchmarkSetup;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::cache::BenchCache;

pub(crate) struct AkdSetup;

#[async_trait]
impl BenchmarkSetup for AkdSetup {
    type Directory = Directory<WhatsAppV1Configuration, AsyncInMemoryDatabase, HardCodedAkdVRF>;

    async fn create_directory() -> Self::Directory {
        let db = AsyncInMemoryDatabase::new();
        let storage = StorageManager::new_no_cache(db);
        let vrf = HardCodedAkdVRF {};
        Directory::<WhatsAppV1Configuration, _, _>::new(
            storage,
            vrf,
            AzksParallelismConfig::default(),
        )
        .await
        .unwrap()
    }

    fn generate_test_data(num_entries: usize, seed: u64) -> Vec<(AkdLabel, AkdValue)> {
        (0..num_entries)
            .map(|i| {
                let label = format!("user_{}", i);
                let value = format!("value_{}_{}", seed, i);
                (AkdLabel::from(&label), AkdValue::from(&value))
            })
            .collect()
    }

    fn name() -> &'static str {
        "AKD (WhatsAppV1)"
    }
}

/// Serializable cache data containing all database records and epoch hashes.
#[derive(Serialize, Deserialize)]
struct CacheData {
    records: Vec<DbRecord>,
    epoch_hashes: Vec<(u64, [u8; 32])>,
}

#[async_trait]
impl BenchCache for AkdSetup {
    type CacheHandle = Arc<AsyncInMemoryDatabase>;

    async fn create_directory_with_handle() -> (Self::Directory, Self::CacheHandle) {
        let db = AsyncInMemoryDatabase::new();
        let storage = StorageManager::new_no_cache(db);
        let db_arc = storage.get_db();
        let vrf = HardCodedAkdVRF {};
        let dir = Directory::<WhatsAppV1Configuration, _, _>::new(
            storage,
            vrf,
            AzksParallelismConfig::default(),
        )
        .await
        .unwrap();
        (dir, db_arc)
    }

    async fn save(handle: &Self::CacheHandle, epoch_hashes: &[EpochHash], path: &Path) {
        let records = handle.batch_get_all_direct().await.unwrap();
        let hashes: Vec<(u64, [u8; 32])> = epoch_hashes
            .iter()
            .map(|eh| (eh.epoch(), eh.hash()))
            .collect();

        let data = CacheData {
            records,
            epoch_hashes: hashes,
        };

        let encoded = bincode::serialize(&data).unwrap();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }

        fs::write(path, &encoded).unwrap();

        let size_mb = encoded.len() as f64 / (1024.0 * 1024.0);
        println!("  Saved cache ({:.1} MB): {}", size_mb, path.display());
    }

    async fn load(path: &Path) -> Option<(Self::Directory, Vec<EpochHash>)> {
        let bytes = fs::read(path).ok()?;

        let data: CacheData = match bincode::deserialize(&bytes) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "Warning: failed to deserialize cache {}: {}",
                    path.display(),
                    e
                );
                return None;
            }
        };

        let db = AsyncInMemoryDatabase::new();
        if let Err(e) = db
            .batch_set(data.records, akd::storage::DbSetState::General)
            .await
        {
            eprintln!("Warning: failed to restore database from cache: {}", e);
            return None;
        }

        let storage = StorageManager::new_no_cache(db);
        let vrf = HardCodedAkdVRF {};
        let akd_dir = match Directory::<WhatsAppV1Configuration, _, _>::new(
            storage,
            vrf,
            AzksParallelismConfig::default(),
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Warning: failed to create directory from cache: {}", e);
                return None;
            }
        };

        let epoch_hashes: Vec<EpochHash> = data
            .epoch_hashes
            .into_iter()
            .map(|(epoch, digest)| EpochHash(epoch, digest))
            .collect();

        let size_mb = bytes.len() as f64 / (1024.0 * 1024.0);
        println!("  Loaded cache ({:.1} MB): {}", size_mb, path.display());

        Some((akd_dir, epoch_hashes))
    }
}
