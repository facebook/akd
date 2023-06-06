// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

use akd::{ecvrf::HardCodedAkdVRF, storage::StorageManager, Configuration};
use log::info;
type InMemoryDb = akd::storage::memory::AsyncInMemoryDatabase;
use crate::test_config_serial;

test_config_serial!(test_directory_operations);
async fn test_directory_operations<TC: Configuration>() {
    crate::test_util::log_init(log::Level::Info);

    info!("\n\n******** Starting In-Memory Directory Operations Integration Test ********\n\n");

    let db = InMemoryDb::new();

    let vrf = HardCodedAkdVRF {};
    let storage_manager = StorageManager::new_no_cache(db);
    akd_test_tools::test_suites::directory_test_suite::<TC, _, HardCodedAkdVRF>(
        &storage_manager,
        500,
        &vrf,
    )
    .await;

    info!("\n\n******** Finished In-Memory Directory Operations Integration Test ********\n\n");
}

test_config_serial!(test_directory_operations_with_caching);
async fn test_directory_operations_with_caching<TC: Configuration>() {
    crate::test_util::log_init(log::Level::Info);

    info!("\n\n******** Starting In-Memory Directory Operations (w/caching) Integration Test ********\n\n");

    let db = InMemoryDb::new();

    let vrf = HardCodedAkdVRF {};
    let storage_manager = StorageManager::new(db, None, None, None);
    akd_test_tools::test_suites::directory_test_suite::<TC, _, HardCodedAkdVRF>(
        &storage_manager,
        500,
        &vrf,
    )
    .await;

    info!("\n\n******** Finished In-Memory Directory Operations (w/caching) Integration Test ********\n\n");
}
