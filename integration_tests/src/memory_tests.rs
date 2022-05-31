// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use akd::ecvrf::HardCodedAkdVRF;
use log::info;

type InMemoryDb = akd::storage::memory::AsyncInMemoryDatabase;

#[tokio::test]
#[serial_test::serial]
async fn test_directory_operations() {
    crate::test_util::log_init(log::Level::Info);

    info!("\n\n******** Starting In-Memory Directory Operations Integration Test ********\n\n");

    let db = InMemoryDb::new();

    let vrf = HardCodedAkdVRF {};
    akd_test_tools::test_suites::directory_test_suite::<_, HardCodedAkdVRF>(&db, 500, &vrf).await;

    info!("\n\n******** Finished In-Memory Directory Operations Integration Test ********\n\n");
}
