// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::StorageManager;
use akd_mysql::mysql::*;
use log::{error, info, warn};

#[tokio::test]
#[serial_test::serial]
async fn test_directory_operations() {
    crate::test_util::log_init(log::Level::Info);

    info!("\n\n******** Starting MySQL Directory Operations Integration Test ********\n\n");

    if AsyncMySqlDatabase::test_guard() {
        // create the "test" database
        if let Err(error) = AsyncMySqlDatabase::create_test_db(
            "localhost",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
        )
        .await
        {
            panic!("Error creating test database: {}", error);
        }

        // connect to the newly created test db
        let mysql_db = AsyncMySqlDatabase::new(
            "localhost",
            "test_db",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
            200,
        )
        .await
        .expect("Failed to create async mysql db");

        // delete all data from the db
        if let Err(error) = mysql_db.delete_data().await {
            error!("Error cleaning mysql prior to test suite: {}", error);
        }

        let vrf = HardCodedAkdVRF {};
        let storage_manager = StorageManager::new_no_cache(mysql_db.clone());
        akd_test_tools::test_suites::directory_test_suite::<_, HardCodedAkdVRF>(
            &storage_manager,
            50,
            &vrf,
        )
        .await;

        storage_manager.log_metrics(log::Level::Trace).await;

        // clean the test infra
        if let Err(mysql_async::Error::Server(error)) = storage_manager.get_db().drop_tables().await
        {
            error!(
                "ERROR: Failed to clean MySQL test database with error {}",
                error
            );
        }
    } else {
        warn!("WARN: Skipping MySQL test due to test guard noting that the docker container appears to not be running.");
    }

    info!("\n\n******** Completed MySQL Directory Operations Integration Test ********\n\n");
}

#[tokio::test]
#[serial_test::serial]
async fn test_directory_operations_with_caching() {
    crate::test_util::log_init(log::Level::Info);

    info!("\n\n******** Starting MySQL Directory Operations (w/caching) Integration Test ********\n\n");

    if AsyncMySqlDatabase::test_guard() {
        // create the "test" database
        if let Err(error) = AsyncMySqlDatabase::create_test_db(
            "localhost",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
        )
        .await
        {
            panic!("Error creating test database: {}", error);
        }

        // connect to the newly created test db
        let mysql_db = AsyncMySqlDatabase::new(
            "localhost",
            "test_db",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
            200,
        )
        .await
        .expect("Failed to create async mysql db");

        // delete all data from the db
        if let Err(error) = mysql_db.delete_data().await {
            error!("Error cleaning mysql prior to test suite: {}", error);
        }

        let vrf = HardCodedAkdVRF {};
        let storage_manager = StorageManager::new(mysql_db.clone(), None, None, None);
        akd_test_tools::test_suites::directory_test_suite::<_, HardCodedAkdVRF>(
            &storage_manager,
            50,
            &vrf,
        )
        .await;

        storage_manager.log_metrics(log::Level::Trace).await;

        // clean the test infra
        if let Err(mysql_async::Error::Server(error)) = storage_manager.get_db().drop_tables().await
        {
            error!(
                "ERROR: Failed to clean MySQL test database with error {}",
                error
            );
        }
    } else {
        warn!("WARN: Skipping MySQL test due to test guard noting that the docker container appears to not be running.");
    }

    info!("\n\n******** Completed MySQL Directory Operations (w/caching) Integration Test ********\n\n");
}

#[tokio::test]
#[serial_test::serial]
async fn test_lookups() {
    crate::test_util::log_init(log::Level::Info);

    info!("\n\n******** Starting MySQL Lookup Tests ********\n\n");

    if AsyncMySqlDatabase::test_guard() {
        // create the "test" database
        if let Err(error) = AsyncMySqlDatabase::create_test_db(
            "localhost",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
        )
        .await
        {
            panic!("Error creating test database: {}", error);
        }

        // connect to the newly created test db
        let mysql_db = AsyncMySqlDatabase::new(
            "localhost",
            "test_db",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
            200,
        )
        .await
        .expect("Failed to create async mysql db");

        // delete all data from the db
        if let Err(error) = mysql_db.delete_data().await {
            error!("Error cleaning mysql prior to test suite: {}", error);
        }

        let vrf = HardCodedAkdVRF {};
        let storage_manager = StorageManager::new(mysql_db, None, None, None);

        crate::test_util::test_lookups::<_, HardCodedAkdVRF>(&storage_manager, &vrf, 50, 5, 100)
            .await;

        // clean the test infra
        if let Err(mysql_async::Error::Server(error)) = storage_manager.get_db().drop_tables().await
        {
            error!(
                "ERROR: Failed to clean MySQL test database with error {}",
                error
            );
        }
    } else {
        warn!("WARN: Skipping MySQL test due to test guard noting that the docker container appears to not be running.");
    }

    info!("\n\n******** Completed MySQL Lookup Tests ********\n\n");
}
