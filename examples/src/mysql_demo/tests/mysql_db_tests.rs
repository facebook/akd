// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

use super::test_util::log_init;
use crate::mysql_demo::mysql::AsyncMySqlDatabase;

// *** Tests *** //

#[tokio::test]
async fn test_mysql_db() {
    log_init(log::Level::Info);
    if AsyncMySqlDatabase::test_guard() {
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

        if let Err(error) = mysql_db.delete_data().await {
            println!("Error cleaning mysql prior to test suite: {error}");
        }

        // The test cases
        let manager = akd::storage::tests::run_test_cases_for_storage_impl(mysql_db.clone()).await;

        // clean the test infra
        if let Err(mysql_async::Error::Server(error)) = manager.get_db().drop_tables().await {
            println!("ERROR: Failed to clean MySQL test database with error {error}");
        }
    } else {
        println!("WARN: Skipping MySQL test due to test guard noting that the docker container appears to not be running.");
    }
}
