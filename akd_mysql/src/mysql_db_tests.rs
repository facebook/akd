#![cfg(test)]
// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use serial_test::serial;

use crate::mysql::*;
// use serial_test::serial;

// *** Tests *** //

#[tokio::test]
// FIXME: Why is serial here??
#[serial]
async fn test_mysql_db() {
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
            MySqlCacheOptions::None,
            200,
        )
        .await;

        if let Err(error) = mysql_db.delete_data().await {
            println!("Error cleaning mysql prior to test suite: {}", error);
        }

        // The test cases
        akd::storage::tests::run_test_cases_for_storage_impl(&mysql_db).await;

        // clean the test infra
        if let Err(mysql_async::Error::Server(error)) = mysql_db.drop_tables().await {
            println!(
                "ERROR: Failed to clean MySQL test database with error {}",
                error
            );
        }
    } else {
        println!("WARN: Skipping MySQL test due to test guard noting that the docker container appears to not be running.");
    }
}
