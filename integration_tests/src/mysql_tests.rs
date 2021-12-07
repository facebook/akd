// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

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
            MySqlCacheOptions::Default,
            200,
        )
        .await;

        // delete all data from the db
        if let Err(error) = mysql_db.delete_data().await {
            error!("Error cleaning mysql prior to test suite: {}", error);
        }

        crate::test_util::directory_test_suite(&mysql_db, 50).await;

        // clean the test infra
        if let Err(mysql_async::error::Error::Server(error)) = mysql_db.test_cleanup().await {
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
