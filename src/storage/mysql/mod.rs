// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use crate::node_state::NodeLabel;
use crate::storage::types::{StorageType, UserData, UserState, UserStateRetrievalFlag, Username};
use crate::storage::Storage;
use async_trait::async_trait;
use mysql_async::prelude::*;
use mysql_async::*;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

const TABLE: &str = "data";
const USER_TABLE: &str = "user_data";
const MAXIMUM_SQL_TIER_CONNECTION_TIMEOUT_SECS: u64 = 300;
const SQL_RECONNECTION_DELAY_SECS: u64 = 5;

/*
    MySql documentation: https://docs.rs/mysql_async/0.28.1/mysql_async/
*/

/// Represents an _asynchronous_ connection to a MySQL database
pub struct AsyncMySqlDatabase {
    opts: Opts,
    pool: Arc<tokio::sync::RwLock<Pool>>,
    is_healthy: Arc<Mutex<bool>>,
}

impl AsyncMySqlDatabase {
    #[allow(unused)]
    pub async fn new<T: Into<String>>(
        endpoint: T,
        database: T,
        user: Option<T>,
        password: Option<T>,
        port: Option<u16>,
    ) -> Self {
        let dport = port.unwrap_or(1u16);
        let opts: Opts = OptsBuilder::default()
            .ip_or_hostname(endpoint)
            .db_name(Option::from(database))
            .user(user)
            .pass(password)
            .tcp_port(dport)
            .into();

        #[allow(clippy::mutex_atomic)]
        let healthy = Arc::new(Mutex::new(false));
        let pool = Self::new_connection_pool(&opts, &healthy).await.unwrap();

        Self {
            opts,
            pool: Arc::new(tokio::sync::RwLock::new(pool)),
            is_healthy: healthy,
        }
    }

    /// Determine if the db connection is healthy at present
    pub fn is_healthy(&self) -> bool {
        let is_healthy_guard = self.is_healthy.lock().unwrap();
        *is_healthy_guard
    }

    fn check_for_infra_error<T>(
        &self,
        result: core::result::Result<T, mysql_async::Error>,
    ) -> core::result::Result<T, mysql_async::Error> {
        match result {
            Err(err) => {
                let is_connection_infra_error: bool = match &err {
                    mysql_async::Error::Other(_) | mysql_async::Error::Url(_) => false,

                    mysql_async::Error::Driver(_)
                    | mysql_async::Error::Io(_)
                    | mysql_async::Error::Server(_) => true,
                };

                // If error is due to infra error (e.g bad connection) refresh
                // connection pool in background. This allows current request to
                // finish (with err) while blocking subsequent requests until a
                // healthy connection is restored.
                if is_connection_infra_error {
                    let db = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(err) = db.refresh_connection_pool().await {
                            println!("Error: Error refreshing MySql connection pool: {:?}", err);
                        }
                    });
                }

                Err::<T, mysql_async::Error>(err)
            }
            Ok(t) => Ok(t),
        }
    }

    async fn get_connection(&self) -> Result<mysql_async::Conn> {
        let /*mut*/ connection = {
            if self.is_healthy() {
                let connection_pool_guard = self.pool.read().await;
                let connection_pool: &Pool = &*connection_pool_guard;

                connection_pool.get_conn().await?
            } else {
                // Connection pool is currently unhealthy and queries are
                // disallowed. Connection pool is being async refreshed in
                // background and will soon become healthy, so no action required

                // fail the connection
                return Err(mysql_async::Error::Driver(mysql_async::DriverError::PoolDisconnected));
            }
        };

        // // Ensure we are running in TRADITIONAL mysql mode. TRADITIONAL mysql
        // // converts many warnings to errors, for example it will reject too
        // // large blob entries instead of truncating them with a warning.
        // // This is essential for our system, since SEE relies on all data in our
        // // XDB being exactly what it wrote.
        // connection.query("SET SESSION sql_mode = 'TRADITIONAL'").await?;

        Ok(connection)
    }

    async fn setup_database(
        conn: &mut mysql_async::Conn,
    ) -> core::result::Result<(), mysql_async::Error> {
        let mut tx = conn.start_transaction(TxOpts::default()).await?;
        let result = async {
            // main data table (for all tree nodes, etc)
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + TABLE
                + "` (`key` VARCHAR(512) NOT NULL, `type` SMALLINT UNSIGNED NOT NULL, `value` VARBINARY(2000), PRIMARY KEY (`key`, `type`)"
                + ")";

            tx.query_drop(command).await?;

            // user data table
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned() + USER_TABLE + "`"
                + " (`username` VARCHAR(512) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, `version` BIGINT UNSIGNED NOT NULL,"
                + " `node_label_val` BIGINT UNSIGNED NOT NULL, `node_label_len` INT UNSIGNED NOT NULL, `data` VARCHAR(2000),"
                + " PRIMARY KEY(`username`, `epoch`)"
                + " )";
            tx.query_drop(command).await?;

            Ok::<(), mysql_async::Error>(())
        };

        if let Err(err) = result.await {
            tx.rollback().await?;
            return Err(err);
        }

        tx.commit().await?;
        Ok(())
    }

    // Occasionally our connection pool will become stale. This happens
    // e.g on DB master promotions during mysql upgrades. In these scenarios our
    // queries will begin to fail, and we will need to call this method to
    // "refresh" the pool.
    async fn refresh_connection_pool(&self) -> core::result::Result<(), StorageError> {
        {
            let mut is_healthy_guard = self.is_healthy.lock().unwrap();
            if !*is_healthy_guard {
                println!("Info: Already refreshing MySql connection pool!");
                return Ok(());
            }

            *is_healthy_guard = false;
        }
        println!("Warn: Refreshing MySql connection pool.");

        // Grab early write lock so no new queries can be initiated before
        // connection pool is refreshed.
        let mut connection_pool_guard = self.pool.write().await;
        let pool = Self::new_connection_pool(&self.opts, &self.is_healthy).await?;
        *connection_pool_guard = pool;

        Ok(())
    }

    async fn new_connection_pool(
        opts: &mysql_async::Opts,
        is_healthy: &Arc<Mutex<bool>>,
    ) -> core::result::Result<mysql_async::Pool, StorageError> {
        let start = Instant::now();
        let mut attempts = 1;

        loop {
            let ip = opts.ip_or_hostname();
            let pool_options = opts.clone();
            let pool = Pool::new(pool_options);
            let conn = pool.get_conn().await;

            if let Ok(mut _conn) = conn {
                if let Ok(()) = Self::setup_database(&mut _conn).await {
                    // set the healthy flag to true
                    let mut is_healthy_guard = is_healthy.lock().unwrap();
                    *is_healthy_guard = true;

                    return Ok(pool);
                }
            }

            if start.elapsed().as_secs() > MAXIMUM_SQL_TIER_CONNECTION_TIMEOUT_SECS {
                let message = format!(
                    "Unable to get a SQL connection to {} after {} attempts in {} seconds",
                    ip,
                    attempts,
                    start.elapsed().as_secs()
                );
                return Err(StorageError::Connection(message));
            }

            println!("Warning: Failed {:?} reconnection attempt(s) to MySQL database. Will retry in {} seconds", attempts, SQL_RECONNECTION_DELAY_SECS);

            tokio::time::sleep(tokio::time::Duration::from_secs(
                SQL_RECONNECTION_DELAY_SECS,
            ))
            .await;

            attempts += 1
        }
    }

    /// Delete all the data in the tables
    #[allow(dead_code)]
    pub async fn delete_data(&self) -> core::result::Result<(), mysql_async::Error> {
        let mut conn = self.get_connection().await?;

        let command = "DELETE FROM `".to_owned() + TABLE + "`";
        conn.query_drop(command).await?;

        let command = "DELETE FROM `".to_owned() + USER_TABLE + "`";
        conn.query_drop(command).await?;

        Ok(())
    }

    /// Cleanup the test data table
    #[allow(dead_code)]
    pub(crate) async fn test_cleanup(&self) -> core::result::Result<(), mysql_async::Error> {
        let mut conn = self.get_connection().await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE + "`";
        conn.query_drop(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + USER_TABLE + "`";
        conn.query_drop(command).await?;

        Ok(())
    }

    /// Determine if the MySQL environment is available for execution (i.e. docker container is running)
    #[allow(dead_code)]
    pub(crate) fn test_guard() -> bool {
        let output = Command::new("/usr/local/bin/docker")
            .args(["container", "ls", "-f", "name=seemless-test-db"])
            .output();
        // docker threw some kind of error running, assume down
        if let Ok(result) = output {
            // the result will look like
            //
            // CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS         PORTS                                                  NAMES
            // 4bd11d9e28f2   ecac195d15af   "docker-entrypoint.s…"   4 minutes ago   Up 4 minutes   33060/tcp, 0.0.0.0:8001->3306/tcp, :::8001->3306/tcp   seemless-test-db
            //
            // so there should be 2 output lines assuming all is successful and the container is running.

            let err = std::str::from_utf8(&result.stderr);
            if let Ok(error_message) = err {
                if !error_message.is_empty() {
                    println!("Error executing docker command: {}", error_message);
                }
            }

            let lines = std::str::from_utf8(&result.stdout).unwrap().lines().count();
            return lines >= 2;
        }

        // docker may have thrown an error, just fail
        false
    }
}

#[async_trait]
impl Storage for AsyncMySqlDatabase {
    async fn set(
        &self,
        pos: String,
        dt: StorageType,
        val: &[u8],
    ) -> core::result::Result<(), StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let statement_text = "INSERT INTO `".to_owned()
                + TABLE
                + "` (`key`, `type`, `value`) VALUES (:the_key, :the_type, :the_value) ON DUPLICATE KEY UPDATE `value` = :the_value";
            let out = conn
                .exec_drop(
                    statement_text,
                    params! { "the_key" => pos, "the_type" => dt as u16, "the_value" => val },
                )
                .await;
            self.check_for_infra_error(out)?;
            Ok::<(), mysql_async::Error>(())
        };

        match result.await {
            Ok(()) => Ok(()),
            Err(code) => Err(StorageError::SetError(code.to_string())),
        }
    }
    async fn get(
        &self,
        pos: String,
        dt: StorageType,
    ) -> core::result::Result<Vec<u8>, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;

            let statement_text = "SELECT `key`, `type`, `value` FROM `".to_owned()
                + TABLE
                + "` WHERE `key` = :the_key AND `type` = :the_type LIMIT 1";
            let statement = conn.prep(statement_text).await?;
            let out = conn
                .exec_first(
                    statement,
                    params! { "the_key" => pos, "the_type" => dt as u16 },
                )
                .await;
            let result: Option<(String, u16, Vec<u8>)> = self.check_for_infra_error(out)?;

            if let Some((_key, _type, value)) = result {
                return Ok(Some(value));
            }
            Ok::<Option<Vec<u8>>, mysql_async::Error>(None)
        };

        match result.await {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(StorageError::GetError(String::from("Not found"))),
            Err(other) => Err(StorageError::GetError(other.to_string())),
        }
    }

    async fn get_all(
        &self,
        data_type: StorageType,
        num: Option<usize>,
    ) -> core::result::Result<Vec<Vec<u8>>, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;

            let mut statement_text =
                "SELECT `value` FROM `".to_owned() + TABLE + "` WHERE `type` = :the_type";
            let mut params_map = vec![("the_type", Value::from(data_type as u16))];
            if let Some(limit) = num {
                statement_text += " LIMIT :the_limit";
                params_map.push(("the_limit", Value::from(limit)));
            }
            let statement = conn.prep(statement_text).await?;
            let out = conn
                .exec_map(statement, mysql_async::Params::from(params_map), |value| {
                    value
                })
                .await;
            let result = self.check_for_infra_error(out)?;
            Ok::<Vec<Vec<u8>>, mysql_async::Error>(result)
        };

        match result.await {
            Ok(result) => Ok(result),
            Err(other) => Err(StorageError::GetError(other.to_string())),
        }
    }

    async fn append_user_state(
        &self,
        username: &Username,
        value: &UserState,
    ) -> core::result::Result<(), StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let statement_text = "INSERT INTO `".to_owned()
                + USER_TABLE
                + "` (`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`)"
                + " VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)";
            let prepped = conn.prep(statement_text).await?;
            let out = conn
                .exec_drop(
                    prepped,
                    params! {
                        "username" => username.0.clone(),
                        "epoch" => value.epoch,
                        "version" => value.version,
                        "node_label_val" => value.label.val,
                        "node_label_len" => value.label.len,
                        "data" => value.plaintext_val.0.clone()
                    },
                )
                .await;
            self.check_for_infra_error(out)?;
            Ok::<(), mysql_async::Error>(())
        };

        match result.await {
            Ok(()) => Ok(()),
            Err(code) => Err(StorageError::SetError(code.to_string())),
        }
    }

    async fn append_user_states(
        &self,
        values: Vec<(Username, UserState)>,
    ) -> core::result::Result<(), StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;

            let statement_text = "INSERT INTO `".to_owned()
                + USER_TABLE
                + "` (`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`)"
                + " VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)";
            // create a transaction to perform the operations on
            let mut tx = conn.start_transaction(TxOpts::default()).await?;
            let mut steps = Ok(());
            for chunk in values.chunks(100) {
                let prepped = tx.prep(statement_text.clone()).await?;
                let out = tx
                    .exec_batch(
                        prepped,
                        chunk.iter().map(|(name, value)| {
                            params! {
                                "username" => name.0.clone(),
                                "epoch" => value.epoch,
                                "version" => value.version,
                                "node_label_val" => value.label.val,
                                "node_label_len" => value.label.len,
                                "data" => value.plaintext_val.0.clone()
                            }
                        }),
                    )
                    .await;
                steps = self.check_for_infra_error(out);
                if steps.is_err() {
                    break;
                }
            }

            // if any of the steps returns an error, fail the entire transaction to in an atomic state
            if steps.is_err() {
                tx.rollback().await?;
            } else {
                tx.commit().await?;
            }
            Ok::<(), mysql_async::Error>(())
        };

        match result.await {
            Ok(()) => Ok(()),
            Err(code) => Err(StorageError::SetError(code.to_string())),
        }
    }

    async fn get_user_data(
        &self,
        username: &Username,
    ) -> core::result::Result<UserData, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let statement_text =
                "SELECT `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                    .to_owned()
                    + USER_TABLE
                    + "` WHERE `username` = :the_user";
            let prepped = conn.prep(statement_text).await?;
            let out = conn
                .exec_map(
                    prepped,
                    params! { "the_user" => username.0.clone() },
                    |(epoch, version, node_label_val, node_label_len, data)| UserState {
                        epoch,
                        version,
                        label: NodeLabel {
                            val: node_label_val,
                            len: node_label_len,
                        },
                        plaintext_val: crate::storage::types::Values(data),
                    },
                )
                .await;
            let selected_records = self.check_for_infra_error(out)?;
            Ok::<UserData, mysql_async::Error>(UserData {
                states: selected_records,
            })
        };

        match result.await {
            Ok(output) => Ok(output),
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }
    async fn get_user_state(
        &self,
        username: &Username,
        flag: UserStateRetrievalFlag,
    ) -> core::result::Result<UserState, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let mut statement_text =
                "SELECT `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                    .to_owned()
                    + USER_TABLE
                    + "` WHERE `username` = :the_user";
            let mut params_map = vec![("the_user", Value::from(&username.0))];
            // apply the specific filter
            match flag {
                UserStateRetrievalFlag::SpecificVersion(version) => {
                    params_map.push(("the_version", Value::from(version)));
                    statement_text += " AND `version` = :the_version";
                }
                UserStateRetrievalFlag::SpecificEpoch(epoch) => {
                    params_map.push(("the_epoch", Value::from(epoch)));
                    statement_text += " AND `epoch` = :the_epoch";
                }
                UserStateRetrievalFlag::MaxEpoch => statement_text += " ORDER BY `epoch` DESC",
                UserStateRetrievalFlag::MaxVersion => statement_text += " ORDER BY `version` DESC",
                UserStateRetrievalFlag::MinEpoch => statement_text += " ORDER BY `epoch` ASC",
                UserStateRetrievalFlag::MinVersion => statement_text += " ORDER BY `version` ASC",
                UserStateRetrievalFlag::LeqEpoch(epoch) => {
                    params_map.push(("the_epoch", Value::from(epoch)));
                    statement_text += " AND `epoch` <= :the_epoch";
                },
            }

            // add limit to retrieve only 1 record
            statement_text += " LIMIT 1";
            let prepped = conn.prep(statement_text).await?;
            let out = conn
                .exec_map(
                    prepped,
                    mysql_async::Params::from(params_map),
                    |(epoch, version, node_label_val, node_label_len, data)| UserState {
                        epoch,
                        version,
                        label: NodeLabel {
                            val: node_label_val,
                            len: node_label_len,
                        },
                        plaintext_val: crate::storage::types::Values(data),
                    },
                )
                .await;
            let selected_record = self.check_for_infra_error(out)?;

            Ok::<Option<UserState>, mysql_async::Error>(selected_record.into_iter().next())
        };

        match result.await {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(StorageError::GetError(String::from("Not found"))),
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }
}

impl Clone for AsyncMySqlDatabase {
    fn clone(&self) -> Self {
        Self {
            opts: self.opts.clone(),
            pool: self.pool.clone(),
            is_healthy: self.is_healthy.clone(),
        }
    }
}
