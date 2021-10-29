// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use crate::node_state::NodeLabel;
use crate::storage::types::{UserData, UserState, UserStateRetrievalFlag, Username};
use crate::storage::SyncStorage;
use mysql::prelude::*;
use mysql::*;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

const TABLE: &str = "data";
const USER_TABLE: &str = "user_data";
const MAXIMUM_SQL_TIER_CONNECTION_TIMEOUT_SECS: u64 = 300;
const SQL_RECONNECTION_DELAY_SECS: u64 = 5;

pub mod r#async;

/*
    MySql documentation: https://docs.rs/mysql/21.0.2/mysql/
*/

pub(crate) struct MySqlDatabase {
    opts: Opts,
    pool: Arc<Mutex<Pool>>,
    is_healthy: Arc<Mutex<bool>>,
}

impl MySqlDatabase {
    #[allow(unused)]
    pub fn new<T: Into<String>>(
        endpoint: T,
        database: T,
        user: Option<T>,
        password: Option<T>,
        port: Option<u16>,
    ) -> Self {
        let dport = port.unwrap_or(1u16);
        let opts: Opts = OptsBuilder::new()
            .ip_or_hostname(Option::from(endpoint))
            .db_name(Option::from(database))
            .user(user)
            .pass(password)
            .tcp_port(dport)
            .into();
        #[allow(clippy::mutex_atomic)]
        let healthy = Arc::new(Mutex::new(false));
        let pool = Self::new_connection_pool(&opts, &healthy).unwrap();

        Self {
            opts,
            pool: Arc::new(Mutex::new(pool)),
            is_healthy: healthy,
        }
    }

    /// Get a connection to the database
    fn get_connection(&self) -> core::result::Result<mysql::PooledConn, mysql::Error> {
        let /*mut*/ connection = {
            if self.is_healthy() {
                let connection_pool_guard = self.pool.lock().unwrap();
                let connection_pool: &Pool = &*connection_pool_guard;
                connection_pool.get_conn()?
            } else {
                // Connection pool is currently unhealthy and queries are
                // disallowed. Connection pool is being async refreshed in
                // background and will soon become healthy, so no action required

                // fail the connection
                return Err(mysql::Error::DriverError(mysql::DriverError::SetupError));
            }
        };

        // // Ensure we are running in TRADITIONAL mysql mode. TRADITIONAL mysql
        // // converts many warnings to errors, for example it will reject too
        // // large blob entries instead of truncating them with a warning.
        // // This is essential for our system, since SEE relies on all data in our
        // // XDB being exactly what it wrote.
        // connection.query("SET SESSION sql_mode = 'TRADITIONAL'")?;

        Ok(connection)
    }

    // Occasionally our connection pool will become stale. This happens
    // e.g on DB master promotions during mysql upgrades. In these scenarios our
    // queries will begin to fail, and we will need to call this method to
    // "refresh" the pool.
    fn refresh_connection_pool(&self) -> core::result::Result<(), StorageError> {
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
        let mut connection_pool_guard = self.pool.lock().unwrap();
        let connection_pool: &mut Pool = &mut *connection_pool_guard;
        *connection_pool = Self::new_connection_pool(&self.opts, &self.is_healthy)?;

        Ok(())
    }

    fn setup_database(conn: &mut mysql::PooledConn) -> core::result::Result<(), mysql::Error> {
        // main data table (for all tree nodes, etc)
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE
            + "` (`key` VARCHAR(64) NOT NULL, `value` VARBINARY(2000), PRIMARY KEY (`key`)"
            + ")";

        conn.query_drop(command)?;

        // user data table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned() + USER_TABLE + "`"
            + " (`username` VARCHAR(64) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, `version` BIGINT UNSIGNED NOT NULL,"
            + " `node_label_val` BIGINT UNSIGNED NOT NULL, `node_label_len` INT UNSIGNED NOT NULL, `data` VARCHAR(2000),"
            + " PRIMARY KEY(`username`, `epoch`)"
            + " )";
        conn.query_drop(command)?;

        Ok(())
    }

    fn new_connection_pool(
        opts: &mysql::Opts,
        is_healthy: &Arc<Mutex<bool>>,
    ) -> core::result::Result<mysql::Pool, StorageError> {
        let start = Instant::now();
        let mut attempts = 1;

        loop {
            let ip = opts.get_ip_or_hostname();
            let pool_options = opts.clone();
            if let Ok(pool) = Pool::new(pool_options) {
                if let Ok(mut _conn) = pool.get_conn() {
                    if let Ok(()) = Self::setup_database(&mut _conn) {
                        // set the healthy flag to true
                        let mut is_healthy_guard = is_healthy.lock().unwrap();
                        *is_healthy_guard = true;

                        return Ok(pool);
                    }
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

            std::thread::sleep(std::time::Duration::from_millis(
                SQL_RECONNECTION_DELAY_SECS * 1000u64,
            ));

            attempts += 1
        }
    }

    /// Determine if the db connection is healthy at present
    pub fn is_healthy(&self) -> bool {
        let is_healthy_guard = self.is_healthy.lock().unwrap();
        *is_healthy_guard
    }

    fn query_with_guard<T, F>(
        &self,
        operator: F,
        conn: &mut PooledConn,
    ) -> core::result::Result<T, mysql::Error>
    where
        F: Fn(&mut PooledConn) -> core::result::Result<T, mysql::Error>,
    {
        match operator(conn) {
            Err(err) => {
                let is_connection_infra_error: bool = match &err {
                    mysql::Error::MySqlError(_)
                    | mysql::Error::UrlError(_)
                    | mysql::Error::FromValueError(_)
                    | mysql::Error::FromRowError(_) => false,

                    mysql::Error::DriverError(_)
                    | mysql::Error::IoError(_)
                    | mysql::Error::CodecError(_)
                    | mysql::Error::TlsError(_)
                    | mysql::Error::TlsHandshakeError(_) => true,
                };

                // If error is due to infra error (e.g bad connection) refresh
                // connection pool in background. This allows current request to
                // finish (with err) while blocking subsequent requests until a
                // healthy connection is restored.
                if is_connection_infra_error {
                    let db = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(err) = db.refresh_connection_pool() {
                            println!("Error: Error refreshing MySql connection pool: {:?}", err);
                        }
                    });
                }
                Err(err)
            }
            other => other,
        }
    }

    /// Cleanup the test data table
    #[allow(dead_code)]
    pub(crate) fn test_cleanup(&self) -> core::result::Result<(), mysql::Error> {
        let mut conn = self.get_connection()?;

        self.query_with_guard(
            |conn| {
                let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE + "`";
                conn.query_drop(command)
            },
            &mut conn,
        )?;

        self.query_with_guard(
            |conn| {
                let command = "DROP TABLE IF EXISTS `".to_owned() + USER_TABLE + "`";
                conn.query_drop(command)
            },
            &mut conn,
        )?;

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

impl SyncStorage for MySqlDatabase {
    fn set(&self, pos: String, val: &[u8]) -> core::result::Result<(), StorageError> {
        let result = || -> core::result::Result<(), mysql::Error> {
            let mut conn = self.get_connection()?;
            self.query_with_guard(
                |conn| {
                    let statement_text = "INSERT INTO `".to_owned()
                        + TABLE
                        + "` (`key`, `value`) VALUES (:the_key, :the_value) ON DUPLICATE KEY UPDATE `value` = :the_value";
                    let prepared = conn.prep(statement_text)?;
                    conn.exec_drop(
                        prepared,
                        params! { "the_key" => pos.clone(), "the_value" => &(*val) },
                    )
                },
                &mut conn,
            )?;
            Ok(())
        };

        match result() {
            Ok(()) => Ok(()),
            Err(code) => Err(StorageError::SetError(code.to_string())),
        }
    }
    fn get(&self, pos: String) -> core::result::Result<Vec<u8>, StorageError> {
        let result = || -> core::result::Result<Option<Vec<u8>>, mysql::Error> {
            let mut conn = self.get_connection()?;

            let result: Option<(String, Vec<u8>)> = self.query_with_guard(
                |conn| {
                    let statement_text = "SELECT `key`, `value` FROM `".to_owned()
                        + TABLE
                        + "` WHERE `key` = :the_key LIMIT 1";
                    let statement = conn.prep(statement_text)?;
                    conn.exec_first(statement, params! { "the_key" => pos.clone() })
                },
                &mut conn,
            )?;
            if let Some((_key, value)) = result {
                return Ok(Some(value));
            }
            Ok(None)
        };

        match result() {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(StorageError::GetError(String::from("Not found"))),
            Err(other) => Err(StorageError::GetError(other.to_string())),
        }
    }

    fn append_user_state(
        &self,
        username: &Username,
        value: &UserState,
    ) -> core::result::Result<(), StorageError> {
        let result = || -> core::result::Result<(), mysql::Error> {
            let mut conn = self.get_connection()?;
            self.query_with_guard(|conn| {
                let statement_text = "INSERT INTO `".to_owned()
                    + USER_TABLE
                    + "` (`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`)"
                    + " VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)";
                let prepared = conn.prep(statement_text)?;
                conn.exec_drop(
                    prepared,
                    params! {
                        "username" => username.0.clone(),
                        "epoch" => value.epoch,
                        "version" => value.version,
                        "node_label_val" => value.label.val,
                        "node_label_len" => value.label.len,
                        "data" => value.plaintext_val.0.clone()
                    },
                )
            }, &mut conn)?;
            Ok(())
        };

        match result() {
            Ok(()) => Ok(()),
            Err(code) => Err(StorageError::SetError(code.to_string())),
        }
    }

    fn append_user_states(
        &self,
        values: Vec<(Username, UserState)>,
    ) -> core::result::Result<(), StorageError> {
        let result = || -> core::result::Result<(), mysql::Error> {
            let mut conn = self.get_connection()?;

            self.query_with_guard(|conn| {
                let statement_text = "INSERT INTO `".to_owned()
                    + USER_TABLE
                    + "` (`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`)"
                    + " VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)";
                // create a transaction to perform the operations on
                let mut tx = conn.start_transaction(TxOpts::default())?;
                let mut steps = || -> core::result::Result<(), mysql::Error> {
                    for chunk in values.chunks(100) {
                        let prepared = tx.prep(statement_text.clone())?;
                        tx.exec_batch(
                            prepared,
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
                        )?;
                    }
                    Ok(())
                };

                // if any of the steps returns an error, fail the entire transaction to in an atomic state
                if steps().is_err() {
                    tx.rollback()?;
                } else {
                    tx.commit()?;
                }
                Ok(())
            }, &mut conn)
        };

        match result() {
            Ok(()) => Ok(()),
            Err(code) => Err(StorageError::SetError(code.to_string())),
        }
    }

    fn get_user_data(&self, username: &Username) -> core::result::Result<UserData, StorageError> {
        let result = || -> core::result::Result<UserData, mysql::Error> {
            let mut conn = self.get_connection()?;
            self.query_with_guard(
                |conn| {
                    let statement_text =
                    "SELECT `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                        .to_owned()
                        + USER_TABLE
                        + "` WHERE `username` = :the_user";
                    let prepared = conn.prep(statement_text)?;
                    let selected_records = conn.exec_map(
                        prepared,
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
                    )?;
                    Ok(UserData {
                        states: selected_records,
                    })
                },
                &mut conn,
            )
        };

        match result() {
            Ok(output) => Ok(output),
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }
    fn get_user_state(
        &self,
        username: &Username,
        flag: UserStateRetrievalFlag,
    ) -> core::result::Result<UserState, StorageError> {
        let result = || -> core::result::Result<Option<UserState>, mysql::Error> {
            let mut conn = self.get_connection()?;

            self.query_with_guard(
                |conn| {
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
                        UserStateRetrievalFlag::MaxEpoch => {
                            statement_text += " ORDER BY `epoch` DESC"
                        }
                        UserStateRetrievalFlag::MaxVersion => {
                            statement_text += " ORDER BY `version` DESC"
                        }
                        UserStateRetrievalFlag::MinEpoch => {
                            statement_text += " ORDER BY `epoch` ASC"
                        }
                        UserStateRetrievalFlag::MinVersion => {
                            statement_text += " ORDER BY `version` ASC"
                        }
                    }

                    // add limit to retrieve only 1 record
                    statement_text += " LIMIT 1";
                    let prepared = conn.prep(statement_text)?;
                    let selected_record = conn.exec_map(
                        prepared,
                        mysql::Params::from(params_map),
                        |(epoch, version, node_label_val, node_label_len, data)| UserState {
                            epoch,
                            version,
                            label: NodeLabel {
                                val: node_label_val,
                                len: node_label_len,
                            },
                            plaintext_val: crate::storage::types::Values(data),
                        },
                    )?;

                    Ok(selected_record.into_iter().next())
                },
                &mut conn,
            )
        };

        match result() {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(StorageError::GetError(String::from("Not found"))),
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }
}

impl Clone for MySqlDatabase {
    fn clone(&self) -> MySqlDatabase {
        MySqlDatabase {
            opts: self.opts.clone(),
            pool: self.pool.clone(),
            is_healthy: self.is_healthy.clone(),
        }
    }
}
