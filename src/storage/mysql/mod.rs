// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements operations for a simple asynchronized mysql database

use crate::errors::StorageError;
use crate::node_state::NodeLabel;
use crate::storage::types::{
    DbRecord, StorageType, UserData, UserState, UserStateRetrievalFlag, Username,
};
use crate::storage::{Storable, V2Storage};
use async_trait::async_trait;
use mysql_async::prelude::*;
use mysql_async::*;
use std::marker::Send;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;
use winter_crypto::Hasher;

const TABLE_AZKS: &str = "azks";
const TABLE_HISTORY_TREE_NODES: &str = "history";
const TABLE_HISTORY_NODE_STATES: &str = "states";
const TABLE_USER: &str = "users";

const MAXIMUM_SQL_TIER_CONNECTION_TIMEOUT_SECS: u64 = 300;
const SQL_RECONNECTION_DELAY_SECS: u64 = 5;

const SELECT_AZKS_DATA: &str = "`root`, `epoch`, `num_nodes`";
const SELECT_HISTORY_TREE_NODE_DATA: &str =
    "`location`, `label_len`, `label_val`, `epochs`, `parent`, `node_type`";
const SELECT_HISTORY_NODE_STATE_DATA: &str =
    "`label_len`, `label_val`, `epoch`, `value`, `child_states`";
const SELECT_USER_DATA: &str =
    "`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`";

/*
    MySql documentation: https://docs.rs/mysql_async/0.28.1/mysql_async/
*/

/// Represents an _asynchronous_ connection to a MySQL database
pub struct AsyncMySqlDatabase {
    opts: Opts,
    pool: Arc<tokio::sync::RwLock<Pool>>,
    is_healthy: Arc<Mutex<bool>>,
}

impl std::fmt::Display for AsyncMySqlDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let db_str = match self.opts.db_name() {
            Some(db) => format!("Database {}", db),
            None => String::from(""),
        };
        let user_str = match self.opts.user() {
            Some(user) => format!(", User {}", user),
            None => String::from(""),
        };

        write!(
            f,
            "Connected to {}:{} ({}{})",
            self.opts.ip_or_hostname(),
            self.opts.tcp_port(),
            db_str,
            user_str
        )
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

impl AsyncMySqlDatabase {
    /// Creates a new mysql database
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

    async fn setup_database(
        conn: &mut mysql_async::Conn,
    ) -> core::result::Result<(), mysql_async::Error> {
        let mut tx = conn.start_transaction(TxOpts::default()).await?;
        let result = async {
            // AZKS table
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + TABLE_AZKS
                + "` (`key` SMALLINT UNSIGNED NOT NULL, `root` BIGINT UNSIGNED NOT NULL,"
                + " `epoch` BIGINT UNSIGNED NOT NULL, `num_nodes` BIGINT UNSIGNED NOT NULL,"
                + " PRIMARY KEY (`key`))";
            tx.query_drop(command).await?;

            // History tree nodes table
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + TABLE_HISTORY_TREE_NODES
                + "` (`location` BIGINT UNSIGNED NOT NULL, `label_len` INT UNSIGNED NOT NULL,"
                + " `label_val` BIGINT UNSIGNED NOT NULL, `epochs` VARBINARY(2000),"
                + " `parent` BIGINT UNSIGNED NOT NULL, `node_type` SMALLINT UNSIGNED NOT NULL,"
                + " PRIMARY KEY (`location`))";
            tx.query_drop(command).await?;

            // History node states table
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + TABLE_HISTORY_NODE_STATES
                + "` (`label_len` INT UNSIGNED NOT NULL, `label_val` BIGINT UNSIGNED NOT NULL, "
                + " `epoch` BIGINT UNSIGNED NOT NULL, `value` VARBINARY(2000), `child_states` VARBINARY(2000),"
                + " PRIMARY KEY (`label_len`, `label_val`, `epoch`))";
            tx.query_drop(command).await?;

            // User data table
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + TABLE_USER
                + "` (`username` VARCHAR(256) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, `version` BIGINT UNSIGNED NOT NULL,"
                + " `node_label_val` BIGINT UNSIGNED NOT NULL, `node_label_len` INT UNSIGNED NOT NULL, `data` VARCHAR(2000),"
                + " PRIMARY KEY(`username`, `epoch`))";
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

    /// Delete all the data in the tables
    #[allow(dead_code)]
    pub async fn delete_data(&self) -> core::result::Result<(), mysql_async::Error> {
        let mut conn = self.get_connection().await?;

        let command = "DELETE FROM `".to_owned() + TABLE_AZKS + "`";
        conn.query_drop(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_USER + "`";
        conn.query_drop(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_HISTORY_NODE_STATES + "`";
        conn.query_drop(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_HISTORY_TREE_NODES + "`";
        conn.query_drop(command).await?;

        Ok(())
    }

    /// Cleanup the test data table
    #[allow(dead_code)]
    pub(crate) async fn test_cleanup(&self) -> core::result::Result<(), mysql_async::Error> {
        let mut conn = self.get_connection().await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_AZKS + "`";
        conn.query_drop(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_USER + "`";
        conn.query_drop(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_HISTORY_NODE_STATES + "`";
        conn.query_drop(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_HISTORY_TREE_NODES + "`";
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

    /// Storage a record in the data layer
    async fn internal_set<H: Hasher + Sync + Send>(
        &self,
        record: DbRecord<H>,
        trans: Option<&mut mysql_async::Transaction<'_>>,
    ) -> core::result::Result<(), mysql_async::Error> {
        let statement_text = record.set_statement();
        let out = match trans {
            Some(tx) => tx.exec_drop(statement_text, record.set_params()).await,
            None => {
                let mut conn = self.get_connection().await?;
                conn.exec_drop(statement_text, record.set_params()).await
            }
        };
        self.check_for_infra_error(out)?;
        Ok::<(), mysql_async::Error>(())
    }

    /// NOTE: This is assuming all of the DB records have been narrowed down to a single record type!
    async fn internal_batch_set<H: Hasher + Sync + Send>(
        &self,
        records: Vec<DbRecord<H>>,
        trans: Option<&mut mysql_async::Transaction<'_>>,
    ) -> core::result::Result<(), mysql_async::Error> {
        match trans {
            Some(tx) => {
                for batch in records.chunks(100) {
                    let head = &batch[0];
                    let statement = head.set_statement();
                    let prepped = tx.prep(statement).await?;
                    let out = tx
                        .exec_batch(prepped, batch.iter().map(|value| value.set_params()))
                        .await;
                    self.check_for_infra_error(out)?;
                }
            }
            None => {
                for batch in records.chunks(100) {
                    let head = &batch[0];
                    let statement = head.set_statement();
                    let mut conn = self.get_connection().await?;
                    let prepped = conn.prep(statement).await?;
                    let out = conn
                        .exec_batch(prepped, batch.iter().map(|value| value.set_params()))
                        .await;
                    self.check_for_infra_error(out)?;
                }
            }
        }
        Ok::<(), mysql_async::Error>(())
    }
}

#[async_trait]
impl V2Storage for AsyncMySqlDatabase {
    /// Storage a record in the data layer
    async fn set<H: Hasher + Sync + Send>(
        &self,
        record: DbRecord<H>,
    ) -> core::result::Result<(), StorageError> {
        match self.internal_set::<H>(record, None).await {
            Ok(_) => Ok(()),
            Err(error) => Err(StorageError::SetError(error.to_string())),
        }
    }

    async fn batch_set<H: Hasher + Sync + Send>(
        &self,
        records: Vec<DbRecord<H>>,
    ) -> core::result::Result<(), StorageError> {
        // generate batches by type
        let mut groups = std::collections::HashMap::new();
        for record in records {
            match &record {
                DbRecord::Azks(_) => groups
                    .entry(StorageType::Azks)
                    .or_insert_with(Vec::new)
                    .push(record),
                DbRecord::HistoryNodeState(_) => groups
                    .entry(StorageType::HistoryNodeState)
                    .or_insert_with(Vec::new)
                    .push(record),
                DbRecord::HistoryTreeNode(_) => groups
                    .entry(StorageType::HistoryTreeNode)
                    .or_insert_with(Vec::new)
                    .push(record),
                DbRecord::UserState(_) => groups
                    .entry(StorageType::UserState)
                    .or_insert_with(Vec::new)
                    .push(record),
            }
        }
        // now execute each type'd batch in batch operations
        let result = async {
            let mut conn = self.get_connection().await?;
            let mut tx = conn.start_transaction(TxOpts::default()).await?;

            let mut running_error = Ok::<(), mysql_async::Error>(());
            for (_key, value) in groups.into_iter() {
                if !value.is_empty() {
                    running_error = self.internal_batch_set(value, Some(&mut tx)).await;
                }
                //early exit
                if running_error.is_err() {
                    break;
                }
            }

            if let Err(error) = running_error {
                tx.rollback().await?;
                Err(error)
            } else {
                tx.commit().await?;
                Ok(())
            }
        };
        match result.await {
            Ok(_) => Ok(()),
            Err(error) => Err(StorageError::SetError(error.to_string())),
        }
    }

    /// Retrieve a stored record from the data layer
    async fn get<H: Hasher + Sync + Send, St: Storable>(
        &self,
        id: St::Key,
    ) -> core::result::Result<DbRecord<H>, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let statement = DbRecord::<H>::get_specific_statement::<St>();
            let params = DbRecord::<H>::get_specific_params::<St>(id);
            let out = match params {
                Some(p) => conn.exec_first(statement, p).await,
                None => conn.query_first(statement).await,
            };
            let result = self.check_for_infra_error(out)?;
            if let Some(mut row) = result {
                let record = DbRecord::<H>::from_row::<St>(&mut row)?;
                return Ok::<Option<DbRecord<H>>, mysql_async::Error>(Some(record));
            }
            Ok::<Option<DbRecord<H>>, mysql_async::Error>(None)
        };

        match result.await {
            Ok(Some(r)) => Ok(r),
            Ok(None) => Err(StorageError::GetError("Not found".to_string())),
            Err(error) => Err(StorageError::GetError(error.to_string())),
        }
    }

    /// Retrieve all of the objects of a given type from the storage layer, optionally limiting on "num" results
    async fn get_all<H: Hasher + Sync + Send, St: Storable>(
        &self,
        num: Option<usize>,
    ) -> core::result::Result<Vec<DbRecord<H>>, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let mut statement = DbRecord::<H>::get_statement::<St>();
            if let Some(limit) = num {
                statement += format!(" LIMIT {}", limit).as_ref();
            }
            let out = conn
                .query_fold(statement, vec![], |mut acc, mut row| {
                    if let Ok(result) = DbRecord::<H>::from_row::<St>(&mut row) {
                        acc.push(result);
                    }
                    acc
                })
                .await?;
            Ok::<Vec<DbRecord<H>>, mysql_async::Error>(out)
        };

        match result.await {
            Ok(map) => Ok(map),
            Err(error) => Err(StorageError::GetError(error.to_string())),
        }
    }

    async fn append_user_state<H: Hasher + Sync + Send>(
        &self,
        value: &UserState,
    ) -> core::result::Result<(), StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let statement_text = "INSERT INTO `".to_owned()
                + TABLE_USER
                + "` (`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`)"
                + " VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)";
            let prepped = conn.prep(statement_text).await?;
            let out = conn
                .exec_drop(
                    prepped,
                    params! {
                        "username" => value.username.0.clone(),
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

    async fn append_user_states<H: Hasher + Sync + Send>(
        &self,
        values: Vec<UserState>,
    ) -> core::result::Result<(), StorageError> {
        let records = values.into_iter().map(DbRecord::<H>::UserState).collect();
        self.batch_set(records).await
    }

    async fn get_user_data<H: Hasher + Sync + Send>(
        &self,
        username: &AkdKey,
    ) -> core::result::Result<KeyData, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let statement_text =
                "SELECT `username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                    .to_owned()
                    + TABLE_USER
                    + "` WHERE `username` = :the_user";
            let prepped = conn.prep(statement_text).await?;
            let out = conn
                .exec_map(
                    prepped,
                    params! { "the_user" => username.0.clone() },
                    |(username, epoch, version, node_label_val, node_label_len, data)| UserState {
                        epoch,
                        version,
                        label: NodeLabel {
                            val: node_label_val,
                            len: node_label_len,
                        },
                        plaintext_val: crate::storage::types::Values(data),
                        username: crate::storage::types::Username(username),
                    },
                )
                .await;
            let selected_records = self.check_for_infra_error(out)?;
            Ok::<KeyData, mysql_async::Error>(KeyData {
                states: selected_records,
            })
        };

        match result.await {
            Ok(output) => Ok(output),
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }

    async fn get_user_state<H: Hasher + Sync + Send>(
        &self,
        username: &AkdKey,
        flag: ValueStateRetrievalFlag,
    ) -> core::result::Result<ValueState, StorageError> {
        let result = async {
            let mut conn = self.get_connection().await?;
            let mut statement_text =
                "SELECT `username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                    .to_owned()
                    + TABLE_USER
                    + "` WHERE `username` = :the_user";
            let mut params_map = vec![("the_user", Value::from(&username.0))];
            // apply the specific filter
            match flag {
                ValueStateRetrievalFlag::SpecificVersion(version) => {
                    params_map.push(("the_version", Value::from(version)));
                    statement_text += " AND `version` = :the_version";
                }
                ValueStateRetrievalFlag::SpecificEpoch(epoch) => {
                    params_map.push(("the_epoch", Value::from(epoch)));
                    statement_text += " AND `epoch` = :the_epoch";
                }
                ValueStateRetrievalFlag::MaxEpoch => statement_text += " ORDER BY `epoch` DESC",
                ValueStateRetrievalFlag::MaxVersion => statement_text += " ORDER BY `version` DESC",
                ValueStateRetrievalFlag::MinEpoch => statement_text += " ORDER BY `epoch` ASC",
                ValueStateRetrievalFlag::MinVersion => statement_text += " ORDER BY `version` ASC",
                ValueStateRetrievalFlag::LeqEpoch(epoch) => {
                    params_map.push(("the_epoch", Value::from(epoch)));
                    statement_text += " AND `epoch` <= :the_epoch";
                }
            }

            // add limit to retrieve only 1 record
            statement_text += " LIMIT 1";
            let prepped = conn.prep(statement_text).await?;
            let out = conn
                .exec_map(
                    prepped,
                    mysql_async::Params::from(params_map),
                    |(username, epoch, version, node_label_val, node_label_len, data)| UserState {
                        epoch,
                        version,
                        label: NodeLabel {
                            val: node_label_val,
                            len: node_label_len,
                        },
                        plaintext_val: crate::storage::types::Values(data),
                        username: crate::storage::types::Username(username),
                    },
                )
                .await;
            let selected_record = self.check_for_infra_error(out)?;

            Ok::<Option<ValueState>, mysql_async::Error>(selected_record.into_iter().next())
        };

        match result.await {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(StorageError::GetError(String::from("Not found"))),
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }
}

/* Generic data structure handling for MySQL */

trait MySqlStorable {
    fn set_statement(&self) -> String;

    fn set_params(&self) -> mysql_async::Params;

    fn get_statement<St: Storable>() -> String;

    fn get_specific_statement<St: Storable>() -> String;

    fn get_specific_params<St: Storable>(key: St::Key) -> Option<mysql_async::Params>;

    fn from_row<St: Storable>(
        row: &mut mysql_async::Row,
    ) -> core::result::Result<Self, mysql_async::Error>
    where
        Self: std::marker::Sized;
}

impl<H: Hasher + Send + Sync> MySqlStorable for DbRecord<H> {
    fn set_statement(&self) -> String {
        match &self {
            DbRecord::Azks(_) => format!("INSERT INTO `{}` (`key`, {}) VALUES (:key, :root, :epoch, :num_nodes) ON DUPLICATE KEY UPDATE `root` = :root, `epoch` = :epoch, `num_nodes` = :num_nodes", TABLE_AZKS, SELECT_AZKS_DATA),
            DbRecord::HistoryNodeState(_) => format!("INSERT INTO `{}` ({}) VALUES (:label_len, :label_val, :epoch, :value, :child_states) ON DUPLICATE KEY UPDATE `value` = :value, `child_states` = :child_states", TABLE_HISTORY_NODE_STATES, SELECT_HISTORY_NODE_STATE_DATA),
            DbRecord::HistoryTreeNode(_) => format!("INSERT INTO `{}` ({}) VALUES (:location, :label_len, :label_val, :epochs, :parent, :node_type) ON DUPLICATE KEY UPDATE `label_len` = :label_len, `label_val` = :label_val, `epochs` = :epochs, `parent` = :parent, `node_type` = :node_type", TABLE_HISTORY_TREE_NODES, SELECT_HISTORY_TREE_NODE_DATA),
            DbRecord::UserState(_) => format!("INSERT INTO `{}` ({}) VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)", TABLE_USER, SELECT_USER_DATA),
        }
    }

    fn set_params(&self) -> mysql_async::Params {
        match &self {
            DbRecord::Azks(azks) => {
                params! { "key" => 1u8, "root" => azks.root, "epoch" => azks.latest_epoch, "num_nodes" => azks.num_nodes }
            }
            DbRecord::HistoryNodeState(state) => {
                let bin_data = bincode::serialize(&state.child_states).unwrap();
                let id = state.get_id();
                params! { "label_len" => id.0.len, "label_val" => id.0.val, "epoch" => id.1, "value" => state.value.clone(), "child_states" => bin_data }
            }
            DbRecord::HistoryTreeNode(node) => {
                let bin_data = bincode::serialize(&node.epochs).unwrap();
                params! { "location" => node.location, "label_len" => node.label.len, "label_val" => node.label.val, "epochs" => bin_data, "parent" => node.parent, "node_type" => node.node_type as u8 }
            }
            DbRecord::UserState(state) => {
                params! { "username" => state.get_id().0, "epoch" => state.epoch, "version" => state.version, "node_label_len" => state.label.len, "node_label_val" => state.label.val, "data" => state.plaintext_val.0.clone()}
            }
        }
    }

    fn get_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => format!("SELECT {} FROM `{}`", SELECT_AZKS_DATA, TABLE_AZKS),
            StorageType::HistoryNodeState => format!(
                "SELECT {} FROM `{}`",
                SELECT_HISTORY_NODE_STATE_DATA, TABLE_HISTORY_NODE_STATES
            ),
            StorageType::HistoryTreeNode => format!(
                "SELECT {} FROM `{}`",
                SELECT_HISTORY_TREE_NODE_DATA, TABLE_HISTORY_TREE_NODES
            ),
            StorageType::UserState => format!("SELECT {} FROM `{}`", SELECT_USER_DATA, TABLE_USER),
        }
    }

    fn get_specific_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => format!("SELECT {} FROM `{}` LIMIT 1", SELECT_AZKS_DATA, TABLE_AZKS),
            StorageType::HistoryNodeState => format!("SELECT {} FROM `{}` WHERE `label_len` = :label_len AND `label_val` = :label_val AND `epoch` = :epoch", SELECT_HISTORY_NODE_STATE_DATA, TABLE_HISTORY_NODE_STATES),
            StorageType::HistoryTreeNode => format!("SELECT {} FROM `{}` WHERE `location` = :location", SELECT_HISTORY_TREE_NODE_DATA, TABLE_HISTORY_TREE_NODES),
            StorageType::UserState => format!("SELECT {} FROM `{}` WHERE `username` = :username AND `epoch` = :epoch", SELECT_USER_DATA, TABLE_USER),
        }
    }

    fn get_specific_params<St: Storable>(key: St::Key) -> Option<mysql_async::Params> {
        // TODO: serializing & deserializing just to get type proper type. There MUST be a better way...
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::HistoryNodeState => {
                let bin = bincode::serialize(&key).unwrap();
                let back: crate::node_state::NodeStateKey = bincode::deserialize(&bin).unwrap();
                Some(params! {
                    "label_len" => back.0.len,
                    "label_val" => back.0.val,
                    "epoch" => back.1
                })
            }
            StorageType::HistoryTreeNode => {
                let bin = bincode::serialize(&key).unwrap();
                let back: crate::history_tree_node::NodeKey = bincode::deserialize(&bin).unwrap();
                Some(params! {
                    "location" => back.0
                })
            }
            StorageType::UserState => {
                let bin = bincode::serialize(&key).unwrap();
                let back: crate::storage::types::UserStateKey = bincode::deserialize(&bin).unwrap();
                Some(params! {
                    "username" => back.0,
                    "epoch" => back.1
                })
            }
        }
    }

    fn from_row<St: Storable>(
        row: &mut mysql_async::Row,
    ) -> core::result::Result<Self, mysql_async::Error>
    where
        Self: std::marker::Sized,
    {
        match St::data_type() {
            StorageType::Azks => {
                // root, epoch, num_nodes
                if let (Some(Ok(root)), Some(Ok(epoch)), Some(Ok(num_nodes))) =
                    (row.take_opt(0), row.take_opt(1), row.take_opt(2))
                {
                    let azks = AsyncMySqlDatabase::build_azks(root, epoch, num_nodes);
                    return Ok(DbRecord::Azks(azks));
                }
            }
            StorageType::HistoryNodeState => {
                // label_len, label_val, epoch, value, child_states
                if let (
                    Some(Ok(label_len)),
                    Some(Ok(label_val)),
                    Some(Ok(epoch)),
                    Some(Ok(value)),
                    Some(Ok(child_states)),
                ) = (
                    row.take_opt(0),
                    row.take_opt(1),
                    row.take_opt(2),
                    row.take_opt(3),
                    row.take_opt(4),
                ) {
                    let child_states_bin_vec: Vec<u8> = child_states;
                    let child_states_decoded: Vec<crate::node_state::HistoryChildState<H>> =
                        bincode::deserialize(&child_states_bin_vec).unwrap();
                    let node_state = AsyncMySqlDatabase::build_history_node_state(
                        value,
                        child_states_decoded,
                        label_len,
                        label_val,
                        epoch,
                    );
                    return Ok(DbRecord::HistoryNodeState(node_state));
                }
            }
            StorageType::HistoryTreeNode => {
                // `location`, `label_len`, `label_val`, `epochs`, `parent`, `node_type`
                if let (
                    Some(Ok(location)),
                    Some(Ok(label_len)),
                    Some(Ok(label_val)),
                    Some(Ok(epochs)),
                    Some(Ok(parent)),
                    Some(Ok(node_type)),
                ) = (
                    row.take_opt(0),
                    row.take_opt(1),
                    row.take_opt(2),
                    row.take_opt(3),
                    row.take_opt(4),
                    row.take_opt(5),
                ) {
                    let bin_epochs: Vec<u8> = epochs;
                    let decoded_epochs: Vec<u64> = bincode::deserialize(&bin_epochs).unwrap();
                    let node = AsyncMySqlDatabase::build_history_tree_node(
                        label_val,
                        label_len,
                        location,
                        decoded_epochs,
                        parent,
                        node_type,
                    );
                    return Ok(DbRecord::HistoryTreeNode(node));
                }
            }
            StorageType::UserState => {
                // `username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`
                if let (
                    Some(Ok(username)),
                    Some(Ok(epoch)),
                    Some(Ok(version)),
                    Some(Ok(node_label_val)),
                    Some(Ok(node_label_len)),
                    Some(Ok(data)),
                ) = (
                    row.take_opt(0),
                    row.take_opt(1),
                    row.take_opt(2),
                    row.take_opt(3),
                    row.take_opt(4),
                    row.take_opt(5),
                ) {
                    let state = AsyncMySqlDatabase::build_user_state(
                        username,
                        data,
                        version,
                        node_label_len,
                        node_label_val,
                        epoch,
                    );
                    return Ok(DbRecord::UserState(state));
                }
            }
        }
        // fallback
        let err =
            mysql_async::Error::Driver(mysql_async::DriverError::FromRow { row: row.clone() });
        Err(err)
    }
}
