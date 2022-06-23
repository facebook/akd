// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements operations for a simple asynchronized mysql database

use crate::mysql_storables::MySqlStorable;
use akd::errors::StorageError;
use akd::storage::types::{
    AkdLabel, AkdValue, DbRecord, KeyData, StorageType, ValueState, ValueStateRetrievalFlag,
};
use akd::storage::{Storable, Storage};
use akd::tree_node::TreeNode;
use akd::NodeLabel;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use mysql_async::prelude::*;
use mysql_async::*;

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::process::Command;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

type MySqlError = mysql_async::Error;
type LocalTransaction = akd::storage::transaction::Transaction;

use akd::storage::timed_cache::*;

const TABLE_AZKS: &str = crate::mysql_storables::TABLE_AZKS;
const TABLE_HISTORY_TREE_NODES: &str = crate::mysql_storables::TABLE_HISTORY_TREE_NODES;
const TABLE_USER: &str = crate::mysql_storables::TABLE_USER;
const TEMP_IDS_TABLE: &str = crate::mysql_storables::TEMP_IDS_TABLE;

const MAXIMUM_SQL_TIER_CONNECTION_TIMEOUT_SECS: u64 = 300;
const SQL_RECONNECTION_DELAY_SECS: u64 = 5;

enum BatchMode {
    Full(mysql_async::Params),
    Partial(mysql_async::Params, usize),
    None,
}

// MySQL's max supported text size is 65535
// Of the prepared insert's below in this logic,
// we have a max-string size of 267 + N(190).
// Assuming 4b/char, we can work out an ABS
// max multi-row write for the prepared statement as
// (| 65535 | - | the constant parts |) / | the parts * depth | = ~ max depth of 343
// This is a conservative value of the estimate ^
// const MYSQL_EXTENDED_INSERT_DEPTH: usize = 1000; // note : migrated to Self::tunable_insert_depth

/*
    MySql documentation: https://docs.rs/mysql_async/0.23.1/mysql_async/
*/

/// Memory cache options for SQL query result caching
pub enum MySqlCacheOptions {
    /// Do not utilize any cache
    None,
    /// Utilize the default caching settings
    Default,
    /// Customize the caching options (cache item duration)
    Specific(std::time::Duration),
}

/// Represents an _asynchronous_ connection to a MySQL database
pub struct AsyncMySqlDatabase {
    opts: Opts,
    pool: Arc<tokio::sync::RwLock<Pool>>,
    is_healthy: Arc<tokio::sync::RwLock<bool>>,
    cache: Option<TimedCache>,
    trans: LocalTransaction,

    num_reads: Arc<tokio::sync::RwLock<u64>>,
    read_call_stats: Arc<tokio::sync::RwLock<HashMap<String, u64>>>,
    num_writes: Arc<tokio::sync::RwLock<u64>>,
    write_call_stats: Arc<tokio::sync::RwLock<HashMap<String, u64>>>,
    time_read: Arc<tokio::sync::RwLock<Duration>>,
    time_write: Arc<tokio::sync::RwLock<Duration>>,

    tunable_insert_depth: usize,
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
            cache: self.cache.clone(),
            trans: LocalTransaction::new(),

            num_reads: self.num_reads.clone(),
            read_call_stats: self.read_call_stats.clone(),
            num_writes: self.num_writes.clone(),
            write_call_stats: self.write_call_stats.clone(),
            time_read: self.time_read.clone(),
            time_write: self.time_write.clone(),

            tunable_insert_depth: self.tunable_insert_depth,
        }
    }
}

impl<'a> AsyncMySqlDatabase {
    /// Creates a new mysql database
    #[allow(unused)]
    pub async fn new<T: Into<String>>(
        endpoint: T,
        database: T,
        user: Option<T>,
        password: Option<T>,
        port: Option<u16>,
        cache_options: MySqlCacheOptions,
        depth: usize,
    ) -> Self {
        let dport = port.unwrap_or(3306u16);
        let mut builder = OptsBuilder::default()
            .ip_or_hostname(endpoint)
            .db_name(Option::from(database))
            .user(user)
            .pass(password)
            .tcp_port(dport);
        let opts: Opts = builder.into();

        #[allow(clippy::mutex_atomic)]
        let healthy = Arc::new(tokio::sync::RwLock::new(false));
        // Exception to issue 139. This call SHOULD panic if we cannot create a connection pool
        // object to fail the entire app. It'll fail very early as we need to create the db
        // prior to the directory
        let pool = Self::new_connection_pool(&opts, &healthy).await.unwrap();

        let cache = match cache_options {
            MySqlCacheOptions::None => None,
            MySqlCacheOptions::Default => Some(TimedCache::new(None)),
            MySqlCacheOptions::Specific(timing) => Some(TimedCache::new(Some(timing))),
        };

        Self {
            opts,
            pool: Arc::new(tokio::sync::RwLock::new(pool)),
            is_healthy: healthy,
            cache,
            trans: LocalTransaction::new(),

            num_reads: Arc::new(tokio::sync::RwLock::new(0)),
            read_call_stats: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            num_writes: Arc::new(tokio::sync::RwLock::new(0)),
            write_call_stats: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            time_read: Arc::new(tokio::sync::RwLock::new(Duration::from_millis(0))),
            time_write: Arc::new(tokio::sync::RwLock::new(Duration::from_millis(0))),

            tunable_insert_depth: depth,
        }
    }

    /// Determine if the db connection is healthy at present
    pub async fn is_healthy(&self) -> bool {
        let is_healthy_guard = self.is_healthy.read().await;
        *is_healthy_guard
    }

    fn check_for_infra_error<T>(
        &self,
        result: core::result::Result<T, MySqlError>,
    ) -> core::result::Result<T, MySqlError> {
        match result {
            Err(err) => {
                let is_connection_infra_error: bool = match &err {
                    // In mysql_async v0.28.1 TLS errors moved to IoError. Thus we cannot use them here.
                    // TODO(eoz): Update error handling to take TLS errors into account.
                    MySqlError::Other(_) | MySqlError::Url(_) /* | mysql_async::IoError::Tls(_) */ => false,

                    MySqlError::Driver(_) | MySqlError::Io(_) | MySqlError::Server(_) => true,
                };

                // If error is due to infra error (e.g bad connection) refresh
                // connection pool in background. This allows current request to
                // finish (with err) while blocking subsequent requests until a
                // healthy connection is restored.
                if is_connection_infra_error {
                    let db = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(err) = db.refresh_connection_pool().await {
                            error!("Error refreshing MySql connection pool: {:?}", err);
                        }
                    });
                }

                Err::<T, MySqlError>(err)
            }
            Ok(t) => Ok(t),
        }
    }

    async fn get_connection(&self) -> Result<mysql_async::Conn> {
        let mut connection = {
            if self.is_healthy().await {
                let connection_pool_guard = self.pool.read().await;
                connection_pool_guard.get_conn().await?
            } else {
                // Connection pool is currently unhealthy and queries are
                // disallowed. Connection pool is being async refreshed in
                // background and will soon become healthy, so no action required

                // fail the connection
                return Err(MySqlError::Driver(
                    mysql_async::DriverError::PoolDisconnected,
                ));
            }
        };

        // Ensure we are running in TRADITIONAL mysql mode. TRADITIONAL mysql
        // converts many warnings to errors, for example it will reject too
        // large blob entries instead of truncating them with a warning.
        // This is essential for our system, since SEE relies on all data in our
        // XDB being exactly what it wrote.
        connection
            .query_drop("SET SESSION sql_mode = 'TRADITIONAL'")
            .await?;
        Ok(connection)
    }

    // Occasionally our connection pool will become stale. This happens
    // e.g on DB master promotions during mysql upgrades. In these scenarios our
    // queries will begin to fail, and we will need to call this method to
    // "refresh" the pool.
    async fn refresh_connection_pool(&self) -> core::result::Result<(), StorageError> {
        {
            let mut is_healthy_guard = self.is_healthy.write().await;
            if !*is_healthy_guard {
                info!("Already refreshing MySql connection pool!");
                return Ok(());
            }

            *is_healthy_guard = false;
        }
        warn!("Refreshing MySql connection pool.");
        debug!("BEGIN refresh mysql connection pool");

        // Grab early write lock so no new queries can be initiated before
        // connection pool is refreshed.
        let mut connection_pool_guard = self.pool.write().await;
        let pool = Self::new_connection_pool(&self.opts, &self.is_healthy).await?;
        *connection_pool_guard = pool;

        debug!("END refresh mysql connection pool");
        Ok(())
    }

    async fn new_connection_pool(
        opts: &mysql_async::Opts,
        is_healthy: &Arc<tokio::sync::RwLock<bool>>,
    ) -> core::result::Result<mysql_async::Pool, StorageError> {
        let start = Instant::now();
        let mut attempts = 1;

        loop {
            let ip = opts.ip_or_hostname();
            let pool_options = opts.clone();
            let pool = Pool::new(pool_options);
            let conn = pool.get_conn().await;

            if let Ok(_conn) = conn {
                match Self::setup_database(_conn).await {
                    Ok(()) => {
                        // set the healthy flag to true
                        let mut is_healthy_guard = is_healthy.write().await;
                        *is_healthy_guard = true;

                        return Ok(pool);
                    }
                    Err(_err) => {
                        #[cfg(test)]
                        panic!("Error setting up db {}", _err)
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
                error!("{}", message);
                return Err(StorageError::Connection(message));
            }

            warn!(
                "Failed {:?} reconnection attempt(s) to MySQL database. Will retry in {} seconds",
                attempts, SQL_RECONNECTION_DELAY_SECS
            );

            tokio::time::sleep(tokio::time::Duration::from_secs(
                // TOKIO 0.2.X
                //tokio::time::sleep(tokio::time::Duration::from_secs( // TOKIO 1.X
                SQL_RECONNECTION_DELAY_SECS,
            ))
            .await;

            attempts += 1
        }
    }

    async fn setup_database(mut conn: mysql_async::Conn) -> core::result::Result<(), MySqlError> {
        let mut tx: mysql_async::Transaction<'_> =
            conn.start_transaction(TxOpts::default()).await?;
        // AZKS table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE_AZKS
            + "` (`key` SMALLINT UNSIGNED NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL,"
            + " `num_nodes` BIGINT UNSIGNED NOT NULL, PRIMARY KEY (`key`))";
        tx.query_drop(command).await?;

        // History tree nodes table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE_HISTORY_TREE_NODES
            + "` (`label_len` INT UNSIGNED NOT NULL, `label_val` VARBINARY(32) NOT NULL,"
            + " `last_epoch` BIGINT UNSIGNED NOT NULL,"
            + " `least_descendent_ep` BIGINT UNSIGNED NOT NULL, `parent_label_len` INT UNSIGNED NOT NULL,"
            + " `parent_label_val` VARBINARY(32) NOT NULL, `node_type` SMALLINT UNSIGNED NOT NULL,"
            + " `left_child_len` INT UNSIGNED, `left_child_label_val` VARBINARY(32),"
            + " `right_child_len` INT UNSIGNED, `right_child_label_val` VARBINARY(32), `hash` VARBINARY(32) NOT NULL,"
            + " PRIMARY KEY (`label_len`, `label_val`))";
        tx.query_drop(command).await?;

        // User data table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE_USER
            + "` (`username` VARBINARY(256) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, `version` BIGINT UNSIGNED NOT NULL,"
            + " `node_label_val` VARBINARY(32) NOT NULL, `node_label_len` INT UNSIGNED NOT NULL, `data` VARBINARY(2000),"
            + " PRIMARY KEY(`username`, `epoch`))";
        tx.query_drop(command).await?;

        // if we got here, we're good to commit. Transaction's will auto-rollback when memory freed if commit wasn't done.
        tx.commit().await?;
        Ok(())
    }

    /// Delete all the data in the tables
    pub async fn delete_data(&self) -> core::result::Result<(), MySqlError> {
        let mut conn = self.get_connection().await?;
        let mut tx = conn.start_transaction(TxOpts::default()).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_AZKS + "`";
        tx.query_drop(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_USER + "`";
        tx.query_drop(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_HISTORY_TREE_NODES + "`";
        tx.query_drop(command).await?;

        tx.commit().await?;

        Ok(())
    }

    /// Drop all the tables
    pub async fn drop_tables(&self) -> core::result::Result<(), MySqlError> {
        let mut conn = self.get_connection().await?;
        let mut tx = conn.start_transaction(TxOpts::default()).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_AZKS + "`";
        tx.query_drop(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_USER + "`";
        tx.query_drop(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_HISTORY_TREE_NODES + "`";
        tx.query_drop(command).await?;

        tx.commit().await?;

        Ok(())
    }

    /// Storage a record in the data layer
    async fn internal_set(
        &self,
        record: DbRecord,
        trans: Option<mysql_async::Transaction<'a>>,
    ) -> Result<()> {
        *(self.num_writes.write().await) += 1;
        self.record_call_stats('w', "internal_set".to_string(), "".to_string())
            .await;

        debug!("BEGIN MySQL set");
        let tic = Instant::now();

        let statement_text = record.set_statement();
        let params = record
            .set_params()
            .ok_or_else(|| Error::Other("Failed to construct MySQL parameters block".into()))?;

        let out = match trans {
            Some(mut tx) => match tx.exec_drop(statement_text, params).await {
                Err(err) => Err(err),
                Ok(next_tx) => Ok(next_tx),
            },
            None => {
                let mut conn = self.get_connection().await?;
                if let Err(err) = conn.exec_drop(statement_text, params).await {
                    Err(err)
                } else {
                    Ok(())
                }
            }
        };
        let result = self.check_for_infra_error(out)?;
        let toc = Instant::now() - tic;
        *(self.time_write.write().await) += toc;

        debug!("END MySQL set");
        Ok(result)
    }

    /// NOTE: This is assuming all of the DB records have been narrowed down to a single record type!
    async fn internal_batch_set(
        &self,
        records: Vec<DbRecord>,
        mut trans: mysql_async::Transaction<'a>,
    ) -> core::result::Result<mysql_async::Transaction<'a>, MySqlError> {
        if records.is_empty() {
            return Ok(trans);
        }

        *(self.num_writes.write().await) += records.len() as u64;
        self.record_call_stats('w', "internal_batch_set".to_string(), "".to_string())
            .await;

        debug!("BEGIN Computing mysql parameters");
        #[allow(clippy::needless_collect)]
        let chunked = records
            .chunks(self.tunable_insert_depth)
            .map(|batch| {
                if batch.is_empty() {
                    Ok(BatchMode::None)
                } else if batch.len() < self.tunable_insert_depth {
                    DbRecord::set_batch_params(batch)
                        .map(|out| BatchMode::Partial(out, batch.len()))
                } else {
                    DbRecord::set_batch_params(batch).map(BatchMode::Full)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        debug!("END Computing mysql parameters");

        debug!("BEGIN MySQL set batch");
        let head = &records[0];
        let statement = |i: usize| -> String {
            match &head {
                DbRecord::Azks(_) => DbRecord::set_batch_statement::<akd::Azks>(i),
                DbRecord::TreeNode(_) => DbRecord::set_batch_statement::<TreeNode>(i),
                DbRecord::ValueState(_) => {
                    DbRecord::set_batch_statement::<akd::storage::types::ValueState>(i)
                }
            }
        };

        let mut params = vec![];
        let mut fallout: Option<(mysql_async::Params, usize)> = None;
        for item in chunked {
            match item {
                BatchMode::Full(part) => params.push(part),
                BatchMode::Partial(part, count) => fallout = Some((part, count)),
                _ => {}
            }
        }

        let tic = Instant::now();

        debug!("MySQL batch - {} full inserts", params.len());
        // insert the batches of size = MYSQL_EXTENDED_INSERT_DEPTH
        if !params.is_empty() {
            let fill_statement = statement(self.tunable_insert_depth);
            let out = trans.exec_batch(fill_statement, params).await;
            self.check_for_infra_error(out)?;
        }

        // insert the remainder as a final statement
        if let Some((remainder, count)) = fallout {
            debug!("MySQL batch - remainder {} insert", count);
            let remainder_stmt = statement(count);
            let out = trans.exec_drop(remainder_stmt, remainder).await;
            self.check_for_infra_error(out)?;
        }

        let toc = Instant::now() - tic;
        *(self.time_write.write().await) += toc;
        debug!("END MySQL set batch");
        Ok(trans)
    }

    /// Create the test database
    #[allow(dead_code)]
    pub async fn create_test_db<T: Into<String>>(
        endpoint: T,
        user: Option<T>,
        password: Option<T>,
        port: Option<u16>,
    ) -> core::result::Result<(), MySqlError> {
        let dport = port.unwrap_or(3306u16);
        let builder = OptsBuilder::default()
            .ip_or_hostname(endpoint)
            .user(user)
            .pass(password)
            .tcp_port(dport);
        let opts: Opts = Opts::from(builder);
        let mut conn = Conn::new(opts).await?;
        conn.query_drop(r"CREATE DATABASE IF NOT EXISTS test_db")
            .await?;

        Ok(())
    }

    async fn record_call_stats(&self, call_type: char, caller_name: String, data_type: String) {
        let mut stats;
        if call_type == 'r' {
            stats = self.read_call_stats.write().await;
        } else if call_type == 'w' {
            stats = self.write_call_stats.write().await;
        } else {
            panic!("Unknown call type to record call stats for.")
        }
        let call_count = (*stats).entry(caller_name + "~" + &data_type).or_insert(0);
        *call_count += 1;
    }

    fn try_dockers() -> std::io::Result<std::process::Output> {
        let potential_docker_paths = vec![
            "/usr/local/bin/docker",
            "/usr/bin/docker",
            "/sbin/docker",
            "/bin/docker",
            "docker",
        ];

        let mut output = Err(std::io::Error::from_raw_os_error(2));

        for path in potential_docker_paths {
            output = Command::new(path)
                // Name filter lists containers containing the name. See https://docs.docker.com/engine/reference/commandline/ps/.
                // Therefore, a container with a name like akd-test-dbc would match but would be wrong.
                // This regex ensures exact match.
                .args(["container", "ls", "-f", "name=^/akd-test-db$"])
                .output();
            match &output {
                Ok(result) => {
                    if let (Ok(out), Ok(err)) = (
                        std::str::from_utf8(&result.stdout),
                        std::str::from_utf8(&result.stderr),
                    ) {
                        info!("Docker ls output\nSTDOUT: {}\nSTDERR: {}", out, err);
                    }
                    break;
                }
                Err(err) => {
                    warn!("Docker ls returned error \"{:?}\"\nTrying next possible docker command location", err);
                }
            }
        }

        output
    }

    /// Determine if the MySQL environment is available for execution (i.e. docker container is running)
    #[allow(dead_code)]
    pub fn test_guard() -> bool {
        let output = Self::try_dockers();

        // docker threw some kind of error running, assume down
        if let Ok(result) = output {
            // the result will look like
            //
            // CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS         PORTS                                                  NAMES
            // 4bd11d9e28f2   ecac195d15af   "docker-entrypoint.s…"   4 minutes ago   Up 4 minutes   33060/tcp, 0.0.0.0:8001->3306/tcp, :::8001->3306/tcp   seemless-test-db
            //
            // so there should be 2 output lines assuming all is successful and the container is running.
            const NUM_LINES_EXPECTED: usize = 2;

            let err = std::str::from_utf8(&result.stderr);
            if let Ok(error_message) = err {
                if !error_message.is_empty() {
                    error!("Error executing docker command: {}", error_message);
                }
            }

            // Note that lines().count() returns the same number for lines with and without a final line ending.
            let is_container_listed = std::str::from_utf8(&result.stdout)
                .map(|str| str.lines().count() == NUM_LINES_EXPECTED);
            return is_container_listed.unwrap_or(false);
        }

        // docker may have thrown an error, just fail
        false
    }
}

#[async_trait]
impl Storage for AsyncMySqlDatabase {
    async fn log_metrics(&self, level: log::Level) {
        if let Some(cache) = &self.cache {
            cache.log_metrics(level).await
        }

        self.trans.log_metrics(level).await;

        let mut tree_size = "Tree size: Query err".to_string();
        let mut value_state_size = "Value state count: Query err".to_string();
        if let Ok(mut conn) = self.get_connection().await {
            let query_text = format!("SELECT COUNT(*) FROM {}", TABLE_HISTORY_TREE_NODES);
            if let Ok(results) = conn.query_iter(query_text).await {
                if let Ok(mapped) = results
                    .map_and_drop(|row| {
                        let count: u64 = mysql_async::from_row(row);
                        count
                    })
                    .await
                {
                    if let Some(count) = mapped.first() {
                        tree_size = format!("Tree size: {}", count);
                    }

                    let query_text = format!("SELECT COUNT(`epoch`) FROM {}", TABLE_USER);
                    if let Ok(results) = conn.query_iter(query_text).await {
                        if let Ok(mapped) = results
                            .map_and_drop(|row| {
                                let count: u64 = mysql_async::from_row(row);
                                count
                            })
                            .await
                        {
                            if let Some(count) = mapped.first() {
                                value_state_size = format!("Value state count: {}", count);
                            }
                        }
                    }
                }
            }
        }

        let mut r = self.num_reads.write().await;
        let mut rcs = self.read_call_stats.write().await;
        let mut w = self.num_writes.write().await;
        let mut wcs = self.write_call_stats.write().await;
        let mut tr = self.time_read.write().await;
        let mut tw = self.time_write.write().await;

        // Sort call stats for consistency.
        let mut rcs_vec = (*rcs).iter().collect::<Vec<_>>();
        let mut wcs_vec = (*wcs).iter().collect::<Vec<_>>();
        rcs_vec.sort_by_key(|rc| rc.0);
        wcs_vec.sort_by_key(|wc| wc.0);

        let msg = format!(
            "MySQL writes: {}, MySQL reads: {}, Time read: {} s, Time write: {} s\n\t{}\n\t{}\nRead call stats: {:?}\nWrite call stats: {:?}\n",
            *w,
            *r,
            (*tr).as_secs_f64(),
            (*tw).as_secs_f64(),
            tree_size,
            value_state_size,
            rcs_vec,
            wcs_vec,
        );

        *r = 0;
        *rcs = HashMap::new();
        *w = 0;
        *wcs = HashMap::new();
        *tr = Duration::from_millis(0);
        *tw = Duration::from_millis(0);

        match level {
            // Currently logs cannot be captured unless they are
            // println!. Normally Level::Trace should use the trace! macro.
            log::Level::Trace => println!("{}", msg),
            log::Level::Debug => debug!("{}", msg),
            log::Level::Info => info!("{}", msg),
            log::Level::Warn => warn!("{}", msg),
            _ => error!("{}", msg),
        }
    }

    /// Start a transaction in the storage layer
    async fn begin_transaction(&self) -> bool {
        // disable the cache cleaning since we're in a write transaction
        // and will want to keep cache'd objects for the life of the transaction
        if let Some(cache) = &self.cache {
            cache.disable_clean().await;
        }

        self.trans.begin_transaction().await
    }

    /// Commit a transaction in the storage layer
    async fn commit_transaction(&self) -> core::result::Result<(), StorageError> {
        // The transaction is now complete (or reverted) and therefore we can re-enable
        // the cache cleaning status
        if let Some(cache) = &self.cache {
            cache.enable_clean().await;
        }

        // this retrieves all the trans operations, and "de-activates" the transaction flag
        let ops = self.trans.commit_transaction().await?;
        self.batch_set(ops).await
    }

    /// Rollback a transaction
    async fn rollback_transaction(&self) -> core::result::Result<(), StorageError> {
        // The transaction is being reverted and therefore we can re-enable
        // the cache cleaning status
        if let Some(cache) = &self.cache {
            cache.enable_clean().await;
        }

        self.trans.rollback_transaction().await
    }

    /// Retrieve a flag determining if there is a transaction active
    async fn is_transaction_active(&self) -> bool {
        self.trans.is_transaction_active().await
    }

    /// Storage a record in the data layer
    async fn set(&self, record: DbRecord) -> core::result::Result<(), StorageError> {
        // we're in a transaction, set the item in the transaction
        if self.is_transaction_active().await {
            self.trans.set(&record).await;
            return Ok(());
        }

        if let Some(cache) = &self.cache {
            cache.put(&record).await;
        }

        match self.internal_set(record, None).await {
            Ok(_) => Ok(()),
            Err(error) => {
                error!("MySQL error {}", error);
                Err(StorageError::Other(format!("MySQL Error {}", error)))
            }
        }
    }

    async fn batch_set(&self, records: Vec<DbRecord>) -> core::result::Result<(), StorageError> {
        if records.is_empty() {
            // nothing to do, save the cycles
            return Ok(());
        }

        // we're in a transaction, set the items in the transaction
        if self.is_transaction_active().await {
            for record in records.into_iter() {
                self.trans.set(&record).await;
            }
            return Ok(());
        }

        if let Some(cache) = &self.cache {
            let _ = cache.batch_put(&records).await;
        }

        // generate batches by type
        let mut groups = std::collections::HashMap::new();
        for record in records {
            match &record {
                DbRecord::Azks(_) => groups
                    .entry(StorageType::Azks)
                    .or_insert_with(Vec::new)
                    .push(record),
                DbRecord::TreeNode(_) => groups
                    .entry(StorageType::TreeNode)
                    .or_insert_with(Vec::new)
                    .push(record),
                DbRecord::ValueState(_) => groups
                    .entry(StorageType::ValueState)
                    .or_insert_with(Vec::new)
                    .push(record),
            }
        }
        // now execute each type'd batch in batch operations
        let result = async {
            let mut conn = self.get_connection().await?;
            let mut tx = conn.start_transaction(TxOpts::default()).await?;
            // go through each group which is narrowed to a single type
            // applying the changes on the transaction
            tx.query_drop("SET autocommit=0").await?;
            tx.query_drop("SET unique_checks=0").await?;
            tx.query_drop("SET foreign_key_checks=0").await?;

            for (_key, mut value) in groups.into_iter() {
                if !value.is_empty() {
                    // Sort the records to match db-layer sorting which will help with insert performance
                    value.sort_by(|a, b| match &a {
                        DbRecord::TreeNode(node) => {
                            if let DbRecord::TreeNode(node2) = &b {
                                node.label.cmp(&node2.label)
                            } else {
                                Ordering::Equal
                            }
                        }
                        DbRecord::ValueState(state) => {
                            if let DbRecord::ValueState(state2) = &b {
                                match state.username.0.cmp(&state2.username.0) {
                                    Ordering::Equal => state.epoch.cmp(&state2.epoch),
                                    other => other,
                                }
                            } else {
                                Ordering::Equal
                            }
                        }
                        _ => Ordering::Equal,
                    });
                    // execute the multi-batch insert statement(s)
                    tx = self.internal_batch_set(value, tx).await?;
                }
            }

            tx.query_drop("SET autocommit=1").await?;
            tx.query_drop("SET unique_checks=1").await?;
            tx.query_drop("SET foreign_key_checks=1").await?;

            tx.commit().await?;
            Ok::<(), MySqlError>(())
        };
        match result.await {
            Ok(_) => Ok(()),
            Err(error) => {
                error!("MySQL error {}", error);
                Err(StorageError::Other(format!("MySQL Error {}", error)))
            }
        }
    }

    /// Retrieve a stored record from the data layer
    async fn get<St: Storable>(
        &self,
        id: &St::Key,
    ) -> core::result::Result<DbRecord, StorageError> {
        // we're in a transaction, meaning the object _might_ be newer and therefore we should try and read if from the transaction
        // log instead of the raw storage layer
        if self.is_transaction_active().await {
            if let Some(result) = self.trans.get::<St>(id).await {
                return Ok(result);
            }
        }

        // check for a cache hit
        if let Some(cache) = &self.cache {
            if let Some(result) = cache.hit_test::<St>(id).await {
                return Ok(result);
            }
        }

        // cache miss, log a real sql read op
        let record = self.get_direct::<St>(id).await?;
        if let Some(cache) = &self.cache {
            // cache the result
            cache.put(&record).await;
        }
        Ok(record)
    }

    async fn get_direct<St: Storable>(
        &self,
        id: &St::Key,
    ) -> core::result::Result<DbRecord, StorageError> {
        *(self.num_reads.write().await) += 1;
        self.record_call_stats(
            'r',
            "get_direct:".to_string(),
            format!("{:?}", St::data_type()),
        )
        .await;

        debug!("BEGIN MySQL get {:?}", id);
        let result = async {
            let tic = Instant::now();

            let mut conn = self.get_connection().await?;
            let statement = DbRecord::get_specific_statement::<St>();
            let params = DbRecord::get_specific_params::<St>(id);
            let out = match params {
                Some(p) => match conn.exec_first(statement, p).await {
                    Err(err) => Err(err),
                    Ok(result) => Ok(result),
                },
                None => match conn.query_first(statement).await {
                    Err(err) => Err(err),
                    Ok(result) => Ok(result),
                },
            };

            let toc = Instant::now() - tic;
            *(self.time_read.write().await) += toc;

            let result = self.check_for_infra_error(out)?;
            if let Some(mut row) = result {
                // return result
                let record = DbRecord::from_row::<St>(&mut row)?;
                return Ok::<Option<DbRecord>, MySqlError>(Some(record));
            }
            Ok::<Option<DbRecord>, MySqlError>(None)
        };

        debug!("END MySQL get");
        match result.await {
            Ok(Some(r)) => Ok(r),
            Ok(None) => Err(StorageError::NotFound(format!(
                "{:?} {:?}",
                St::data_type(),
                id
            ))),
            Err(error) => {
                error!("MySQL error {}", error);
                Err(StorageError::Other(format!("MySQL Error {}", error)))
            }
        }
    }

    /// Flush the caching of objects (if present)
    async fn flush_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.flush().await;
        }
    }

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::Key],
    ) -> core::result::Result<Vec<DbRecord>, StorageError> {
        let mut map = Vec::new();

        if ids.is_empty() {
            // nothing to retrieve, save the cycles
            return Ok(map);
        }

        let mut key_set: HashSet<St::Key> = ids.iter().cloned().collect::<HashSet<_>>();

        let trans_active = self.is_transaction_active().await;
        // first check the transaction log & cache records
        for id in ids.iter() {
            if trans_active {
                // we're in a transaction, meaning the object _might_ be newer and therefore we should try and read if from the transaction
                // log instead of the raw storage layer
                if let Some(result) = self.trans.get::<St>(id).await {
                    map.push(result);
                    key_set.remove(id);
                    continue;
                }
            }

            // check if item is cached
            if let Some(cache) = &self.cache {
                if let Some(result) = cache.hit_test::<St>(id).await {
                    map.push(result);
                    key_set.remove(id);
                    continue;
                }
            }
        }

        if !key_set.is_empty() {
            // these are items to be retrieved from the backing database (not in pending transaction or in the object cache)
            let result = async {
                let tic = Instant::now();

                let key_set_vec: Vec<_> = key_set.into_iter().collect();

                debug!("BEGIN MySQL get batch");
                let mut conn = self.get_connection().await?;

                let results = if let Some(create_table_cmd) =
                    DbRecord::get_batch_create_temp_table::<St>()
                {
                    // Create the temp table of ids
                    let out = conn.query_drop(create_table_cmd).await;
                    self.check_for_infra_error(out)?;

                    // Fill temp table with the requested ids
                    let mut tx = conn.start_transaction(TxOpts::default()).await?;
                    tx.query_drop("SET autocommit=0").await?;
                    tx.query_drop("SET unique_checks=0").await?;
                    tx.query_drop("SET foreign_key_checks=0").await?;

                    let mut fallout: Option<Vec<_>> = None;
                    let mut params = vec![];
                    for batch in key_set_vec.chunks(self.tunable_insert_depth) {
                        if batch.len() < self.tunable_insert_depth {
                            fallout = Some(batch.to_vec());
                        } else if let Some(p) = DbRecord::get_multi_row_specific_params::<St>(batch)
                        {
                            params.push(p);
                        } else {
                            return Err(MySqlError::Other(
                                "Unable to generate type-specific MySQL parameters".into(),
                            ));
                        }
                    }

                    // insert the batches of size = MYSQL_EXTENDED_INSERT_DEPTH
                    if !params.is_empty() {
                        let fill_statement = DbRecord::get_batch_fill_temp_table::<St>(Some(
                            self.tunable_insert_depth,
                        ));
                        let out = tx.exec_batch(fill_statement, params).await;
                        self.check_for_infra_error(out)?;
                        // We would need the statement for it. (Possibly) No need for close here.
                        // See https://docs.rs/mysql_async/0.28.1/mysql_async/struct.Opts.html#caveats.
                        // tx.close().await?;
                    }

                    // insert the remainder as a final statement
                    if let Some(remainder) = fallout {
                        let remainder_stmt =
                            DbRecord::get_batch_fill_temp_table::<St>(Some(remainder.len()));
                        let params_batch =
                            DbRecord::get_multi_row_specific_params::<St>(&remainder);
                        if let Some(pb) = params_batch {
                            let out = tx.exec_drop(remainder_stmt, pb).await;
                            self.check_for_infra_error(out)?;
                        } else {
                            return Err(MySqlError::Other(
                                "Unable to generate type-specific MySQL parameters".into(),
                            ));
                        }
                    }

                    tx.query_drop("SET autocommit=1").await?;
                    tx.query_drop("SET unique_checks=1").await?;
                    tx.query_drop("SET foreign_key_checks=1").await?;
                    tx.commit().await?;

                    // Query the records which intersect (INNER JOIN) with the temp table of ids
                    let query = DbRecord::get_batch_statement::<St>();
                    let out = conn.query_iter(query).await;
                    let result = self.check_for_infra_error(out)?;

                    let out = result
                        .reduce_and_drop(vec![], |mut acc, mut row| {
                            if let Ok(result) = DbRecord::from_row::<St>(&mut row) {
                                acc.push(result);
                            }
                            acc
                        })
                        .await?;

                    // drop the temp table of ids
                    let t_out = conn
                        .query_drop(format!("DROP TEMPORARY TABLE `{}`", TEMP_IDS_TABLE))
                        .await;
                    self.check_for_infra_error(t_out)?;

                    out
                } else {
                    // no results (i.e. AZKS table doesn't support "get by batch ids")
                    vec![]
                };

                debug!("END MySQL get batch");
                let toc = Instant::now() - tic;
                *(self.time_read.write().await) += toc;

                if let Some(cache) = &self.cache {
                    // insert retrieved records into the cache for faster future access
                    for el in results.iter() {
                        cache.put(el).await;
                    }
                }

                Ok::<Vec<DbRecord>, mysql_async::Error>(results)
            };

            *(self.num_reads.write().await) += 1;
            self.record_call_stats(
                'r',
                "batch_get".to_string(),
                format!("{:?}", St::data_type()),
            )
            .await;

            match result.await {
                Ok(result_vec) => {
                    for item in result_vec.into_iter() {
                        map.push(item);
                    }
                }
                Err(error) => {
                    error!("MySQL error {}", error);
                    return Err(StorageError::Other(format!("MySQL Error {}", error)));
                }
            }
        }
        Ok(map)
    }

    async fn tombstone_value_states(
        &self,
        keys: &[akd::storage::types::ValueStateKey],
    ) -> core::result::Result<(), StorageError> {
        // NOTE: This might be optimizable in the future where we could use a SQL statement such as
        //
        // UPDATE `users`
        // SET `data` = TOMBSTONE
        // WHERE key in (set)
        //
        // However, the problem comes from managing an active transaction and cache (if there is one)
        // since we may need to batch load nodes anyways in order to get the other properties
        // which might need to be set. We could write everything to SQL, and after-the-fact update
        // the active transaction and caches with replacing nodes which were updated? Anyways it's a
        // relatively minor improvement here, due to proper use of batch operations

        if keys.is_empty() {
            return Ok(());
        }

        let data = self.batch_get::<ValueState>(keys).await?;
        let mut new_data = vec![];
        for record in data {
            if let DbRecord::ValueState(value_state) = record {
                new_data.push(DbRecord::ValueState(ValueState {
                    epoch: value_state.epoch,
                    label: value_state.label,
                    plaintext_val: akd::AkdValue(akd::TOMBSTONE.to_vec()),
                    username: value_state.username,
                    version: value_state.version,
                }));
            }
        }
        if !new_data.is_empty() {
            debug!("Tombstoning {} entries", new_data.len());
            self.batch_set(new_data).await?;
        }

        Ok(())
    }

    async fn get_user_data(
        &self,
        username: &AkdLabel,
    ) -> core::result::Result<KeyData, StorageError> {
        // This is the same as previous logic under "get_all"

        *(self.num_reads.write().await) += 1;
        self.record_call_stats('r', "get_user_data".to_string(), "".to_string())
            .await;

        // DO NOT log the user info, it's PII in the future
        debug!("BEGIN MySQL get user data");
        let result = async {
            let tic = Instant::now();

            let mut conn = self.get_connection().await?;
            let statement_text =
                "SELECT `username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                    .to_owned()
                    + TABLE_USER
                    + "` WHERE `username` = :the_user";
            let mut result = conn
                .exec_iter(statement_text, params! { "the_user" => username.0.clone() })
                .await?;
            let out = result
                .map(|mut row| {
                    if let (
                        Some(username),
                        Some(epoch),
                        Some(version),
                        Some(node_label_val),
                        Some(node_label_len),
                        Some(data),
                    ) = (
                        row.take(0),
                        row.take(1),
                        row.take(2),
                        row.take::<Vec<u8>, _>(3),
                        row.take(4),
                        row.take(5),
                    ) {
                        // explicitly check the array length for safety
                        if node_label_val.len() == 32 {
                            let val: [u8; 32] = node_label_val.try_into().unwrap();
                            return Some(ValueState {
                                epoch,
                                version,
                                label: NodeLabel {
                                    val,
                                    len: node_label_len,
                                },
                                plaintext_val: akd::storage::types::AkdValue(data),
                                username: akd::storage::types::AkdLabel(username),
                            });
                        }
                    }
                    None
                })
                .await
                .map(|a| a.into_iter().flatten().collect::<Vec<_>>());

            let toc = Instant::now() - tic;
            *(self.time_read.write().await) += toc;
            let selected_records = self.check_for_infra_error(out)?;
            if let Some(cache) = &self.cache {
                for record in selected_records.iter() {
                    cache.put(&DbRecord::ValueState(record.clone())).await;
                }
            }
            if self.is_transaction_active().await {
                let mut updated = vec![];
                for record in selected_records.into_iter() {
                    if let Some(DbRecord::ValueState(value)) = self
                        .trans
                        .get::<akd::storage::types::ValueState>(&record.get_id())
                        .await
                    {
                        updated.push(value);
                    } else {
                        updated.push(record);
                    }
                }
                Ok::<KeyData, MySqlError>(KeyData { states: updated })
            } else {
                Ok::<KeyData, MySqlError>(KeyData {
                    states: selected_records,
                })
            }
        };

        debug!("END MySQL get user data");
        match result.await {
            Ok(output) => Ok(output),
            Err(error) => {
                error!("MySQL error {}", error);
                Err(StorageError::Other(format!("MySQL Error {}", error)))
            }
        }
    }

    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> core::result::Result<ValueState, StorageError> {
        *(self.num_reads.write().await) += 1;
        self.record_call_stats('r', "get_user_state".to_string(), "".to_string())
            .await;

        debug!("BEGIN MySQL get user state (flag {:?})", flag);
        let result = async {
            let tic = Instant::now();

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
                ValueStateRetrievalFlag::MinEpoch => statement_text += " ORDER BY `epoch` ASC",
                ValueStateRetrievalFlag::LeqEpoch(epoch) => {
                    params_map.push(("the_epoch", Value::from(epoch)));
                    statement_text += " AND `epoch` <= :the_epoch ORDER BY `epoch` DESC";
                }
            }

            // add limit to retrieve only 1 record
            statement_text += " LIMIT 1";
            let out = conn
                .exec_iter(statement_text, mysql_async::Params::from(params_map))
                .await?
                .map(|mut row| {
                    if let (
                        Some(username),
                        Some(epoch),
                        Some(version),
                        Some(node_label_val),
                        Some(node_label_len),
                        Some(data),
                    ) = (
                        row.take(0),
                        row.take(1),
                        row.take(2),
                        row.take::<Vec<_>, _>(3),
                        row.take(4),
                        row.take(5),
                    ) {
                        // explicitly check the array length for safety
                        if node_label_val.len() == 32 {
                            let val: [u8; 32] = node_label_val.try_into().unwrap();
                            return Some(ValueState {
                                epoch,
                                version,
                                label: NodeLabel {
                                    val,
                                    len: node_label_len,
                                },
                                plaintext_val: akd::storage::types::AkdValue(data),
                                username: akd::storage::types::AkdLabel(username),
                            });
                        }
                    }
                    None
                })
                .await
                .map(|a| a.into_iter().flatten().collect::<Vec<_>>());

            let toc = Instant::now() - tic;
            *(self.time_read.write().await) += toc;
            let selected_record = self.check_for_infra_error(out)?;

            let item = selected_record.into_iter().next();
            if let Some(value_in_item) = &item {
                if let Some(cache) = &self.cache {
                    cache
                        .put(&DbRecord::ValueState(value_in_item.clone()))
                        .await;
                }
            }
            // check the transaction log for an updated record
            if self.is_transaction_active().await {
                if let Some(found_item) = &item {
                    if let Some(DbRecord::ValueState(value)) = self
                        .trans
                        .get::<akd::storage::types::ValueState>(&found_item.get_id())
                        .await
                    {
                        return Ok::<Option<ValueState>, MySqlError>(Some(value));
                    }
                }
            }
            Ok::<Option<ValueState>, MySqlError>(item)
        };
        debug!("END MySQL get user state");
        match result.await {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(StorageError::NotFound(format!("ValueState {:?}", username))),
            Err(error) => {
                error!("MySQL error {}", error);
                Err(StorageError::Other(format!("MySQL Error {}", error)))
            }
        }
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> core::result::Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError> {
        *(self.num_reads.write().await) += 1;
        self.record_call_stats('r', "get_user_state_versions".to_string(), "".to_string())
            .await;

        let mut results = HashMap::new();

        debug!("BEGIN MySQL get user state versions (flag {:?})", flag);
        let result = async {
            let tic = Instant::now();

            let mut conn = self.get_connection().await?;

            debug!("Creating the temporary search username's table");
            let out = conn
                .query_drop(
                    "CREATE TEMPORARY TABLE `search_users`(`username` VARBINARY(256) NOT NULL, PRIMARY KEY (`username`))",
                )
                .await;
            self.check_for_infra_error(out)?;

            debug!(
                "Inserting the query users into the temporary table in batches of {}",
                self.tunable_insert_depth
            );

            let mut tx = conn.start_transaction(TxOpts::default()).await?;
            tx.query_drop("SET autocommit=0").await?;
            tx.query_drop("SET unique_checks=0").await?;
            tx.query_drop("SET foreign_key_checks=0").await?;

            let mut statement = "INSERT INTO `search_users` (`username`) VALUES ".to_string();
            for i in 0..self.tunable_insert_depth {
                if i < self.tunable_insert_depth - 1 {
                    statement += format!("(:username{}), ", i).as_ref();
                } else {
                    statement += format!("(:username{})", i).as_ref();
                }
            }

            let mut fallout: Option<Vec<_>> = None;
            let mut params = vec![];
            for batch in keys.chunks(self.tunable_insert_depth) {
                if batch.len() < self.tunable_insert_depth {
                    // final batch, use a new query
                    fallout = Some(batch.to_vec());
                } else {
                    let pvec: Vec<_> = batch
                        .iter()
                        .enumerate()
                        .map(|(idx, username)| {
                            (format!("username{}", idx), Value::from(username.0.clone()))
                        })
                        .collect();
                    params.push(mysql_async::Params::from(pvec));
                }
            }

            if !params.is_empty() {
                // first do the big batches
                let out = tx.exec_batch(statement, params).await;
                self.check_for_infra_error(out)?;
            }

            if let Some(remainder) = fallout {
                // now there's some remainder that wasn't _exactly_ equal to MYSQL_EXTENDED_INSERT_DEPTH
                // we do it item-by-item
                let rlen = remainder.len();
                let mut remainder_stmt =
                    "INSERT INTO `search_users` (`username`) VALUES ".to_string();
                for i in 0..rlen {
                    if i < rlen - 1 {
                        remainder_stmt += format!("(:username{}), ", i).as_ref();
                    } else {
                        remainder_stmt += format!("(:username{})", i).as_ref();
                    }
                }

                // we don't need a prepared statement, since we're only doing this 1 time
                let users_vec: Vec<_> = remainder
                    .iter()
                    .enumerate()
                    .map(|(idx, username)| {
                        (format!("username{}", idx), Value::from(username.0.clone()))
                    })
                    .collect();
                let params_batch = mysql_async::Params::from(users_vec);
                let out = tx.exec_drop(remainder_stmt, params_batch).await;
                self.check_for_infra_error(out)?;
            }

            // re-enable all the checks
            tx.query_drop("SET autocommit=1").await?;
            tx.query_drop("SET unique_checks=1").await?;
            tx.query_drop("SET foreign_key_checks=1").await?;

            // commit the transaction
            tx.commit().await?;

            debug!("Querying records with JOIN");
            // select all records for provided user names
            let mut params_map = vec![];
            let (filter, epoch_grouping) = {
                // apply the specific filter
                match flag {
                    ValueStateRetrievalFlag::SpecificVersion(version) => {
                        params_map.push(("the_version", Value::from(version)));
                        ("WHERE tmp.`version` = :the_version", "tmp.`epoch`")
                    }
                    ValueStateRetrievalFlag::SpecificEpoch(epoch) => {
                        params_map.push(("the_epoch", Value::from(epoch)));
                        ("WHERE tmp.`epoch` = :the_epoch", "tmp.`epoch`")
                    }
                    ValueStateRetrievalFlag::MaxEpoch => ("", "MAX(tmp.`epoch`)"),
                    ValueStateRetrievalFlag::MinEpoch => ("", "MIN(tmp.`epoch`)"),
                    ValueStateRetrievalFlag::LeqEpoch(epoch) => {
                        params_map.push(("the_epoch", Value::from(epoch)));
                        (" WHERE tmp.`epoch` <= :the_epoch", "MAX(tmp.`epoch`)")
                    }
                }
            };
            let select_statement = format!(
                r"SELECT full.`username`, full.`version`, full.`data`
                FROM {} full
                INNER JOIN (
                    SELECT tmp.`username`, {} AS `epoch`
                    FROM {} tmp
                    INNER JOIN `search_users` su
                        ON su.`username` = tmp.`username`
                    {}
                    GROUP BY tmp.`username`
                ) epochs
                    ON epochs.`username` = full.`username`
                    AND epochs.`epoch` = full.`epoch`
                ",
                TABLE_USER, epoch_grouping, TABLE_USER, filter
            );

            let out = if params_map.is_empty() {
                let _t = conn.query_iter(select_statement).await;
                self.check_for_infra_error(_t)?
                    .reduce_and_drop(vec![], |mut acc, mut row: mysql_async::Row| {
                        if let (Some(Ok(username)), Some(Ok(version)), Some(Ok(data))) =
                            (row.take_opt(0), row.take_opt(1), row.take_opt(2))
                        {
                            acc.push((AkdLabel(username), (version, AkdValue(data))))
                        }
                        acc
                    })
                    .await?
            } else {
                let _t = conn
                    .exec_iter(select_statement, mysql_async::Params::from(params_map))
                    .await;
                self.check_for_infra_error(_t)?
                    .reduce_and_drop(vec![], |mut acc, mut row: mysql_async::Row| {
                        if let (Some(Ok(username)), Some(Ok(version)), Some(Ok(data))) =
                            (row.take_opt(0), row.take_opt(1), row.take_opt(2))
                        {
                            acc.push((AkdLabel(username), (version, AkdValue(data))))
                        }
                        acc
                    })
                    .await?
            };

            debug!(
                "Retrieved {} records for {} users in query\nDropping search table...",
                out.len(),
                keys.len()
            );

            let nout = conn.query_drop("DROP TEMPORARY TABLE `search_users`").await;
            self.check_for_infra_error(nout)?;

            let toc = Instant::now() - tic;
            *(self.time_read.write().await) += toc;

            for item in out.into_iter() {
                results.insert(item.0, item.1);
            }

            Ok::<(), MySqlError>(())
        };
        debug!("END MySQL get user states");
        match result.await {
            Ok(()) => Ok(results),
            Err(error) => {
                error!("MySQL error {}", error);
                Err(StorageError::Other(format!("MySQL Error {}", error)))
            }
        }
    }
}
