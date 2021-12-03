// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements operations for a simple asynchronized mysql database

use akd::errors::StorageError;
use akd::node_state::NodeLabel;
use akd::storage::types::{
    AkdKey, DbRecord, KeyData, StorageType, ValueState, ValueStateRetrievalFlag,
};
use akd::storage::{Storable, Storage};
use akd::ARITY;
type LocalTransaction = akd::storage::transaction::Transaction;
use async_trait::async_trait;
use log::{debug, error, info, trace, warn};
use mysql_async::prelude::*;
use mysql_async::*;

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

type MySqlError = mysql_async::error::Error;

use akd::storage::timed_cache::*;

const TABLE_AZKS: &str = "azks";
const TABLE_HISTORY_TREE_NODES: &str = "history";
const TABLE_HISTORY_NODE_STATES: &str = "states";
const TABLE_USER: &str = "users";
const TEMP_IDS_TABLE: &str = "temp_ids_table";

const MAXIMUM_SQL_TIER_CONNECTION_TIMEOUT_SECS: u64 = 300;
const SQL_RECONNECTION_DELAY_SECS: u64 = 5;

const SELECT_AZKS_DATA: &str = "`root`, `epoch`, `num_nodes`";
const SELECT_HISTORY_TREE_NODE_DATA: &str =
    "`location`, `label_len`, `label_val`, `epochs`, `parent`, `node_type`";
const SELECT_HISTORY_NODE_STATE_DATA: &str =
    "`label_len`, `label_val`, `epoch`, `value`, `child_states`";
const SELECT_USER_DATA: &str =
    "`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`";

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
    num_writes: Arc<tokio::sync::RwLock<u64>>,
    time_read: Arc<tokio::sync::RwLock<Duration>>,
    time_write: Arc<tokio::sync::RwLock<Duration>>,

    tunable_insert_depth: usize,
}

impl std::fmt::Display for AsyncMySqlDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let db_str = match self.opts.get_db_name() {
            Some(db) => format!("Database {}", db),
            None => String::from(""),
        };
        let user_str = match self.opts.get_user() {
            Some(user) => format!(", User {}", user),
            None => String::from(""),
        };

        write!(
            f,
            "Connected to {}:{} ({}{})",
            self.opts.get_ip_or_hostname(),
            self.opts.get_tcp_port(),
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
            num_writes: self.num_writes.clone(),
            time_read: self.time_read.clone(),
            time_write: self.time_write.clone(),

            tunable_insert_depth: self.tunable_insert_depth,
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
        cache_options: MySqlCacheOptions,
        depth: usize,
    ) -> Self {
        let dport = port.unwrap_or(3306u16);
        let mut builder = OptsBuilder::new();
        builder
            .ip_or_hostname(endpoint)
            .db_name(Option::from(database))
            .user(user)
            .pass(password)
            .tcp_port(dport);
        let opts: Opts = builder.into();

        #[allow(clippy::mutex_atomic)]
        let healthy = Arc::new(tokio::sync::RwLock::new(false));
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
            num_writes: Arc::new(tokio::sync::RwLock::new(0)),
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
                    MySqlError::Other(_) | MySqlError::Url(_) | MySqlError::Tls(_) => false,

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

    async fn get_connection(&self) -> Result<mysql_async::Conn, MySqlError> {
        let connection = {
            if self.is_healthy().await {
                let connection_pool_guard = self.pool.read().await;
                (*connection_pool_guard).get_conn().await?
            } else {
                // Connection pool is currently unhealthy and queries are
                // disallowed. Connection pool is being async refreshed in
                // background and will soon become healthy, so no action required

                // fail the connection
                return Err(MySqlError::Driver(
                    mysql_async::error::DriverError::PoolDisconnected,
                ));
            }
        };

        // Ensure we are running in TRADITIONAL mysql mode. TRADITIONAL mysql
        // converts many warnings to errors, for example it will reject too
        // large blob entries instead of truncating them with a warning.
        // This is essential for our system, since SEE relies on all data in our
        // XDB being exactly what it wrote.
        let connection = connection
            .drop_query("SET SESSION sql_mode = 'TRADITIONAL'")
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
            let ip = opts.get_ip_or_hostname();
            let pool_options = opts.clone();
            let pool = Pool::new(pool_options);
            let conn = pool.get_conn().await;

            if let Ok(_conn) = conn {
                if let Ok(()) = Self::setup_database(_conn).await {
                    // set the healthy flag to true
                    let mut is_healthy_guard = is_healthy.write().await;
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

            warn!(
                "Failed {:?} reconnection attempt(s) to MySQL database. Will retry in {} seconds",
                attempts, SQL_RECONNECTION_DELAY_SECS
            );

            tokio::time::delay_for(tokio::time::Duration::from_secs(
                // TOKIO 0.2.X
                //tokio::time::sleep(tokio::time::Duration::from_secs( // TOKIO 1.X
                SQL_RECONNECTION_DELAY_SECS,
            ))
            .await;

            attempts += 1
        }
    }

    async fn setup_database(conn: mysql_async::Conn) -> core::result::Result<(), MySqlError> {
        let mut tx: mysql_async::Transaction<mysql_async::Conn> = conn
            .start_transaction(TransactionOptions::default())
            .await?;
        // AZKS table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE_AZKS
            + "` (`key` SMALLINT UNSIGNED NOT NULL, `root` BIGINT UNSIGNED NOT NULL,"
            + " `epoch` BIGINT UNSIGNED NOT NULL, `num_nodes` BIGINT UNSIGNED NOT NULL,"
            + " PRIMARY KEY (`key`))";
        tx = tx.drop_query(command).await?;

        // History tree nodes table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE_HISTORY_TREE_NODES
            + "` (`location` BIGINT UNSIGNED NOT NULL, `label_len` INT UNSIGNED NOT NULL,"
            + " `label_val` BIGINT UNSIGNED NOT NULL, `epochs` VARBINARY(2000),"
            + " `parent` BIGINT UNSIGNED NOT NULL, `node_type` SMALLINT UNSIGNED NOT NULL,"
            + " PRIMARY KEY (`location`))";
        tx = tx.drop_query(command).await?;

        // History node states table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE_HISTORY_NODE_STATES
            + "` (`label_len` INT UNSIGNED NOT NULL, `label_val` BIGINT UNSIGNED NOT NULL, "
            + " `epoch` BIGINT UNSIGNED NOT NULL, `value` VARBINARY(2000), `child_states` VARBINARY(2000),"
            + " PRIMARY KEY (`label_len`, `label_val`, `epoch`))";
        tx = tx.drop_query(command).await?;

        // User data table
        let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
            + TABLE_USER
            + "` (`username` VARCHAR(256) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, `version` BIGINT UNSIGNED NOT NULL,"
            + " `node_label_val` BIGINT UNSIGNED NOT NULL, `node_label_len` INT UNSIGNED NOT NULL, `data` VARCHAR(2000),"
            + " PRIMARY KEY(`username`, `epoch`))";
        tx = tx.drop_query(command).await?;

        // if we got here, we're good to commit. Transaction's will auto-rollback when memory freed if commit wasn't done.
        tx.commit().await?;
        Ok(())
    }

    /// Delete all the data in the tables
    pub async fn delete_data(&self) -> core::result::Result<(), MySqlError> {
        let conn = self.get_connection().await?;
        let mut tx = conn
            .start_transaction(TransactionOptions::default())
            .await?;

        let command = "DELETE FROM `".to_owned() + TABLE_AZKS + "`";
        tx = tx.drop_query(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_USER + "`";
        tx = tx.drop_query(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_HISTORY_NODE_STATES + "`";
        tx = tx.drop_query(command).await?;

        let command = "DELETE FROM `".to_owned() + TABLE_HISTORY_TREE_NODES + "`";
        tx = tx.drop_query(command).await?;

        tx.commit().await?;

        Ok(())
    }

    /// Storage a record in the data layer
    async fn internal_set(
        &self,
        record: DbRecord,
        trans: Option<mysql_async::Transaction<mysql_async::Conn>>,
    ) -> core::result::Result<Option<mysql_async::Transaction<mysql_async::Conn>>, MySqlError> {
        *(self.num_writes.write().await) += 1;

        debug!("BEGIN MySQL set");
        let tic = Instant::now();

        let statement_text = record.set_statement();
        let (ntx, out) = match trans {
            Some(tx) => match tx.drop_exec(statement_text, record.set_params()).await {
                Err(err) => (None, Err(err)),
                Ok(next_tx) => (Some(next_tx), Ok(())),
            },
            None => {
                let conn = self.get_connection().await?;
                if let Err(err) = conn.drop_exec(statement_text, record.set_params()).await {
                    (None, Err(err))
                } else {
                    (None, Ok(()))
                }
            }
        };
        self.check_for_infra_error(out)?;
        let toc = Instant::now() - tic;
        *(self.time_write.write().await) += toc;

        debug!("END MySQL set");
        Ok(ntx)
    }

    /// NOTE: This is assuming all of the DB records have been narrowed down to a single record type!
    async fn internal_batch_set(
        &self,
        records: Vec<DbRecord>,
        trans: mysql_async::Transaction<mysql_async::Conn>,
    ) -> core::result::Result<mysql_async::Transaction<mysql_async::Conn>, MySqlError> {
        if records.is_empty() {
            return Ok(trans);
        }

        *(self.num_writes.write().await) += records.len() as u64;
        let mut mini_tx = trans;

        debug!("BEGIN Computing mysql parameters");
        #[allow(clippy::needless_collect)]
        let chunked = records
            .chunks(self.tunable_insert_depth)
            .map(|batch| {
                if batch.is_empty() {
                    BatchMode::None
                } else if batch.len() < self.tunable_insert_depth {
                    BatchMode::Partial(DbRecord::set_batch_params(batch), batch.len())
                } else {
                    BatchMode::Full(DbRecord::set_batch_params(batch))
                }
            })
            .collect::<Vec<_>>();
        debug!("END Computing mysql parameters");

        debug!("BEGIN MySQL set batch");
        let head = &records[0];
        let statement = |i: usize| -> String {
            match &head {
                DbRecord::Azks(_) => DbRecord::set_batch_statement::<akd::append_only_zks::Azks>(i),
                DbRecord::HistoryNodeState(_) => {
                    DbRecord::set_batch_statement::<akd::node_state::HistoryNodeState>(i)
                }
                DbRecord::HistoryTreeNode(_) => {
                    DbRecord::set_batch_statement::<akd::history_tree_node::HistoryTreeNode>(i)
                }
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
            let mut prepped = mini_tx.prepare(fill_statement).await?;
            let out = prepped.batch(params).await;
            prepped = self.check_for_infra_error(out)?;
            mini_tx = prepped.close().await?;
        }

        // insert the remainder as a final statement
        if let Some((remainder, count)) = fallout {
            debug!("MySQL batch - remainder {} insert", count);
            let remainder_stmt = statement(count);
            let out = mini_tx.drop_exec(remainder_stmt, remainder).await;
            mini_tx = self.check_for_infra_error(out)?;
        }

        let toc = Instant::now() - tic;
        *(self.time_write.write().await) += toc;
        debug!("END MySQL set batch");
        Ok(mini_tx)
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
        let mut builder = OptsBuilder::new();
        builder
            .ip_or_hostname(endpoint)
            .user(user)
            .pass(password)
            .tcp_port(dport);
        let opts: Opts = builder.into();
        let conn = Conn::new(opts).await?;
        conn.drop_query(r"CREATE DATABASE IF NOT EXISTS test_db")
            .await?;

        Ok(())
    }

    /// Cleanup the test data table
    #[allow(dead_code)]
    pub async fn test_cleanup(&self) -> core::result::Result<(), MySqlError> {
        let conn = self.get_connection().await?;
        let mut tx = conn
            .start_transaction(TransactionOptions::default())
            .await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_AZKS + "`";
        tx = tx.drop_query(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_USER + "`";
        tx = tx.drop_query(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_HISTORY_NODE_STATES + "`";
        tx = tx.drop_query(command).await?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE_HISTORY_TREE_NODES + "`";
        tx = tx.drop_query(command).await?;

        tx.commit().await?;

        Ok(())
    }

    /// Determine if the MySQL environment is available for execution (i.e. docker container is running)
    #[allow(dead_code)]
    pub fn test_guard() -> bool {
        let output = Command::new("/usr/local/bin/docker")
            .args(["container", "ls", "-f", "name=akd-test-db"])
            .output();
        match &output {
            Ok(result) => {
                if let (Ok(out), Ok(err)) = (std::str::from_utf8(&result.stdout), std::str::from_utf8(&result.stderr)) {
                    info!("Docker ls output\nSTDOUT: {}\nSTDERR: {}", out, err);
                }
            },
            Err(err) => warn!("Docker ls returned error: {:?}", err),
        }

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
                    error!("Error executing docker command: {}", error_message);
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
    async fn log_metrics(&self, level: log::Level) {
        if let Some(cache) = &self.cache {
            cache.log_metrics(level).await
        }

        self.trans.log_metrics(level).await;

        let mut tree_size = "Tree size: Query err".to_string();
        let mut node_state_size = "Node state count: Query err".to_string();
        let mut value_state_size = "Value state count: Query err".to_string();
        if let Ok(conn) = self.get_connection().await {
            let query_text = format!("SELECT COUNT(`location`) FROM {}", TABLE_HISTORY_TREE_NODES);
            if let Ok(results) = conn.query(query_text).await {
                if let Ok((conn2, mapped)) = results
                    .map_and_drop(|row| {
                        let count: u64 = mysql_async::from_row(row);
                        count
                    })
                    .await
                {
                    if let Some(count) = mapped.first() {
                        tree_size = format!("Tree size: {}", count);
                    }

                    let query_text =
                        format!("SELECT COUNT(`epoch`) FROM {}", TABLE_HISTORY_NODE_STATES);
                    if let Ok(results) = conn2.query(query_text).await {
                        if let Ok((conn3, mapped)) = results
                            .map_and_drop(|row| {
                                let count: u64 = mysql_async::from_row(row);
                                count
                            })
                            .await
                        {
                            if let Some(count) = mapped.first() {
                                node_state_size = format!("Node state count: {}", count);
                            }

                            let query_text = format!("SELECT COUNT(`epoch`) FROM {}", TABLE_USER);
                            if let Ok(results) = conn3.query(query_text).await {
                                if let Ok((_, mapped)) = results
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
            }
        }

        let mut r = self.num_reads.write().await;
        let mut w = self.num_writes.write().await;
        let mut tr = self.time_read.write().await;
        let mut tw = self.time_write.write().await;

        let msg = format!(
            "MySQL writes: {}, MySQL reads: {}, Time read: {} s, Time write: {} s\n\t{}\n\t{}\n\t{}",
            *w,
            *r,
            (*tr).as_secs_f64(),
            (*tw).as_secs_f64(),
            tree_size,
            node_state_size,
            value_state_size,
        );

        *r = 0;
        *w = 0;
        *tr = Duration::from_millis(0);
        *tw = Duration::from_millis(0);

        match level {
            log::Level::Trace => trace!("{}", msg),
            log::Level::Debug => debug!("{}", msg),
            log::Level::Info => info!("{}", msg),
            log::Level::Warn => warn!("{}", msg),
            _ => error!("{}", msg),
        }
    }

    /// Start a transaction in the storage layer
    async fn begin_transaction(&mut self) -> bool {
        // disable the cache cleaning since we're in a write transaction
        // and will want to keep cache'd objects for the life of the transaction
        if let Some(cache) = &self.cache {
            cache.disable_clean().await;
        }

        self.trans.begin_transaction().await
    }

    /// Commit a transaction in the storage layer
    async fn commit_transaction(&mut self) -> Result<(), StorageError> {
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
    async fn rollback_transaction(&mut self) -> Result<(), StorageError> {
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
            Err(error) => Err(StorageError::SetError(error.to_string())),
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
                DbRecord::HistoryNodeState(_) => groups
                    .entry(StorageType::HistoryNodeState)
                    .or_insert_with(Vec::new)
                    .push(record),
                DbRecord::HistoryTreeNode(_) => groups
                    .entry(StorageType::HistoryTreeNode)
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
            let conn = self.get_connection().await?;
            let mut tx: Transaction<_> = conn
                .start_transaction(TransactionOptions::default())
                .await?;
            // go through each group which is narrowed to a single type
            // applying the changes on the transaction
            tx = tx.drop_query("SET autocommit=0").await?;
            tx = tx.drop_query("SET unique_checks=0").await?;
            tx = tx.drop_query("SET foreign_key_checks=0").await?;

            for (_key, mut value) in groups.into_iter() {
                if !value.is_empty() {
                    // Sort the records to match db-layer sorting which will help with insert performance
                    value.sort_by(|a, b| match &a {
                        DbRecord::HistoryNodeState(state) => {
                            if let DbRecord::HistoryNodeState(state2) = &b {
                                state.key.cmp(&state2.key)
                            } else {
                                Ordering::Equal
                            }
                        }
                        DbRecord::HistoryTreeNode(node) => {
                            if let DbRecord::HistoryTreeNode(node2) = &b {
                                node.location.cmp(&node2.location)
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

            tx = tx.drop_query("SET autocommit=1").await?;
            tx = tx.drop_query("SET unique_checks=1").await?;
            tx = tx.drop_query("SET foreign_key_checks=1").await?;

            tx.commit().await?;
            Ok::<(), MySqlError>(())
        };
        match result.await {
            Ok(_) => Ok(()),
            Err(error) => Err(StorageError::SetError(error.to_string())),
        }
    }

    /// Retrieve a stored record from the data layer
    async fn get<St: Storable>(&self, id: St::Key) -> core::result::Result<DbRecord, StorageError> {
        // we're in a transaction, meaning the object _might_ be newer and therefore we should try and read if from the transaction
        // log instead of the raw storage layer
        if self.is_transaction_active().await {
            if let Some(result) = self.trans.get::<St>(&id).await {
                return Ok(result);
            }
        }

        // check for a cache hit
        if let Some(cache) = &self.cache {
            if let Some(result) = cache.hit_test::<St>(&id).await {
                return Ok(result);
            }
        }

        // cache miss, log a real sql read op
        *(self.num_reads.write().await) += 1;

        debug!("BEGIN MySQL get {:?}", id);
        let result = async {
            let tic = Instant::now();

            let conn = self.get_connection().await?;
            let statement = DbRecord::get_specific_statement::<St>();
            let params = DbRecord::get_specific_params::<St>(&id);
            let out = match params {
                Some(p) => match conn.first_exec(statement, p).await {
                    Err(err) => Err(err),
                    Ok((_, result)) => Ok(result),
                },
                None => match conn.first(statement).await {
                    Err(err) => Err(err),
                    Ok((_, result)) => Ok(result),
                },
            };

            let toc = Instant::now() - tic;
            *(self.time_read.write().await) += toc;

            let result = self.check_for_infra_error(out)?;
            if let Some(mut row) = result {
                let record = DbRecord::from_row::<St>(&mut row)?;
                if let Some(cache) = &self.cache {
                    cache.put(&record).await;
                }
                // return
                return Ok::<Option<DbRecord>, MySqlError>(Some(record));
            }
            Ok::<Option<DbRecord>, MySqlError>(None)
        };

        debug!("END MySQL get");
        match result.await {
            Ok(Some(r)) => Ok(r),
            Ok(None) => Err(StorageError::GetError("Not found".to_string())),
            Err(error) => Err(StorageError::GetError(error.to_string())),
        }
    }

    /// Retrieve a batch of records by id
    async fn batch_get<St: Storable>(
        &self,
        ids: Vec<St::Key>,
    ) -> Result<Vec<DbRecord>, StorageError> {
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

                let results =
                    if let Some(create_table_cmd) = DbRecord::get_batch_create_temp_table::<St>() {
                        // Create the temp table of ids
                        let out = conn.drop_query(create_table_cmd).await;
                        conn = self.check_for_infra_error(out)?;

                        // Fill temp table with the requested ids
                        let mut tx = conn
                            .start_transaction(TransactionOptions::default())
                            .await?;
                        tx = tx.drop_query("SET autocommit=0").await?;
                        tx = tx.drop_query("SET unique_checks=0").await?;
                        tx = tx.drop_query("SET foreign_key_checks=0").await?;

                        let mut fallout: Option<Vec<_>> = None;
                        let mut params = vec![];
                        for batch in key_set_vec.chunks(self.tunable_insert_depth) {
                            if batch.len() < self.tunable_insert_depth {
                                fallout = Some(batch.to_vec());
                            } else {
                                params.push(
                                    DbRecord::get_multi_row_specific_params::<St>(batch).unwrap(),
                                );
                            }
                        }

                        // insert the batches of size = MYSQL_EXTENDED_INSERT_DEPTH
                        if !params.is_empty() {
                            let fill_statement = DbRecord::get_batch_fill_temp_table::<St>(Some(
                                self.tunable_insert_depth,
                            ));
                            let mut prepped = tx.prepare(fill_statement).await?;
                            let out = prepped.batch(params).await;
                            prepped = self.check_for_infra_error(out)?;
                            tx = prepped.close().await?;
                        }

                        // insert the remainder as a final statement
                        if let Some(remainder) = fallout {
                            let remainder_stmt =
                                DbRecord::get_batch_fill_temp_table::<St>(Some(remainder.len()));
                            let params_batch =
                                DbRecord::get_multi_row_specific_params::<St>(&remainder).unwrap();
                            let out = tx.drop_exec(remainder_stmt, params_batch).await;
                            tx = self.check_for_infra_error(out)?;
                        }

                        tx = tx.drop_query("SET autocommit=1").await?;
                        tx = tx.drop_query("SET unique_checks=1").await?;
                        tx = tx.drop_query("SET foreign_key_checks=1").await?;
                        conn = tx.commit().await?;

                        // Query the records which intersect (INNER JOIN) with the temp table of ids
                        let query = DbRecord::get_batch_statement::<St>();
                        let out = conn.query(query).await;
                        let result = self.check_for_infra_error(out)?;

                        let (nconn, out) = result
                            .reduce_and_drop(vec![], |mut acc, mut row| {
                                if let Ok(result) = DbRecord::from_row::<St>(&mut row) {
                                    acc.push(result);
                                }
                                acc
                            })
                            .await?;

                        // drop the temp table of ids
                        let t_out = nconn
                            .drop_query(format!("DROP TEMPORARY TABLE `{}`", TEMP_IDS_TABLE))
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

                Ok::<Vec<DbRecord>, mysql_async::error::Error>(results)
            };

            *(self.num_reads.write().await) += 1;

            match result.await {
                Ok(result_vec) => {
                    for item in result_vec.into_iter() {
                        map.push(item);
                    }
                }
                Err(error) => return Err(StorageError::GetError(error.to_string())),
            }
        }
        Ok(map)
    }

    async fn get_user_data(
        &self,
        username: &AkdKey,
    ) -> core::result::Result<KeyData, StorageError> {
        // This is the same as previous logic under "get_all"

        *(self.num_reads.write().await) += 1;
        // DO NOT log the user info, it's PII in the future
        debug!("BEGIN MySQL get user data");
        let result = async {
            let tic = Instant::now();

            let conn = self.get_connection().await?;
            let statement_text =
                "SELECT `username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                    .to_owned()
                    + TABLE_USER
                    + "` WHERE `username` = :the_user";
            let prepped = conn.prepare(statement_text).await?;
            let result = prepped
                .execute(params! { "the_user" => username.0.clone() })
                .await?;
            let out = result
                .map(|mut row| {
                    let (username, epoch, version, node_label_val, node_label_len, data) = (
                        row.take(0),
                        row.take(1),
                        row.take(2),
                        row.take(3),
                        row.take(4),
                        row.take(5),
                    );

                    ValueState {
                        epoch: epoch.unwrap(),
                        version: version.unwrap(),
                        label: NodeLabel {
                            val: node_label_val.unwrap(),
                            len: node_label_len.unwrap(),
                        },
                        plaintext_val: akd::storage::types::Values(data.unwrap()),
                        username: akd::storage::types::AkdKey(username.unwrap()),
                    }
                })
                .await;

            let toc = Instant::now() - tic;
            *(self.time_read.write().await) += toc;
            let (_, selected_records) = self.check_for_infra_error(out)?;
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
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }

    async fn get_user_state(
        &self,
        username: &AkdKey,
        flag: ValueStateRetrievalFlag,
    ) -> core::result::Result<ValueState, StorageError> {
        *(self.num_reads.write().await) += 1;

        debug!("BEGIN MySQL get user state (flag {:?})", flag);
        let result = async {
            let tic = Instant::now();

            let conn = self.get_connection().await?;
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
                    statement_text += " AND `epoch` <= :the_epoch";
                }
            }

            // add limit to retrieve only 1 record
            statement_text += " LIMIT 1";
            let prepped = conn.prepare(statement_text).await?;
            let out = prepped
                .execute(mysql_async::Params::from(params_map))
                .await?
                .map(|mut row| {
                    let (username, epoch, version, node_label_val, node_label_len, data) = (
                        row.take(0),
                        row.take(1),
                        row.take(2),
                        row.take(3),
                        row.take(4),
                        row.take(5),
                    );
                    ValueState {
                        epoch: epoch.unwrap(),
                        version: version.unwrap(),
                        label: NodeLabel {
                            val: node_label_val.unwrap(),
                            len: node_label_len.unwrap(),
                        },
                        plaintext_val: akd::storage::types::Values(data.unwrap()),
                        username: akd::storage::types::AkdKey(username.unwrap()),
                    }
                })
                .await;

            let toc = Instant::now() - tic;
            *(self.time_read.write().await) += toc;
            let (_, selected_record) = self.check_for_infra_error(out)?;

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
            Ok(None) => Err(StorageError::GetError(String::from("Not found"))),
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }

    async fn get_user_state_versions(
        &self,
        keys: &[AkdKey],
        flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdKey, u64>, StorageError> {
        *(self.num_reads.write().await) += 1;

        let mut results = HashMap::new();

        debug!("BEGIN MySQL get user state versions (flag {:?})", flag);
        let result = async {
            let tic = Instant::now();

            let mut conn = self.get_connection().await?;

            debug!("Creating the temporary search username's table");
            let out = conn
                .drop_query(
                    "CREATE TEMPORARY TABLE `search_users`(`username` VARCHAR(256) NOT NULL, PRIMARY KEY (`username`))",
                )
                .await;
            conn = self.check_for_infra_error(out)?;

            debug!(
                "Inserting the query users into the temporary table in batches of {}",
                self.tunable_insert_depth
            );

            let mut tx = conn
                .start_transaction(TransactionOptions::default())
                .await?;
            tx = tx.drop_query("SET autocommit=0").await?;
            tx = tx.drop_query("SET unique_checks=0").await?;
            tx = tx.drop_query("SET foreign_key_checks=0").await?;

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
                let mut prep = tx.prepare(statement).await?;
                let out = prep.batch(params).await;
                prep = self.check_for_infra_error(out)?;
                tx = prep.close().await?;
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
                let out = tx.drop_exec(remainder_stmt, params_batch).await;
                tx = self.check_for_infra_error(out)?;
            }

            // re-enable all the checks
            tx = tx.drop_query("SET autocommit=1").await?;
            tx = tx.drop_query("SET unique_checks=1").await?;
            tx = tx.drop_query("SET foreign_key_checks=1").await?;

            // commit the transaction
            conn = tx.commit().await?;

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
                r"SELECT full.`username`, full.`version`
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

            let (nconn, out) = if params_map.is_empty() {
                let _t = conn.query(select_statement).await;
                self.check_for_infra_error(_t)?
                    .reduce_and_drop(vec![], |mut acc, mut row| {
                        if let (Some(Ok(username)), Some(Ok(version))) =
                            (row.take_opt(0), row.take_opt(1))
                        {
                            acc.push((AkdKey(username), version))
                        }
                        acc
                    })
                    .await?
            } else {
                let _t = conn
                    .prep_exec(select_statement, mysql_async::Params::from(params_map))
                    .await;
                self.check_for_infra_error(_t)?
                    .reduce_and_drop(vec![], |mut acc, mut row| {
                        if let (Some(Ok(username)), Some(Ok(version))) =
                            (row.take_opt(0), row.take_opt(1))
                        {
                            acc.push((AkdKey(username), version))
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

            let nout = nconn
                .drop_query("DROP TEMPORARY TABLE `search_users`")
                .await;
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
            Err(code) => Err(StorageError::GetError(code.to_string())),
        }
    }
}

/* Generic data structure handling for MySQL */

trait MySqlStorable {
    fn set_statement(&self) -> String;

    fn set_params(&self) -> mysql_async::Params;

    fn set_batch_statement<St: Storable>(items: usize) -> String;

    fn set_batch_params(items: &[DbRecord]) -> mysql_async::Params;

    fn get_statement<St: Storable>() -> String;

    fn get_batch_create_temp_table<St: Storable>() -> Option<String>;

    fn get_batch_fill_temp_table<St: Storable>(num_items: Option<usize>) -> String;

    fn get_batch_statement<St: Storable>() -> String;

    fn get_specific_statement<St: Storable>() -> String;

    fn get_specific_params<St: Storable>(key: &St::Key) -> Option<mysql_async::Params>;

    fn get_multi_row_specific_params<St: Storable>(keys: &[St::Key])
        -> Option<mysql_async::Params>;

    fn from_row<St: Storable>(row: &mut mysql_async::Row) -> core::result::Result<Self, MySqlError>
    where
        Self: std::marker::Sized;

    fn serialize_epochs(epochs: &[u64]) -> Vec<u8>;
    fn deserialize_epochs(bin: &[u8]) -> Option<Vec<u64>>;
}

impl MySqlStorable for DbRecord {
    fn set_statement(&self) -> String {
        match &self {
            DbRecord::Azks(_) => format!("INSERT INTO `{}` (`key`, {}) VALUES (:key, :root, :epoch, :num_nodes) ON DUPLICATE KEY UPDATE `root` = :root, `epoch` = :epoch, `num_nodes` = :num_nodes", TABLE_AZKS, SELECT_AZKS_DATA),
            DbRecord::HistoryNodeState(_) => format!("INSERT INTO `{}` ({}) VALUES (:label_len, :label_val, :epoch, :value, :child_states) ON DUPLICATE KEY UPDATE `value` = :value, `child_states` = :child_states", TABLE_HISTORY_NODE_STATES, SELECT_HISTORY_NODE_STATE_DATA),
            DbRecord::HistoryTreeNode(_) => format!("INSERT INTO `{}` ({}) VALUES (:location, :label_len, :label_val, :epochs, :parent, :node_type) ON DUPLICATE KEY UPDATE `label_len` = :label_len, `label_val` = :label_val, `epochs` = :epochs, `parent` = :parent, `node_type` = :node_type", TABLE_HISTORY_TREE_NODES, SELECT_HISTORY_TREE_NODE_DATA),
            DbRecord::ValueState(_) => format!("INSERT INTO `{}` ({}) VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)", TABLE_USER, SELECT_USER_DATA),
        }
    }

    fn set_params(&self) -> mysql_async::Params {
        match &self {
            DbRecord::Azks(azks) => mysql_async::Params::from(
                params! { "key" => 1u8, "root" => azks.root, "epoch" => azks.latest_epoch, "num_nodes" => azks.num_nodes },
            ),
            DbRecord::HistoryNodeState(state) => {
                let bin_data = bincode::serialize(&state.child_states).unwrap();
                let id = state.get_id();
                mysql_async::Params::from(
                    params! { "label_len" => id.0.len, "label_val" => id.0.val, "epoch" => id.1, "value" => state.value.clone(), "child_states" => bin_data },
                )
            }
            DbRecord::HistoryTreeNode(node) => {
                let bin_data = DbRecord::serialize_epochs(&node.epochs);
                mysql_async::Params::from(
                    params! { "location" => node.location, "label_len" => node.label.len, "label_val" => node.label.val, "epochs" => bin_data, "parent" => node.parent, "node_type" => node.node_type as u8 },
                )
            }
            DbRecord::ValueState(state) => mysql_async::Params::from(
                params! { "username" => state.get_id().0, "epoch" => state.epoch, "version" => state.version, "node_label_len" => state.label.len, "node_label_val" => state.label.val, "data" => state.plaintext_val.0.clone()},
            ),
        }
    }

    fn set_batch_statement<St: Storable>(items: usize) -> String {
        let mut parts = "".to_string();
        for i in 0..items {
            match St::data_type() {
                StorageType::HistoryNodeState => {
                    parts = format!(
                        "{}(:label_len{}, :label_val{}, :epoch{}, :value{}, :child_states{})",
                        parts, i, i, i, i, i
                    );
                }
                StorageType::HistoryTreeNode => {
                    parts = format!("{}(:location{}, :label_len{}, :label_val{}, :epochs{}, :parent{}, :node_type{})", parts, i, i, i, i, i, i);
                }
                StorageType::ValueState => {
                    parts = format!("{}(:username{}, :epoch{}, :version{}, :node_label_val{}, :node_label_len{}, :data{})", parts, i, i, i, i, i, i);
                }
                _ => {
                    // azks
                }
            }

            if i < items - 1 {
                parts += ", ";
            }
        }

        match St::data_type() {
            StorageType::Azks => format!("INSERT INTO `{}` (`key`, {}) VALUES (:key, :root, :epoch, :num_nodes) as new ON DUPLICATE KEY UPDATE `root` = new.root, `epoch` = new.epoch, `num_nodes` = new.num_nodes", TABLE_AZKS, SELECT_AZKS_DATA),
            StorageType::HistoryNodeState => format!("INSERT INTO `{}` ({}) VALUES {} as new ON DUPLICATE KEY UPDATE `value` = new.value, `child_states` = new.child_states", TABLE_HISTORY_NODE_STATES, SELECT_HISTORY_NODE_STATE_DATA, parts),
            StorageType::HistoryTreeNode => format!("INSERT INTO `{}` ({}) VALUES {} as new ON DUPLICATE KEY UPDATE `label_len` = new.label_len, `label_val` = new.label_val, `epochs` = new.epochs, `parent` = new.parent, `node_type` = new.node_type", TABLE_HISTORY_TREE_NODES, SELECT_HISTORY_TREE_NODE_DATA, parts),
            StorageType::ValueState => format!("INSERT INTO `{}` ({}) VALUES {}", TABLE_USER, SELECT_USER_DATA, parts),
        }
    }

    fn set_batch_params(items: &[DbRecord]) -> mysql_async::Params {
        let param_batch = items
            .iter()
            .enumerate()
            .map(|(idx, item)| match &item {
                DbRecord::Azks(azks) => {
                    vec![
                        ("key".to_string(), Value::from(1u8)),
                        ("root".to_string(), Value::from(azks.root)),
                        ("epoch".to_string(), Value::from(azks.latest_epoch)),
                        ("num_nodes".to_string(), Value::from(azks.num_nodes)),
                    ]
                }
                DbRecord::HistoryNodeState(state) => {
                    let bin_data = bincode::serialize(&state.child_states).unwrap();
                    let id = state.get_id();
                    vec![
                        (format!("label_len{}", idx), Value::from(id.0.len)),
                        (format!("label_val{}", idx), Value::from(id.0.val)),
                        (format!("epoch{}", idx), Value::from(id.1)),
                        (format!("value{}", idx), Value::from(state.value.clone())),
                        (format!("child_states{}", idx), Value::from(bin_data)),
                    ]
                }
                DbRecord::HistoryTreeNode(node) => {
                    let bin_data = DbRecord::serialize_epochs(&node.epochs);
                    vec![
                        (format!("location{}", idx), Value::from(node.location)),
                        (format!("label_len{}", idx), Value::from(node.label.len)),
                        (format!("label_val{}", idx), Value::from(node.label.val)),
                        (format!("epochs{}", idx), Value::from(bin_data)),
                        (format!("parent{}", idx), Value::from(node.parent)),
                        (
                            format!("node_type{}", idx),
                            Value::from(node.node_type as u8),
                        ),
                    ]
                }
                DbRecord::ValueState(state) => {
                    vec![
                        (format!("username{}", idx), Value::from(state.get_id().0)),
                        (format!("epoch{}", idx), Value::from(state.epoch)),
                        (format!("version{}", idx), Value::from(state.version)),
                        (
                            format!("node_label_len{}", idx),
                            Value::from(state.label.len),
                        ),
                        (
                            format!("node_label_val{}", idx),
                            Value::from(state.label.val),
                        ),
                        (
                            format!("data{}", idx),
                            Value::from(state.plaintext_val.0.clone()),
                        ),
                    ]
                }
            })
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        mysql_async::Params::from(param_batch)
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
            StorageType::ValueState => format!("SELECT {} FROM `{}`", SELECT_USER_DATA, TABLE_USER),
        }
    }

    fn get_batch_create_temp_table<St: Storable>() -> Option<String> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::HistoryNodeState => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{}`(`label_len` INT UNSIGNED NOT NULL, `label_val` BIGINT UNSIGNED NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, PRIMARY KEY(`label_len`, `label_val`, `epoch`))",
                        TEMP_IDS_TABLE
                    )
                )
            },
            StorageType::HistoryTreeNode => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{}`(`location` BIGINT UNSIGNED NOT NULL, PRIMARY KEY(`location`))",
                        TEMP_IDS_TABLE
                    )
                )
            },
            StorageType::ValueState => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{}`(`username` VARCHAR(256) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, PRIMARY KEY(`username`, `epoch`))",
                        TEMP_IDS_TABLE
                    )
                )
            },
        }
    }

    fn get_batch_fill_temp_table<St: Storable>(num_items: Option<usize>) -> String {
        let mut statement = match St::data_type() {
            StorageType::Azks => "".to_string(),
            StorageType::HistoryNodeState => {
                format!(
                    "INSERT INTO `{}` (`label_len`, `label_val`, `epoch`) VALUES ",
                    TEMP_IDS_TABLE
                )
            }
            StorageType::HistoryTreeNode => {
                format!("INSERT INTO `{}` (`location`) VALUES ", TEMP_IDS_TABLE)
            }
            StorageType::ValueState => {
                format!(
                    "INSERT INTO `{}` (`username`, `epoch`) VALUES ",
                    TEMP_IDS_TABLE
                )
            }
        };
        if let Some(item_count) = num_items {
            for i in 0..item_count {
                let append = match St::data_type() {
                    StorageType::Azks => String::from(""),
                    StorageType::HistoryNodeState => {
                        format!("(:label_len{}, :label_val{}, :epoch{})", i, i, i)
                    }
                    StorageType::HistoryTreeNode => {
                        format!("(:location{})", i)
                    }
                    StorageType::ValueState => {
                        format!("(:username{}, :epoch{})", i, i)
                    }
                };
                statement = format!("{}{}", statement, append);

                if i < item_count - 1 {
                    // inner-item, append a comma
                    statement += ", ";
                }
            }
        } else {
            statement += match St::data_type() {
                StorageType::Azks => "",
                StorageType::HistoryNodeState => "(:label_len, :label_val, :epoch)",
                StorageType::HistoryTreeNode => "(:location)",
                StorageType::ValueState => "(:username, :epoch)",
            };
        }
        statement
    }

    fn get_batch_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => {
                format!("SELECT {} FROM `{}` LIMIT 1", SELECT_AZKS_DATA, TABLE_AZKS)
            }
            StorageType::HistoryNodeState => {
                format!(
                    "SELECT a.`label_len`, a.`label_val`, a.`epoch`, a.`value`, a.`child_states` FROM `{}` a INNER JOIN {} ids ON ids.`label_len` = a.`label_len` AND ids.`label_val` = a.`label_val` AND ids.`epoch` = a.`epoch`",
                    TABLE_HISTORY_NODE_STATES,
                    TEMP_IDS_TABLE
                )
            }
            StorageType::HistoryTreeNode => {
                format!(
                    "SELECT a.`location`, a.`label_len`, a.`label_val`, a.`epochs`, a.`parent`, a.`node_type` FROM `{}` a INNER JOIN {} ids ON ids.`location` = a.`location`",
                    TABLE_HISTORY_TREE_NODES,
                    TEMP_IDS_TABLE
                )
            }
            StorageType::ValueState => {
                format!(
                    "SELECT a.`username`, a.`epoch`, a.`version`, a.`node_label_val`, a.`node_label_len`, a.`data` FROM `{}` a INNER JOIN {} ids ON ids.`username` = a.`username` AND ids.`epoch` = a.`epoch`",
                    TABLE_USER,
                    TEMP_IDS_TABLE
                )
            }
        }
    }

    fn get_specific_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => format!("SELECT {} FROM `{}` LIMIT 1", SELECT_AZKS_DATA, TABLE_AZKS),
            StorageType::HistoryNodeState => format!("SELECT {} FROM `{}` WHERE `label_len` = :label_len AND `label_val` = :label_val AND `epoch` = :epoch", SELECT_HISTORY_NODE_STATE_DATA, TABLE_HISTORY_NODE_STATES),
            StorageType::HistoryTreeNode => format!("SELECT {} FROM `{}` WHERE `location` = :location", SELECT_HISTORY_TREE_NODE_DATA, TABLE_HISTORY_TREE_NODES),
            StorageType::ValueState => format!("SELECT {} FROM `{}` WHERE `username` = :username AND `epoch` = :epoch", SELECT_USER_DATA, TABLE_USER),
        }
    }

    fn get_multi_row_specific_params<St: Storable>(
        keys: &[St::Key],
    ) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::HistoryNodeState => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        let back: akd::node_state::NodeStateKey =
                            akd::node_state::HistoryNodeState::key_from_full_binary(&bin).unwrap();
                        vec![
                            (format!("label_len{}", idx), Value::from(back.0.len)),
                            (format!("label_val{}", idx), Value::from(back.0.val)),
                            (format!("epoch{}", idx), Value::from(back.1)),
                        ]
                    })
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                Some(mysql_async::Params::from(pvec))
            }
            StorageType::HistoryTreeNode => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        let back: akd::history_tree_node::NodeKey =
                            akd::history_tree_node::HistoryTreeNode::key_from_full_binary(&bin)
                                .unwrap();
                        (format!("location{}", idx), Value::from(back.0))
                    })
                    .collect::<Vec<_>>();
                Some(mysql_async::Params::from(pvec))
            }
            StorageType::ValueState => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        let back: akd::storage::types::ValueStateKey =
                            akd::storage::types::ValueState::key_from_full_binary(&bin).unwrap();
                        vec![
                            (format!("username{}", idx), Value::from(back.0.clone())),
                            (format!("epoch{}", idx), Value::from(back.1)),
                        ]
                    })
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                Some(mysql_async::Params::from(pvec))
            }
        }
    }

    fn get_specific_params<St: Storable>(key: &St::Key) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::HistoryNodeState => {
                let bin = St::get_full_binary_key_id(key);
                let back: akd::node_state::NodeStateKey =
                    akd::node_state::HistoryNodeState::key_from_full_binary(&bin).unwrap();
                Some(mysql_async::Params::from(params! {
                    "label_len" => back.0.len,
                    "label_val" => back.0.val,
                    "epoch" => back.1
                }))
            }
            StorageType::HistoryTreeNode => {
                let bin = St::get_full_binary_key_id(key);
                let back: akd::history_tree_node::NodeKey =
                    akd::history_tree_node::HistoryTreeNode::key_from_full_binary(&bin).unwrap();
                Some(mysql_async::Params::from(params! {
                    "location" => back.0
                }))
            }
            StorageType::ValueState => {
                let bin = St::get_full_binary_key_id(key);
                let back: akd::storage::types::ValueStateKey =
                    akd::storage::types::ValueState::key_from_full_binary(&bin).unwrap();
                Some(mysql_async::Params::from(params! {
                    "username" => back.0,
                    "epoch" => back.1
                }))
            }
        }
    }

    fn from_row<St: Storable>(row: &mut mysql_async::Row) -> core::result::Result<Self, MySqlError>
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
                    let child_states_decoded: [Option<akd::node_state::HistoryChildState>; ARITY] =
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
                    let bin_vec: Vec<u8> = epochs;
                    if let Some(decoded_epochs) = DbRecord::deserialize_epochs(&bin_vec) {
                        let node = AsyncMySqlDatabase::build_history_tree_node(
                            label_val,
                            label_len,
                            location,
                            decoded_epochs,
                            parent,
                            node_type,
                        );
                        return Ok(DbRecord::HistoryTreeNode(node));
                    } else {
                        return Err(MySqlError::from("Deserialization of epochs failed"));
                    }
                }
            }
            StorageType::ValueState => {
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
                    return Ok(DbRecord::ValueState(state));
                }
            }
        }
        // fallback
        let err = MySqlError::Driver(mysql_async::error::DriverError::FromRow { row: row.clone() });
        Err(err)
    }

    fn serialize_epochs(epochs: &[u64]) -> Vec<u8> {
        let mut results = vec![];
        for item in epochs {
            let bytes = (*item).to_be_bytes();
            results.extend_from_slice(&bytes);
        }
        results
    }

    fn deserialize_epochs(bin: &[u8]) -> Option<Vec<u64>> {
        if bin.len() % 8 == 0 {
            // modulo 8 means that we have proper length byte arrays which can be decoded into u64's
            let mut results = vec![];
            for chunk in bin.chunks(8) {
                let mut a: [u8; 8] = Default::default();
                a.copy_from_slice(chunk);
                results.push(u64::from_be_bytes(a));
            }
            Some(results)
        } else {
            None
        }
    }
}

trait StorageErrorWrappable<TErr> {
    fn as_get<T>(result: Result<T, TErr>) -> Result<T, StorageError>;
    fn as_set<T>(result: Result<T, TErr>) -> Result<T, StorageError>;
}

impl StorageErrorWrappable<MySqlError> for StorageError {
    fn as_get<T>(result: Result<T, MySqlError>) -> Result<T, Self> {
        match result {
            Ok(t) => Ok(t),
            Err(err) => Err(StorageError::GetError(err.to_string())),
        }
    }
    fn as_set<T>(result: Result<T, MySqlError>) -> Result<T, Self> {
        match result {
            Ok(t) => Ok(t),
            Err(err) => Err(StorageError::SetError(err.to_string())),
        }
    }
}
