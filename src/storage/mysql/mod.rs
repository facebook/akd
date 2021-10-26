// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use crate::node_state::NodeLabel;
use crate::storage::types::{UserData, UserState, UserStateRetrievalFlag, Username};
use crate::storage::Storage;
use mysql::prelude::*;
use mysql::*;
use std::process::Command;

const TABLE: &str = "data";
const USER_TABLE: &str = "user_data";

/*
    MySql documentation: https://docs.rs/mysql/21.0.2/mysql/
*/

pub(crate) struct MySqlDatabase {
    opts: Opts,
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

        let result = |options: Opts| -> core::result::Result<(), mysql::Error> {
            let pool = Pool::new(options)?;
            let mut conn = pool.get_conn()?;

            // main data table (for all tree nodes, etc)
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + TABLE
                + "` (`key` VARCHAR(64) NOT NULL, `value` VARBINARY(2000), PRIMARY KEY (`key`)"
                + ")";
            conn.query_drop(command)?;

            // user data table
            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + USER_TABLE
                + "` (`username` VARCHAR(64) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, `version` BIGINT UNSIGNED NOT NULL, `node_label_val` BIGINT UNSIGNED NOT NULL, `node_label_len` INT UNSIGNED NOT NULL, `data` VARCHAR(2000), PRIMARY KEY(`username`, `epoch`)"
                + ")";
            conn.query_drop(command)?;

            Ok(())
        };

        let _output = result(opts.clone());

        Self { opts }
    }

    /// Cleanup the test data table
    #[allow(dead_code)]
    pub(crate) fn test_cleanup(&self) -> core::result::Result<(), mysql::Error> {
        let options = self.opts.clone();
        let pool = Pool::new(options)?;
        let mut conn = pool.get_conn()?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + TABLE + "`";
        conn.query_drop(command)?;

        let command = "DROP TABLE IF EXISTS `".to_owned() + USER_TABLE + "`";
        conn.query_drop(command)?;

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

// === Storage error conversion from mysql error
impl std::convert::From<mysql::Error> for StorageError {
    fn from(_error: mysql::Error) -> Self {
        StorageError::GetError
    }
}

impl Storage for MySqlDatabase {
    fn set(&self, pos: String, val: &[u8]) -> core::result::Result<(), StorageError> {
        let result = || -> core::result::Result<(), mysql::Error> {
            let pool = Pool::new(self.opts.clone())?;
            let mut conn = pool.get_conn()?;
            let statement_text = "INSERT INTO `".to_owned()
                + TABLE
                + "` (`key`, `value`) VALUES (:the_key, :the_value)";
            conn.exec_drop(
                statement_text,
                params! { "the_key" => pos, "the_value" => val },
            )?;
            Ok(())
        };

        match result() {
            Ok(()) => Ok(()),
            _code => Err(StorageError::SetError),
        }
    }
    fn get(&self, pos: String) -> core::result::Result<Vec<u8>, StorageError> {
        let pool = Pool::new(self.opts.clone())?;
        let mut conn = pool.get_conn()?;

        let statement_text =
            "SELECT `key`, `value` FROM `".to_owned() + TABLE + "` WHERE `key` = :the_key LIMIT 1";
        let statement = conn.prep(statement_text)?;
        let result: Option<(String, Vec<u8>)> =
            conn.exec_first(statement, params! { "the_key" => pos })?;

        if let Some((_key, value)) = result {
            return Ok(value);
        }

        core::result::Result::Err(StorageError::GetError)
    }

    fn append_user_state(
        &self,
        username: &Username,
        value: &UserState,
    ) -> core::result::Result<(), StorageError> {
        let result = || -> core::result::Result<(), mysql::Error> {
            let pool = Pool::new(self.opts.clone())?;
            let mut conn = pool.get_conn()?;
            let statement_text = "INSERT INTO `".to_owned()
                + USER_TABLE
                + "` (`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`) VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)";
            conn.exec_drop(
                statement_text,
                params! { "username" => username.0.clone(), "epoch" => value.epoch, "version" => value.version, "node_label_val" => value.label.val, "node_label_len" => value.label.len, "data" => value.plaintext_val.0.clone() },
            )?;
            Ok(())
        };

        match result() {
            Ok(()) => Ok(()),
            _code => Err(StorageError::SetError),
        }
    }

    // TODO: modify this
    fn append_user_states(
        &self,
        values: Vec<(Username, UserState)>,
    ) -> core::result::Result<(), StorageError> {
        // for kvp in values {
        //     self.append_user_state(&kvp.0, &kvp.1)?;
        // }
        // Ok(())

        let result = || -> core::result::Result<(), mysql::Error> {
            let pool = Pool::new(self.opts.clone())?;
            let mut conn = pool.get_conn()?;

            let statement_text = "INSERT INTO `".to_owned()
                + USER_TABLE
                + "` (`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`) VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)";

            let mut tx = conn.start_transaction(TxOpts::default())?;

            let mut steps = || -> core::result::Result<(), mysql::Error> {
                for chunk in values.chunks(100) {
                    tx.exec_batch(
                        statement_text.clone(),
                        chunk.iter().map(|(name, value)| {
                            params! { "username" => name.0.clone(), "epoch" => value.epoch, "version" => value.version, "node_label_val" => value.label.val, "node_label_len" => value.label.len, "data" => value.plaintext_val.0.clone() }
                        })
                    )?;
                }
                Ok(())
            };

            if steps().is_err() {
                tx.rollback()?;
            } else {
                tx.commit()?;
            }
            Ok(())
        };

        match result() {
            Ok(()) => Ok(()),
            _code => Err(StorageError::SetError),
        }
    }

    fn get_user_data(&self, username: &Username) -> core::result::Result<UserData, StorageError> {
        let result = || -> core::result::Result<UserData, mysql::Error> {
            let pool = Pool::new(self.opts.clone())?;
            let mut conn = pool.get_conn()?;
            let statement_text =
                "SELECT `epoch`, `version`, `node_label_val`, `node_label_len`, `data` FROM `"
                    .to_owned()
                    + USER_TABLE
                    + "` WHERE `username` = :the_user";
            let selected_records = conn.exec_map(
                statement_text,
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
        };

        match result() {
            Ok(output) => Ok(output),
            _ => Err(StorageError::GetError),
        }
    }
    fn get_user_state(
        &self,
        username: &Username,
        flag: UserStateRetrievalFlag,
    ) -> core::result::Result<UserState, StorageError> {
        let result = || -> core::result::Result<Option<UserState>, mysql::Error> {
            let pool = Pool::new(self.opts.clone())?;
            let mut conn = pool.get_conn()?;
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
            }

            // add limit to retrieve only 1 record
            statement_text += " LIMIT 1";
            let selected_record = conn.exec_map(
                statement_text,
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
        };

        match result() {
            Ok(Some(result)) => Ok(result),
            _ => Err(StorageError::GetError),
        }
    }
}

impl Clone for MySqlDatabase {
    fn clone(&self) -> MySqlDatabase {
        MySqlDatabase {
            opts: self.opts.clone(),
        }
    }
}
