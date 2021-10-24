// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::StorageError;
use crate::storage::Storage;
use mysql::prelude::*;
use mysql::*;
use std::process::Command;

const TABLE: &str = "data";

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

            let command = "CREATE TABLE IF NOT EXISTS `".to_owned()
                + TABLE
                + "` (`key` VARCHAR(64) NOT NULL, `value` VARCHAR(2000), PRIMARY KEY (`key`)"
                + ")";
            conn.query_drop(command)?;

            Ok(())
        };

        let _output = result(opts.clone());

        Self { opts }
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
    fn set(&self, pos: String, val: String) -> core::result::Result<(), StorageError> {
        let result = || -> core::result::Result<(), StorageError> {
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

        // The casting above ^ will auto-convert SQL errs to StorageError::GetError where it should be SetError.
        // Here we trap that and convert it
        match result() {
            core::result::Result::Err(StorageError::GetError) => Err(StorageError::SetError),
            code => code,
        }
    }
    fn get(&self, pos: String) -> core::result::Result<String, StorageError> {
        let pool = Pool::new(self.opts.clone())?;
        let mut conn = pool.get_conn()?;

        let statement_text =
            "SELECT `key`, `value` FROM `".to_owned() + TABLE + "` WHERE `key` = :the_key LIMIT 1";
        let statement = conn.prep(statement_text)?;
        let result: Option<(String, String)> =
            conn.exec_first(statement, params! { "the_key" => pos })?;

        if let Some((_key, value)) = result {
            return Ok(value);
        }

        core::result::Result::Err(StorageError::GetError)
    }
}

impl Clone for MySqlDatabase {
    fn clone(&self) -> MySqlDatabase {
        MySqlDatabase {
            opts: self.opts.clone(),
        }
    }
}
