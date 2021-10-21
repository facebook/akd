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

const TABLE: &str = "data";
#[allow(unused)]
const NUMBER_OF_DB_CHARS: u16 = 2000u16;

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

            let char_str = NUMBER_OF_DB_CHARS.to_string();

            let command = "CREATE TABLE IF NOT EXISTS ".to_owned()
                + TABLE
                + " (key VARCHAR("
                + &char_str
                + "), value VARCHAR("
                + &char_str
                + "));";
            conn.query_drop(command)?;

            Ok(())
        };

        let _output = result(opts.clone());

        Self { opts }
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
            let statement_text =
                "INSERT INTO ".to_owned() + TABLE + " (key, value) VALUES (:the_key, :the_value)";
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
            "SELECT TOP(1) key, value FROM ".to_owned() + TABLE + " WHERE key = :the_key";
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
