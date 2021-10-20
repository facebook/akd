// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

// use mysql::*;
// use mysql::prelude::*;
use crate::errors::StorageError;
use crate::storage::Storage;

/*
    MySql documentation: https://docs.rs/mysql/21.0.2/mysql/
*/

pub struct XdbDatabase {
    connection_string: String,
    table: String,
}

impl XdbDatabase {
    pub fn new(conn: String, table: String) -> XdbDatabase {
        XdbDatabase { connection_string: conn, table: table }
    }
}

impl Storage for XdbDatabase {
    fn set(&self, _pos: String, _val: String) -> core::result::Result<(), StorageError> {

        // let pool = Pool::new(self.connection_string.to_string())?;
        // let mut conn = pool.get_conn()?;
        // let result = conn.query_first(r"SELECT value from {table}")?;

        Ok(())
    }
    fn get(&self, _pos: String) -> core::result::Result<String, StorageError> {
        Ok("".to_string())
    }
}

impl Clone for XdbDatabase {
    fn clone(&self) -> XdbDatabase {
        XdbDatabase { connection_string: self.connection_string.clone(), table: self.table.clone() }
    }
}
