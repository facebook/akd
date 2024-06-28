// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Contains the tests for the high-level API (directory, auditor, client)

mod test_core_protocol;
mod test_errors;
mod test_preloads;

use std::collections::HashMap;

use crate::{
    errors::StorageError,
    storage::{
        memory::AsyncInMemoryDatabase,
        types::{DbRecord, KeyData, ValueState, ValueStateRetrievalFlag},
        Database, DbSetState, Storable,
    },
    tree_node::TreeNodeWithPreviousValue,
    AkdLabel, AkdValue, Azks,
};

// Below contains the mock code for constructing a `MockLocalDatabase`

#[allow(dead_code)]
#[derive(Clone)]
pub struct LocalDatabase;

unsafe impl Send for LocalDatabase {}

unsafe impl Sync for LocalDatabase {}

// Note that this macro produces a `MockLocalDatabase` struct
mockall::mock! {
    pub LocalDatabase {

    }
    impl Clone for LocalDatabase {
        fn clone(&self) -> Self;
    }
    #[async_trait::async_trait]
    impl Database for LocalDatabase {
        async fn set(&self, record: DbRecord) -> Result<(), StorageError>;
        async fn batch_set(
            &self,
            records: Vec<DbRecord>,
            state: DbSetState,
        ) -> Result<(), StorageError>;
        async fn get<St: Storable>(&self, id: &St::StorageKey) -> Result<DbRecord, StorageError>;
        async fn batch_get<St: Storable>(
            &self,
            ids: &[St::StorageKey],
        ) -> Result<Vec<DbRecord>, StorageError>;
        async fn get_user_data(&self, username: &AkdLabel) -> Result<KeyData, StorageError>;
        async fn get_user_state(
            &self,
            username: &AkdLabel,
            flag: ValueStateRetrievalFlag,
        ) -> Result<ValueState, StorageError>;
        async fn get_user_state_versions(
            &self,
            usernames: &[AkdLabel],
            flag: ValueStateRetrievalFlag,
        ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError>;
    }
}

fn setup_mocked_db(db: &mut MockLocalDatabase, test_db: &AsyncInMemoryDatabase) {
    // ===== Set ===== //
    let tmp_db = test_db.clone();
    db.expect_set()
        .returning(move |record| futures::executor::block_on(tmp_db.set(record)));

    // ===== Batch Set ===== //
    let tmp_db = test_db.clone();
    db.expect_batch_set().returning(move |record, other| {
        futures::executor::block_on(tmp_db.batch_set(record, other))
    });

    // ===== Get ===== //
    let tmp_db = test_db.clone();
    db.expect_get::<Azks>()
        .returning(move |key| futures::executor::block_on(tmp_db.get::<Azks>(key)));

    let tmp_db = test_db.clone();
    db.expect_get::<TreeNodeWithPreviousValue>()
        .returning(move |key| {
            futures::executor::block_on(tmp_db.get::<TreeNodeWithPreviousValue>(key))
        });

    let tmp_db = test_db.clone();
    db.expect_get::<Azks>()
        .returning(move |key| futures::executor::block_on(tmp_db.get::<Azks>(key)));

    // ===== Batch Get ===== //
    let tmp_db = test_db.clone();
    db.expect_batch_get::<Azks>()
        .returning(move |key| futures::executor::block_on(tmp_db.batch_get::<Azks>(key)));

    let tmp_db = test_db.clone();
    db.expect_batch_get::<TreeNodeWithPreviousValue>()
        .returning(move |key| {
            futures::executor::block_on(tmp_db.batch_get::<TreeNodeWithPreviousValue>(key))
        });

    // ===== Get User Data ===== //
    let tmp_db = test_db.clone();
    db.expect_get_user_data()
        .returning(move |arg| futures::executor::block_on(tmp_db.get_user_data(arg)));

    // ===== Get User State ===== //
    let tmp_db = test_db.clone();
    db.expect_get_user_state()
        .returning(move |arg, flag| futures::executor::block_on(tmp_db.get_user_state(arg, flag)));

    // ===== Get User State Versions ===== //
    let tmp_db = test_db.clone();
    db.expect_get_user_state_versions()
        .returning(move |arg, flag| {
            futures::executor::block_on(tmp_db.get_user_state_versions(arg, flag))
        });
}
