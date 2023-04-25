// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Tests of the storage manager

use akd_core::hash::EMPTY_DIGEST;

use super::*;
use crate::storage::memory::AsyncInMemoryDatabase;
use crate::storage::{types::*, StorageUtil};
use crate::tree_node::{NodeKey, TreeNodeWithPreviousValue};
use crate::*;

#[tokio::test]
async fn test_storage_manager_transaction() {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new_no_cache(db);

    assert!(
        storage_manager.begin_transaction(),
        "Failed to start transaction"
    );

    let mut records = (0..10)
        .map(|i| {
            let label = NodeLabel {
                label_len: i,
                label_val: [i as u8; 32],
            };
            DbRecord::TreeNode(DbRecord::build_tree_node_with_previous_value(
                label.label_val,
                label.label_len,
                0,
                0,
                [0u8; 32],
                0,
                0,
                None,
                None,
                EMPTY_DIGEST,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ))
        })
        .collect::<Vec<_>>();

    records.push(DbRecord::Azks(Azks {
        latest_epoch: 0,
        num_nodes: 0,
    }));

    storage_manager
        .batch_set(records)
        .await
        .expect("Failed to set batch of records");
    // there should be no items in the db, as they should all be in the transaction log
    assert_eq!(
        Ok(0),
        storage_manager
            .db
            .batch_get_all_direct()
            .await
            .map(|items| items.len())
    );
    assert_eq!(11, storage_manager.transaction.count());

    // test a retrieval doesn't go to the database. Since we know the db is empty, it should be retrieved from the transaction log
    let key = NodeKey(NodeLabel {
        label_len: 2,
        label_val: [2u8; 32],
    });
    storage_manager
        .get::<TreeNodeWithPreviousValue>(&key)
        .await
        .expect("Failed to get database record for node label 2");

    let keys = vec![
        key,
        NodeKey(NodeLabel {
            label_len: 3,
            label_val: [3u8; 32],
        }),
    ];
    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(2, got.len());

    storage_manager
        .commit_transaction()
        .await
        .expect("Failed to commit transaction");
    // now the records should be in the database and the transaction log empty
    assert_eq!(
        Ok(11),
        storage_manager
            .db
            .batch_get_all_direct()
            .await
            .map(|items| items.len())
    );
    assert_eq!(0, storage_manager.transaction.count());
}

#[tokio::test]
async fn test_storage_manager_cache_populated_by_batch_set() {
    let db = AsyncInMemoryDatabase::new();

    let storage_manager = StorageManager::new(db, None, None, None);

    let mut records = (0..10)
        .map(|i| {
            let label = NodeLabel {
                label_len: i,
                label_val: [i as u8; 32],
            };
            DbRecord::TreeNode(DbRecord::build_tree_node_with_previous_value(
                label.label_val,
                label.label_len,
                0,
                0,
                [0u8; 32],
                0,
                0,
                None,
                None,
                EMPTY_DIGEST,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ))
        })
        .collect::<Vec<_>>();

    records.push(DbRecord::Azks(Azks {
        latest_epoch: 0,
        num_nodes: 0,
    }));

    // write straight to the db, populating the cache
    storage_manager
        .batch_set(records)
        .await
        .expect("Failed to set batch of records");

    // flush the database
    storage_manager.db.clear();

    // test a retrieval still gets data (from the cache)
    let key = NodeKey(NodeLabel {
        label_len: 2,
        label_val: [2u8; 32],
    });
    storage_manager
        .get::<TreeNodeWithPreviousValue>(&key)
        .await
        .expect("Failed to get database record for node label 2");

    let keys = vec![
        key,
        NodeKey(NodeLabel {
            label_len: 3,
            label_val: [3u8; 32],
        }),
    ];
    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(2, got.len());

    storage_manager.flush_cache().await;

    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(0, got.len());
}

#[tokio::test]
async fn test_storage_manager_cache_populated_by_batch_get() {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new(db, None, None, None);

    let mut keys = vec![];
    let mut records = (0..10)
        .map(|i| {
            let label = NodeLabel {
                label_len: i,
                label_val: [i as u8; 32],
            };
            keys.push(NodeKey(label));
            DbRecord::TreeNode(DbRecord::build_tree_node_with_previous_value(
                label.label_val,
                label.label_len,
                0,
                0,
                [0u8; 32],
                0,
                0,
                None,
                None,
                EMPTY_DIGEST,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ))
        })
        .collect::<Vec<_>>();

    records.push(DbRecord::Azks(Azks {
        latest_epoch: 0,
        num_nodes: 0,
    }));

    // write straight to the db
    storage_manager
        .batch_set(records)
        .await
        .expect("Failed to set batch of records");

    let db_arc = storage_manager.get_db();
    // flush the cache by destroying the storage manager
    drop(storage_manager);

    // re-create the storage manager, and run a batch_get of the same data keys to populate the cache
    let storage_manager = StorageManager::new(
        Arc::try_unwrap(db_arc).expect("Failed to grab arc"),
        Some(std::time::Duration::from_secs(1000)),
        None,
        None,
    );

    let _ = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to get a batch of records");

    // flush the database
    storage_manager.db.clear();

    // test a retrieval still gets data (from the cache)
    let key = NodeKey(NodeLabel {
        label_len: 2,
        label_val: [2u8; 32],
    });
    storage_manager
        .get::<TreeNodeWithPreviousValue>(&key)
        .await
        .expect("Failed to get database record for node label 2");

    let keys = vec![
        key,
        NodeKey(NodeLabel {
            label_len: 3,
            label_val: [3u8; 32],
        }),
    ];
    let got = storage_manager
        .batch_get::<TreeNodeWithPreviousValue>(&keys)
        .await
        .expect("Failed to batch-get");
    assert_eq!(2, got.len());

    storage_manager.flush_cache().await;

    // This should be an empty result
    assert_eq!(
        Ok(vec![]),
        storage_manager
            .batch_get::<TreeNodeWithPreviousValue>(&keys)
            .await
    );
}
