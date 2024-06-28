// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Contains the tests for ensuring that preloading of nodes works as intended

use akd_core::configuration::Configuration;

use crate::{
    directory::Directory,
    ecvrf::HardCodedAkdVRF,
    errors::{AkdError, StorageError},
    storage::{manager::StorageManager, memory::AsyncInMemoryDatabase},
    test_config,
    tests::{setup_mocked_db, MockLocalDatabase},
    tree_node::TreeNodeWithPreviousValue,
    AkdLabel, AkdValue,
};

test_config!(test_publish_op_makes_no_get_requests);
async fn test_publish_op_makes_no_get_requests<TC: Configuration>() -> Result<(), AkdError> {
    let test_db = AsyncInMemoryDatabase::new();

    let mut db = MockLocalDatabase {
        ..Default::default()
    };
    setup_mocked_db(&mut db, &test_db);

    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf)
        .await
        .expect("Failed to create directory");

    // Create a set with 2 updates, (label, value) pairs
    // ("hello10", "hello10")
    // ("hello11", "hello11")
    let mut updates = vec![];
    for i in 0..2 {
        updates.push((
            AkdLabel(format!("hello1{i}").as_bytes().to_vec()),
            AkdValue(format!("hello1{i}").as_bytes().to_vec()),
        ));
    }
    // Publish the updates. Now the akd's epoch will be 1.
    akd.publish(updates)
        .await
        .expect("Failed to do initial publish");

    // create a new mock, this time which explodes on any "get" of tree-nodes (shouldn't happen). It is still backed by the same
    // async in-mem db so all previous data should be there
    let mut db2 = MockLocalDatabase {
        ..Default::default()
    };
    setup_mocked_db(&mut db2, &test_db);
    db2.expect_get::<TreeNodeWithPreviousValue>()
        .returning(|_| Err(StorageError::Other("Boom!".to_string())));

    let storage = StorageManager::new_no_cache(db2);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf)
        .await
        .expect("Failed to create directory");

    // create more updates
    let mut updates = vec![];
    for i in 0..2 {
        updates.push((
            AkdLabel(format!("hello1{i}").as_bytes().to_vec()),
            AkdValue(format!("hello1{}", i + 1).as_bytes().to_vec()),
        ));
    }

    // try to publish again, this time with the "boom" returning from any mocked get-calls
    // on tree nodes
    akd.publish(updates)
        .await
        .expect("Failed to do subsequent publish");

    Ok(())
}
