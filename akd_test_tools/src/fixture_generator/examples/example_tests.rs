// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Example test utilizing a fixture file.

use std::fs::File;
use std::sync::Arc;

use akd::{
    directory::Directory,
    ecvrf::HardCodedAkdVRF,
    storage::{memory::AsyncInMemoryDatabase, Database, StorageManager, StorageUtil},
};

use crate::fixture_generator::reader::yaml::YamlFileReader;
use crate::fixture_generator::reader::Reader;

// Contains two consecutive states and the delta between them
const TEST_FILE: &str = "src/fixture_generator/examples/test.yaml";

#[tokio::test]
async fn test_use_fixture() {
    // load fixture
    let mut reader = YamlFileReader::new(File::open(TEST_FILE).unwrap()).unwrap();
    let metadata = reader.read_metadata().unwrap();
    let epochs = metadata.args.capture_states.unwrap();

    // prepare directory with initial state
    let initial_state = reader.read_state(epochs[0]).unwrap();
    let db = Arc::new(AsyncInMemoryDatabase::new());
    db.batch_set(initial_state.records, akd::storage::DbSetState::General)
        .await
        .unwrap();
    let vrf = HardCodedAkdVRF {};
    let storage_manager = StorageManager::new_no_cache(db.clone());
    let akd = Directory::<_, _>::new(storage_manager, vrf, false)
        .await
        .unwrap();

    // publish delta updates
    let delta = reader.read_delta(epochs[1]).unwrap();
    akd.publish(delta.updates).await.unwrap();

    // assert final directory state
    let final_state = reader.read_state(epochs[1]).unwrap();
    let records = db.batch_get_all_direct().await.unwrap();
    assert_eq!(final_state.records.len(), records.len());
    assert!(records.iter().all(|r| final_state.records.contains(r)));
}
