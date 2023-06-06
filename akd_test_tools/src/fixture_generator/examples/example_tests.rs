// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Example test utilizing a fixture file.

use std::fs::File;

use akd::{
    directory::Directory,
    ecvrf::HardCodedAkdVRF,
    storage::{memory::AsyncInMemoryDatabase, Database, StorageManager, StorageUtil},
    NamedConfiguration,
};

use crate::fixture_generator::reader::Reader;
use crate::{fixture_generator::reader::yaml::YamlFileReader, test_config};

// Contains two consecutive states and the delta between them
const FILE_PATH: &str = "src/fixture_generator/examples";

test_config!(test_use_fixture);
async fn test_use_fixture<TC: NamedConfiguration>() {
    // load fixture
    let mut reader =
        YamlFileReader::new(File::open(format!("{}/{}.yaml", FILE_PATH, TC::name())).unwrap())
            .unwrap();
    let metadata = reader.read_metadata().unwrap();
    let epochs = metadata.args.capture_states.unwrap();

    // prepare directory with initial state
    let initial_state = reader.read_state(epochs[0]).unwrap();
    let db = AsyncInMemoryDatabase::new();
    db.batch_set(initial_state.records, akd::storage::DbSetState::General)
        .await
        .unwrap();
    let vrf = HardCodedAkdVRF {};
    let storage_manager = StorageManager::new_no_cache(db);
    let akd = Directory::<TC, _, _>::new(storage_manager.clone(), vrf)
        .await
        .unwrap();

    // publish delta updates
    let delta = reader.read_delta(epochs[1]).unwrap();
    akd.publish(delta.updates).await.unwrap();

    // assert final directory state
    let final_state = reader.read_state(epochs[1]).unwrap();
    let records = storage_manager
        .get_db()
        .batch_get_all_direct()
        .await
        .unwrap();
    assert_eq!(final_state.records.len(), records.len());
    assert!(records.iter().all(|r| final_state.records.contains(r)));
}
