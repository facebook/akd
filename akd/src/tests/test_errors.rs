// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Contains the tests for error conditions and invariants that should be upheld
//! by the API.

use akd_core::configuration::Configuration;
use std::default::Default;

use crate::storage::types::KeyData;
use crate::tree_node::TreeNodeWithPreviousValue;
use crate::{
    auditor::audit_verify,
    client::{key_history_verify, lookup_verify},
    directory::{Directory, PublishCorruption, ReadOnlyDirectory},
    ecvrf::{HardCodedAkdVRF, VRFKeyStorage},
    errors::{AkdError, DirectoryError, StorageError},
    storage::{
        manager::StorageManager, memory::AsyncInMemoryDatabase, types::DbRecord, types::ValueState,
        Database,
    },
    test_config,
    tests::{setup_mocked_db, MockLocalDatabase},
    AkdLabel, AkdValue, Azks, EpochHash, HistoryParams, HistoryVerificationParams, NodeLabel,
};

// This test is meant to test the function poll_for_azks_change
// which is meant to detect changes in the azks, to prevent inconsistencies
// between the local cache and storage.
test_config!(test_directory_polling_azks_change);
async fn test_directory_polling_azks_change<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new(db, None, None, None);
    let vrf = HardCodedAkdVRF {};
    // writer will write the AZKS record
    let writer = Directory::<TC, _, _>::new(storage.clone(), vrf.clone()).await?;

    writer
        .publish(vec![
            (AkdLabel::from("hello"), AkdValue::from("world")),
            (AkdLabel::from("hello2"), AkdValue::from("world2")),
        ])
        .await?;

    // reader will not write the AZKS but will be "polling" for AZKS changes
    let reader = ReadOnlyDirectory::<TC, _, _>::new(storage, vrf).await?;

    // start the poller
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    let reader_clone = reader.clone();
    let _join_handle = tokio::task::spawn(async move {
        reader_clone
            .poll_for_azks_changes(tokio::time::Duration::from_millis(100), Some(tx))
            .await
    });

    // wait for a second to make sure the poller has started
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // verify a lookup proof, which will populate the cache
    async_poll_helper_proof(&reader, AkdValue::from("world")).await?;

    // publish epoch 2
    writer
        .publish(vec![
            (AkdLabel::from("hello"), AkdValue::from("world_2")),
            (AkdLabel::from("hello2"), AkdValue::from("world2_2")),
        ])
        .await?;

    // assert that the change is picked up in a reasonable time-frame and the cache is flushed
    let notification = tokio::time::timeout(tokio::time::Duration::from_secs(10), rx.recv()).await;
    assert!(matches!(notification, Ok(Some(()))));

    async_poll_helper_proof(&reader, AkdValue::from("world_2")).await?;

    Ok(())
}

// A test to ensure that any database error at the time a Directory is created
// does not automatically attempt to create a new aZKS. Only aZKS not found errors
// should assume that a successful read happened and no aZKS exists.
test_config!(test_directory_azks_bootstrapping);
async fn test_directory_azks_bootstrapping<TC: Configuration>() -> Result<(), AkdError> {
    let vrf = HardCodedAkdVRF {};

    // Verify that a Storage error results in an error when attempting to create the Directory
    let mut mock_db = MockLocalDatabase {
        ..Default::default()
    };
    mock_db
        .expect_get::<Azks>()
        .returning(|_| Err(StorageError::Connection("Fire!".to_string())));
    mock_db.expect_set().times(0);
    let storage = StorageManager::new_no_cache(mock_db);

    let maybe_akd = Directory::<TC, _, _>::new(storage, vrf.clone()).await;
    assert!(maybe_akd.is_err());

    // Verify that an aZKS not found error results in one being created with the Directory
    // We're creating an empty directory here, so this is the expected behavior for NotFound
    let mut mock_db = MockLocalDatabase {
        ..Default::default()
    };
    let test_db = AsyncInMemoryDatabase::new();
    setup_mocked_db(&mut mock_db, &test_db);
    let storage = StorageManager::new_no_cache(mock_db);

    let maybe_akd = Directory::<TC, _, _>::new(storage, vrf).await;
    assert!(maybe_akd.is_ok());

    let akd = maybe_akd.expect("Failed to get create a Directory!");
    let azks = akd.retrieve_azks().await.expect("Failed to get aZKS!");
    assert_eq!(0, azks.get_latest_epoch());

    Ok(())
}

// It is possible to perform a "dirty read" when reading states during a key history operation
// that will result in an epoch from the dirty read being higher than the aZKS epoch. In such an
// event, we ignore value states that are part of the dirty read. This test ensures that we do not
// inadvertently panic when inspecting marker versions due to "start version" and "end version"
// invariants being violated.
test_config!(test_key_history_dirty_reads);
async fn test_key_history_dirty_reads<TC: Configuration>() -> Result<(), AkdError> {
    let committed_epoch = 10;
    let dirty_epoch = 11;

    let mut mock_db = MockLocalDatabase::default();
    mock_db.expect_get::<Azks>().returning(move |_| {
        Ok(DbRecord::Azks(Azks {
            latest_epoch: committed_epoch,
            num_nodes: 1,
        }))
    });
    mock_db.expect_get_user_data().returning(move |_| {
        Ok(KeyData {
            states: vec![ValueState {
                value: AkdValue(Vec::new()),
                version: 2,
                label: NodeLabel {
                    label_val: [0u8; 32],
                    label_len: 32,
                },
                epoch: dirty_epoch,
                username: AkdLabel::from("ferris"),
            }],
        })
    });
    // We can just return some fake error at this point, as we're not validating
    // actual history proof functionality.
    mock_db
        .expect_get::<TreeNodeWithPreviousValue>()
        .returning(|_| Err(StorageError::Other("Fake!".to_string())));

    let storage = StorageManager::new_no_cache(mock_db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf).await?;

    // Ensure that we do not panic in this scenario, so we can just ignore the result.
    let _res = akd
        .key_history(&AkdLabel::from("ferris"), HistoryParams::MostRecent(1))
        .await;

    Ok(())
}

test_config!(test_read_during_publish);
async fn test_read_during_publish<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db.clone());
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf).await?;

    // Publish once
    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world")),
        (AkdLabel::from("hello2"), AkdValue::from("world2")),
    ])
    .await
    .unwrap();
    // Get the root hash after the first publish
    let root_hash_1 = akd.get_epoch_hash().await?.1;
    // Publish updates for the same labels.
    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world_2")),
        (AkdLabel::from("hello2"), AkdValue::from("world2_2")),
    ])
    .await
    .unwrap();

    // Get the root hash after the second publish
    let root_hash_2 = akd.get_epoch_hash().await?.1;

    // Make the current azks a "checkpoint" to reset to later
    let checkpoint_azks = akd.retrieve_azks().await.unwrap();

    // Publish for the third time with a new label
    akd.publish(vec![
        (AkdLabel::from("hello"), AkdValue::from("world_3")),
        (AkdLabel::from("hello2"), AkdValue::from("world2_3")),
        (AkdLabel::from("hello3"), AkdValue::from("world3")),
    ])
    .await
    .unwrap();

    // Reset the azks record back to previous epoch, to emulate an akd reader
    // communicating with storage that is in the middle of a publish operation
    db.set(DbRecord::Azks(checkpoint_azks))
        .await
        .expect("Error resetting directory to previous epoch");

    // re-create the directory instance so it refreshes from storage
    let storage = StorageManager::new_no_cache(db.clone());
    let vrf = HardCodedAkdVRF {};
    let akd = ReadOnlyDirectory::<TC, _, _>::new(storage, vrf)
        .await
        .unwrap();

    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await.unwrap();

    // Lookup proof should contain the checkpoint epoch's value and still verify
    let (lookup_proof, root_hash) = akd.lookup(AkdLabel::from("hello")).await.unwrap();
    assert_eq!(AkdValue::from("world_2"), lookup_proof.value);
    lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        lookup_proof,
    )
    .unwrap();

    // History proof should not contain the third epoch's update but still verify
    let (history_proof, root_hash) = akd
        .key_history(&AkdLabel::from("hello"), HistoryParams::default())
        .await
        .unwrap();
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        history_proof,
        HistoryVerificationParams::default(),
    )
    .unwrap();

    // Lookup proof for the most recently added key (ahead of directory epoch) should
    // result in the entry not being found.
    let recently_added_lookup_result = akd.lookup(AkdLabel::from("hello3")).await;
    assert!(matches!(
        recently_added_lookup_result,
        Err(AkdError::Storage(StorageError::NotFound(_)))
    ));

    // History proof for the most recently added key (ahead of directory epoch) should
    // result in the entry not being found.
    let recently_added_history_result = akd
        .key_history(&AkdLabel::from("hello3"), HistoryParams::default())
        .await;
    assert!(matches!(
        recently_added_history_result,
        Err(AkdError::Storage(StorageError::NotFound(_)))
    ));

    // Audit proof should only work up until checkpoint's epoch
    let audit_proof = akd.audit(1, 2).await.unwrap();
    audit_verify::<TC>(vec![root_hash_1, root_hash_2], audit_proof)
        .await
        .unwrap();

    let invalid_audit = akd.audit(2, 3).await;
    assert!(invalid_audit.is_err());

    Ok(())
}

// The read-only mode of a directory is meant to simply read from memory.
// This test makes sure it throws errors appropriately, i.e. when trying to
// write to a read-only directory and when trying to read a directory when none
// exists in storage.
test_config!(test_directory_read_only_mode);
async fn test_directory_read_only_mode<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // There is no AZKS object in the storage layer, directory construction should fail
    let akd = ReadOnlyDirectory::<TC, _, _>::new(storage, vrf).await;
    assert!(akd.is_err());

    Ok(())
}

// Test for attempting to publish duplicate entries as updates to the directory
test_config!(test_publish_duplicate_entries);
async fn test_publish_duplicate_entries<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf.clone()).await?;

    // Create a set of updates
    let mut updates = vec![];
    for i in 0..10 {
        updates.push((
            AkdLabel(format!("hello1{i}").as_bytes().to_vec()),
            AkdValue(format!("hello1{i}").as_bytes().to_vec()),
        ));
    }

    // Now add a duplicate entry
    updates.push(updates[0].clone());

    // Attempt to publish -- this should throw an error because of the duplicate entry
    let Err(AkdError::Directory(DirectoryError::Publish(_))) = akd.publish(updates).await else {
        panic!("Expected a directory publish error");
    };

    Ok(())
}

// This tests that key history does fail on a small tree, when malicious updates are made.
// Other that it is just a simple check to see that a valid key history proof passes.
test_config!(test_malicious_key_history);
async fn test_malicious_key_history<TC: Configuration>() -> Result<(), AkdError> {
    // This test has an akd with a single label: "hello", followed by an
    // insertion of a new label "hello2". Meanwhile, the server has a one epoch
    // delay in marking the first version for "hello" as stale, which should
    // be caught by key history verifications for "hello".
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf).await?;
    // Publish the first value for the label "hello"
    // Epoch here will be 1
    akd.publish(vec![(AkdLabel::from("hello"), AkdValue::from("world"))])
        .await?;
    // Publish the second value for the label "hello" without marking the first value as stale
    // Epoch here will be 2
    let corruption_2 = PublishCorruption::UnmarkedStaleVersion(AkdLabel::from("hello"));
    akd.publish_malicious_update(
        vec![(AkdLabel::from("hello"), AkdValue::from("world2"))],
        corruption_2,
    )
    .await?;

    // Get the key_history_proof for the label "hello"
    let (key_history_proof, root_hash) = akd
        .key_history(&AkdLabel::from("hello"), HistoryParams::default())
        .await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof: This should fail since the server did not mark the version 1 for
    // this username as stale, upon adding version 2.
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    ).expect_err("The key history proof should fail here since the previous value was not marked stale at all");

    // Mark the first value for the label "hello" as stale
    // Epoch here will be 3
    let corruption_3 = PublishCorruption::MarkVersionStale(AkdLabel::from("hello"), 1);
    akd.publish_malicious_update(
        vec![(AkdLabel::from("hello2"), AkdValue::from("world"))],
        corruption_3,
    )
    .await?;

    // Get the key_history_proof for the label "hello"
    let (key_history_proof, root_hash) = akd
        .key_history(&AkdLabel::from("hello"), HistoryParams::default())
        .await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof: This should still fail, since the server added the version number too late.
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    ).expect_err("The key history proof should fail here since the previous value was marked stale one epoch too late.");

    Ok(())
}

// Test key history verification for error handling of malformed key history proofs
test_config!(test_key_history_verify_malformed);
async fn test_key_history_verify_malformed<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<TC, _, _>::new(storage, vrf.clone()).await?;

    let mut rng = rand::rngs::OsRng;
    for _ in 0..100 {
        let mut updates = vec![];
        updates.push((
            AkdLabel("label".to_string().as_bytes().to_vec()),
            AkdValue::random(&mut rng),
        ));
        akd.publish(updates.clone()).await?;
    }

    for _ in 0..100 {
        let mut updates = vec![];
        updates.push((
            AkdLabel("another label".to_string().as_bytes().to_vec()),
            AkdValue::random(&mut rng),
        ));
        akd.publish(updates.clone()).await?;
    }

    // Get the latest root hash
    let EpochHash(current_epoch, root_hash) = akd.get_epoch_hash().await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    let target_label = AkdLabel("label".to_string().as_bytes().to_vec());

    let history_params_5 = HistoryParams::MostRecent(5);

    let (key_history_proof, _) = akd.key_history(&target_label, history_params_5).await?;

    let correct_verification_params = HistoryVerificationParams::Default {
        history_params: history_params_5,
    };

    // Normal verification should succeed
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        target_label.clone(),
        key_history_proof.clone(),
        correct_verification_params,
    )?;

    // Using an inconsistent set of history parameters should fail
    for bad_params in [
        HistoryParams::MostRecent(1),
        HistoryParams::MostRecent(4),
        HistoryParams::MostRecent(6),
        HistoryParams::default(),
    ] {
        assert!(key_history_verify::<TC>(
            vrf_pk.as_bytes(),
            root_hash,
            current_epoch,
            target_label.clone(),
            key_history_proof.clone(),
            HistoryVerificationParams::Default {
                history_params: bad_params
            },
        )
        .is_err());
    }

    let mut malformed_proof_1 = key_history_proof.clone();
    malformed_proof_1.past_marker_vrf_proofs = key_history_proof.past_marker_vrf_proofs
        [..key_history_proof.past_marker_vrf_proofs.len() - 1]
        .to_vec();
    let mut malformed_proof_2 = key_history_proof.clone();
    malformed_proof_2.existence_of_past_marker_proofs = key_history_proof
        .existence_of_past_marker_proofs
        [..key_history_proof.existence_of_past_marker_proofs.len() - 1]
        .to_vec();
    let mut malformed_proof_3 = key_history_proof.clone();
    malformed_proof_3.future_marker_vrf_proofs = key_history_proof.future_marker_vrf_proofs
        [..key_history_proof.future_marker_vrf_proofs.len() - 1]
        .to_vec();
    let mut malformed_proof_4 = key_history_proof.clone();
    malformed_proof_4.non_existence_of_future_marker_proofs = key_history_proof
        .non_existence_of_future_marker_proofs[..key_history_proof
        .non_existence_of_future_marker_proofs
        .len()
        - 1]
        .to_vec();

    // Malformed proof verification should fail
    for malformed_proof in [
        malformed_proof_1,
        malformed_proof_2,
        malformed_proof_3,
        malformed_proof_4,
    ] {
        assert!(key_history_verify::<TC>(
            vrf_pk.as_bytes(),
            root_hash,
            current_epoch,
            target_label.clone(),
            malformed_proof,
            correct_verification_params
        )
        .is_err());
    }

    let mut malformed_proof_start_version_is_zero = key_history_proof.clone();
    malformed_proof_start_version_is_zero.update_proofs[0].epoch = 0;
    let mut malformed_proof_end_version_exceeds_epoch = key_history_proof.clone();
    malformed_proof_end_version_exceeds_epoch.update_proofs[0].epoch = current_epoch + 1;

    // Malformed proof verification should fail
    for malformed_proof in [
        malformed_proof_start_version_is_zero,
        malformed_proof_end_version_exceeds_epoch,
    ] {
        assert!(key_history_verify::<TC>(
            vrf_pk.as_bytes(),
            root_hash,
            current_epoch,
            target_label.clone(),
            malformed_proof,
            correct_verification_params,
        )
        .is_err());
    }

    Ok(())
}

// Test lookup_verify where version number exceeds epoch (and it should throw an error)
test_config!(test_lookup_verify_invalid_version_number);
async fn test_lookup_verify_invalid_version_number<TC: Configuration>() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<TC, _, _>::new(storage, vrf.clone()).await?;

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
    // Repeatedly publish the updates. Afterwards, the akd's epoch will be 10.
    for _ in 0..10 {
        akd.publish(updates.clone()).await?;
    }

    // The label we will lookup is "hello10"
    let target_label = AkdLabel(format!("hello1{}", 0).as_bytes().to_vec());

    // retrieve the lookup proof
    let (lookup_proof, root_hash) = akd.lookup(target_label.clone()).await?;

    // Get the VRF public key
    let vrf_pk = vrf.get_vrf_public_key().await?;

    let akd_result = crate::client::lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch() - 1, // To fake a lower epoch and trigger the error condition
        target_label.clone(),
        lookup_proof,
    );

    // Check that the result is a verification error
    match akd_result {
        Err(akd_core::verify::VerificationError::LookupProof(_)) => (),
        _ => panic!("Expected an invalid epoch error"),
    }

    Ok(())
}

/*
=========== Test Helpers ===========
*/

async fn async_poll_helper_proof<TC: Configuration, T: Database + 'static, V: VRFKeyStorage>(
    reader: &ReadOnlyDirectory<TC, T, V>,
    value: AkdValue,
) -> Result<(), AkdError> {
    // reader should read "hello" and this will populate the "cache" a log
    let (lookup_proof, root_hash) = reader.lookup(AkdLabel::from("hello")).await?;
    assert_eq!(value, lookup_proof.value);
    let pk = reader.get_public_key().await?;
    lookup_verify::<TC>(
        pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from("hello"),
        lookup_proof,
    )?;
    Ok(())
}
