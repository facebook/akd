#![cfg(test)]
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the tests for the high-level API (directory, auditor, client)

use crate::{
    auditor::audit_verify,
    client::{key_history_verify, lookup_verify},
    directory::{get_key_history_hashes, Directory, PublishCorruption},
    ecvrf::{HardCodedAkdVRF, VRFKeyStorage},
    errors::AkdError,
    storage::{
        memory::AsyncInMemoryDatabase,
        storage::StorageManager,
        types::{AkdLabel, AkdValue, DbRecord},
        Database as Storage,
    },
};
use winter_crypto::{Digest, Hasher};
use winter_math::fields::f128::BaseElement;
type Blake3 = winter_crypto::hashers::Blake3_256<BaseElement>;
type Sha3 = winter_crypto::hashers::Sha3_256<BaseElement>;

// A simple test to ensure that the empty tree hashes to the correct value
#[tokio::test]
async fn test_empty_tree_root_hash() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;

    let current_azks = akd.retrieve_current_azks().await?;
    let hash = akd.get_root_hash(&current_azks).await?;
    // Ensuring that the root hash of an empty tree is equal to the following constant
    assert_eq!(
        "f48ded419214732a2c610c1e280543744bab3c17aec33e444997fa2d8f79792a",
        hex::encode(hash.as_bytes())
    );
    Ok(())
}

// A simple publish test to make sure a publish doesn't throw an error.
#[tokio::test]
async fn test_simple_publish() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;
    // Make sure you can publish and that something so simple
    // won't throw errors.
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world"),
    )])
    .await?;
    Ok(())
}

// A simple lookup test, for a tree with two elements:
// ensure that calculation of a lookup proof doesn't throw an error and
// that the output of akd.lookup verifies on the client.
#[tokio::test]
async fn test_simple_lookup() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;
    // Add two labels and corresponding values to the akd
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;
    // Get the lookup proof
    let lookup_proof = akd.lookup(AkdLabel::from_utf8_str("hello")).await?;
    // Get the root hash with respect to which lookup_proof should verify
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash(&current_azks).await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the lookup proof
    lookup_verify(
        &vrf_pk,
        root_hash,
        AkdLabel::from_utf8_str("hello"),
        lookup_proof,
    )?;
    Ok(())
}

// This test also covers #144: That key history doesn't fail on very small trees,
// i.e. trees with a potentially empty child for the root node.
// Other that it is just a simple check to see that a valid key history proof passes.
#[tokio::test]
async fn test_small_key_history() -> Result<(), AkdError> {
    // This test has an akd with a single label: "hello"
    // The value of this label is updated two times.
    // Then the test verifies the key history.
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;
    // Publish the first value for the label "hello"
    // Epoch here will be 1
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world"),
    )])
    .await?;
    // Publish the second value for the label "hello"
    // Epoch here will be 2
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world2"),
    )])
    .await?;

    // Get the key_history_proof for the label "hello"
    let key_history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    // Get the latest root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash(&current_azks).await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        false,
    )?;

    Ok(())
}

// Checks history proof for labels with differing numbers of updates.
// Note that this test only performs some basic validation on the proofs and
// checks that the valid proofs verify. It doesn't do much more.
#[tokio::test]
async fn test_simple_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;
    // Epoch 1: Add labels "hello" and "hello2"
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;
    // Epoch 2: Update the values for both the labels to version 2
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_2"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2_2"),
        ),
    ])
    .await?;
    // Epoch 3: Update the values for both the labels again to version 3
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world3"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world4"),
        ),
    ])
    .await?;
    // Epoch 4: Add two new labels
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello3"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello4"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;
    // Epoch 5: Updated "hello" to version 4
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world_updated"),
    )])
    .await?;
    // Epoch 6: Update the values for "hello3" and "hello4"
    // both two version 2.
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello3"),
            AkdValue::from_utf8_str("world6"),
        ),
        (
            AkdLabel::from_utf8_str("hello4"),
            AkdValue::from_utf8_str("world12"),
        ),
    ])
    .await?;
    // Get the key history proof for the label "hello". This should have 4 versions.
    let key_history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    // Check that the correct number of proofs are sent
    if key_history_proof.update_proofs.len() != 4 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 4 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    // Get the latest root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash(&current_azks).await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        false,
    )?;

    // Key history proof for "hello2"
    let key_history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello2")).await?;
    // Check that the correct number of proofs are sent
    if key_history_proof.update_proofs.len() != 3 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 3 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello2"),
        key_history_proof,
        false,
    )?;

    // Key history proof for "hello3"
    let key_history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello3")).await?;
    // Check that the correct number of proofs are sent
    if key_history_proof.update_proofs.len() != 2 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 2 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello3"),
        key_history_proof,
        false,
    )?;

    // Key history proof for "hello4"
    let key_history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello4")).await?;
    // Check that the correct number of proofs are sent
    if key_history_proof.update_proofs.len() != 2 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 2 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello4"),
        key_history_proof.clone(),
        false,
    )?;

    // history proof with updates of non-decreasing versions/epochs fail to verify
    let mut borked_proof = key_history_proof;
    borked_proof.update_proofs = borked_proof.update_proofs.into_iter().rev().collect();
    let result = key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello4"),
        borked_proof,
        false,
    );
    assert!(matches!(result, Err(_)), "{:?}", result);

    Ok(())
}

// This test covers the tests for PR #224, addresses issue #222: That key history does fail on a small tree,
// when malicious updates are made.
// Other that it is just a simple check to see that a valid key history proof passes.
#[tokio::test]
async fn test_malicious_key_history() -> Result<(), AkdError> {
    // This test has an akd with a single label: "hello", followed by an
    // insertion of a new label "hello2". Meanwhile, the server has a one epoch
    // delay in marking the first version for "hello" as stale, which should
    // be caught by key history verifications for "hello".
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;
    // Publish the first value for the label "hello"
    // Epoch here will be 1
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world"),
    )])
    .await?;
    // Publish the second value for the label "hello" without marking the first value as stale
    // Epoch here will be 2
    let corruption_2 = PublishCorruption::UnmarkedStaleVersion(AkdLabel::from_utf8_str("hello"));
    akd.publish_malicious_update(
        vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world2"),
        )],
        corruption_2,
    )
    .await?;

    // Get the key_history_proof for the label "hello"
    let key_history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    // Get the latest root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash(&current_azks).await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof: This should fail since the server did not mark the version 1 for
    // this username as stale, upon adding version 2.
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        false,
    ).expect_err("The key history proof should fail here since the previous value was not marked stale at all");

    // Mark the first value for the label "hello" as stale
    // Epoch here will be 3
    let corruption_3 = PublishCorruption::MarkVersionStale(AkdLabel::from_utf8_str("hello"), 1);
    akd.publish_malicious_update(
        vec![(
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world"),
        )],
        corruption_3,
    )
    .await?;

    // Get the key_history_proof for the label "hello"
    let key_history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    // Get the latest root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash(&current_azks).await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof: This should still fail, since the server added the version number too late.
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        false,
    ).expect_err("The key history proof should fail here since the previous value was marked stale one epoch too late.");

    Ok(())
}

// This test ensures valid audit proofs pass for various epochs and
// that invalid audit proofs fail.
#[tokio::test]
async fn test_simple_audit() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;

    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;

    // Get the root hash after the first server publish
    let root_hash_1 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_2"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2_2"),
        ),
    ])
    .await?;

    // Get the root hash after the second server publish
    let root_hash_2 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world3"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world4"),
        ),
    ])
    .await?;

    // Get the root hash after the third server publish
    let root_hash_3 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello3"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello4"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;

    // Get the root hash after the fourth server publish
    let root_hash_4 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world_updated"),
    )])
    .await?;

    // Get the root hash after the fifth server publish
    let root_hash_5 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello3"),
            AkdValue::from_utf8_str("world6"),
        ),
        (
            AkdLabel::from_utf8_str("hello4"),
            AkdValue::from_utf8_str("world12"),
        ),
    ])
    .await?;

    // Get the root hash after the 6th server publish
    let root_hash_6 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;

    // This is to ensure that an audit of two consecutive, although relatively old epochs is calculated correctly.
    let audit_proof_1 = akd.audit(1, 2).await?;
    audit_verify::<Blake3>(vec![root_hash_1, root_hash_2], audit_proof_1).await?;

    // This is to ensure that an audit of 3 consecutive epochs although not the most recent is calculated correctly.
    let audit_proof_2 = akd.audit(1, 3).await?;
    audit_verify::<Blake3>(vec![root_hash_1, root_hash_2, root_hash_3], audit_proof_2).await?;

    // This is to ensure that an audit of 4 consecutive epochs is calculated correctly.
    let audit_proof_3 = akd.audit(1, 4).await?;
    audit_verify::<Blake3>(
        vec![root_hash_1, root_hash_2, root_hash_3, root_hash_4],
        audit_proof_3,
    )
    .await?;

    // This is to ensure that an audit of 5 consecutive epochs is calculated correctly.
    let audit_proof_4 = akd.audit(1, 5).await?;
    audit_verify::<Blake3>(
        vec![
            root_hash_1,
            root_hash_2,
            root_hash_3,
            root_hash_4,
            root_hash_5,
        ],
        audit_proof_4,
    )
    .await?;

    // Test correct audit of two consecutive epochs but not starting at epoch 1.
    let audit_proof_5 = akd.audit(2, 3).await?;
    audit_verify::<Blake3>(vec![root_hash_2, root_hash_3], audit_proof_5).await?;

    // Test correct audit of 3 consecutive epochs but not starting at epoch 1.
    let audit_proof_6 = akd.audit(2, 4).await?;
    audit_verify::<Blake3>(vec![root_hash_2, root_hash_3, root_hash_4], audit_proof_6).await?;

    // Test correct audit of 3 consecutive epochs ending at epoch 6 -- the last epoch
    let audit_proof_7 = akd.audit(4, 6).await?;
    audit_verify::<Blake3>(vec![root_hash_4, root_hash_5, root_hash_6], audit_proof_7).await?;

    // The audit should be of more than 1 epoch
    let invalid_audit = akd.audit(3, 3).await;
    assert!(matches!(invalid_audit, Err(_)));

    // The audit epochs must be increasing
    let invalid_audit = akd.audit(3, 2).await;
    assert!(matches!(invalid_audit, Err(_)));

    // The audit should throw an error when queried for an epoch which hasn't yet taken place!
    let invalid_audit = akd.audit(6, 7).await;
    assert!(matches!(invalid_audit, Err(_)));

    Ok(())
}

#[tokio::test]
async fn test_read_during_publish() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;

    // Publish once
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;
    // Get the root hash after the first publish
    let root_hash_1 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;
    // Publish updates for the same labels.
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_2"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2_2"),
        ),
    ])
    .await?;

    // Get the root hash after the second publish
    let root_hash_2 = akd
        .get_root_hash(&akd.retrieve_current_azks().await?)
        .await?;

    // Make the current azks a "checkpoint" to reset to later
    let checkpoint_azks = akd.retrieve_current_azks().await.unwrap();

    // Publish for the third time
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_3"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2_3"),
        ),
    ])
    .await?;

    // Reset the azks record back to previous epoch, to emulate an akd reader
    // communicating with storage that is in the middle of a publish operation
    db.set(DbRecord::Azks(checkpoint_azks))
        .await
        .expect("Error resetting directory to previous epoch");

    // History proof should not contain the third epoch's update but still verify
    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    let (root_hashes, _) = get_key_history_hashes(&akd, &history_proof).await?;
    assert_eq!(2, root_hashes.len());
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash(&current_azks).await?;
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        false,
    )?;

    // Lookup proof should contain the checkpoint epoch's value and still verify
    let lookup_proof = akd.lookup(AkdLabel::from_utf8_str("hello")).await?;
    assert_eq!(
        AkdValue::from_utf8_str("world_2"),
        lookup_proof.plaintext_value
    );
    lookup_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        AkdLabel::from_utf8_str("hello"),
        lookup_proof,
    )?;

    // Audit proof should only work up until checkpoint's epoch
    let audit_proof = akd.audit(1, 2).await?;
    audit_verify::<Blake3>(vec![root_hash_1, root_hash_2], audit_proof).await?;

    let invalid_audit = akd.audit(2, 3).await;
    assert!(matches!(invalid_audit, Err(_)));

    Ok(())
}

// The read-only mode of a directory is meant to simply read from memory.
// This test makes sure it throws errors appropriately, i.e. when trying to
// write to a read-only directory and when trying to read a directory when none
// exists in storage.
#[tokio::test]
async fn test_directory_read_only_mode() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    // There is no AZKS object in the storage layer, directory construction should fail
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, true).await;
    assert!(matches!(akd, Err(_)));

    // now create the AZKS
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await;
    assert!(matches!(akd, Ok(_)));

    // create another read-only dir now that the AZKS exists in the storage layer, and try to publish which should fail
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, true).await?;
    assert!(matches!(akd.publish(vec![]).await, Err(_)));

    Ok(())
}

// This test is meant to test the function poll_for_azks_change
// which is meant to detect changes in the azks, to prevent inconsistencies
// between the local cache and storage.
#[tokio::test]
async fn test_directory_polling_azks_change() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    // writer will write the AZKS record
    let writer = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;

    writer
        .publish(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

    // reader will not write the AZKS but will be "polling" for AZKS changes
    let reader = Directory::<_, _, Blake3>::new(&storage, &vrf, true).await?;

    // start the poller
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    let reader_clone = reader.clone();
    let _join_handle = tokio::task::spawn(async move {
        reader_clone
            .poll_for_azks_changes(tokio::time::Duration::from_millis(100), Some(tx))
            .await
    });

    // verify a lookup proof, which will populate the cache
    async_poll_helper_proof(&reader, AkdValue::from_utf8_str("world")).await?;

    // publish epoch 2
    writer
        .publish(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world_2"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2_2"),
            ),
        ])
        .await?;

    // assert that the change is picked up in a reasonable time-frame and the cache is flushed
    let notification = tokio::time::timeout(tokio::time::Duration::from_secs(10), rx.recv()).await;
    assert!(matches!(notification, Ok(Some(()))));

    async_poll_helper_proof(&reader, AkdValue::from_utf8_str("world_2")).await?;

    Ok(())
}

// This test is testing the limited_key_history function,
// which takes a parameter n and gets the history for the
// n most recent updates.
// We also want this update to verify.
#[tokio::test]
async fn test_limited_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;

    // epoch 1
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;

    // epoch 2
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_2"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world2_2"),
        ),
    ])
    .await?;

    // epoch 3
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world3"),
        ),
        (
            AkdLabel::from_utf8_str("hello2"),
            AkdValue::from_utf8_str("world4"),
        ),
    ])
    .await?;

    // epoch 4
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello3"),
            AkdValue::from_utf8_str("world"),
        ),
        (
            AkdLabel::from_utf8_str("hello4"),
            AkdValue::from_utf8_str("world2"),
        ),
    ])
    .await?;

    // epoch 5
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world_updated"),
    )])
    .await?;

    // epoch 6
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello3"),
            AkdValue::from_utf8_str("world6"),
        ),
        (
            AkdLabel::from_utf8_str("hello4"),
            AkdValue::from_utf8_str("world12"),
        ),
    ])
    .await?;

    // epoch 7
    akd.publish(vec![
        (
            AkdLabel::from_utf8_str("hello3"),
            AkdValue::from_utf8_str("world7"),
        ),
        (
            AkdLabel::from_utf8_str("hello4"),
            AkdValue::from_utf8_str("world13"),
        ),
    ])
    .await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;

    // "hello" was updated in epochs 1,2,3,5. Pull the latest item from the history (i.e. a lookup proof)
    let history_proof = akd
        .limited_key_history(1, &AkdLabel::from_utf8_str("hello"))
        .await?;
    assert_eq!(1, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);

    // Get the current epoch and the current root hash for this akd.
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash(&current_azks).await?;

    // Now check that the key history verifies
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        false,
    )?;

    // Take the top 3 results, and check that we're getting the right epoch updates
    let history_proof = akd
        .limited_key_history(3, &AkdLabel::from_utf8_str("hello"))
        .await?;
    assert_eq!(3, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);
    assert_eq!(3, history_proof.update_proofs[1].epoch);
    assert_eq!(2, history_proof.update_proofs[2].epoch);

    // Now check that the key history verifies
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        false,
    )?;

    Ok(())
}

#[tokio::test]
async fn test_tombstoned_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;

    // epoch 1
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world"),
    )])
    .await?;

    // epoch 2
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world2"),
    )])
    .await?;

    // epoch 3
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world3"),
    )])
    .await?;

    // epoch 4
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world4"),
    )])
    .await?;

    // epoch 5
    akd.publish(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world5"),
    )])
    .await?;

    // Epochs 1-5, we're going to tombstone 1 & 2

    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;

    // tombstone epochs 1 & 2
    let tombstones = [
        crate::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 1u64),
        crate::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 2u64),
    ];
    db.tombstone_value_states(&tombstones).await?;

    // Now get a history proof for this key
    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    assert_eq!(5, history_proof.update_proofs.len());

    // Get the current epoch and the current root hash for this akd.
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash(&current_azks).await?;
    // If we request a proof with tombstones but without saying we're OK with tombstones, throw an err
    let tombstones = key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof.clone(),
        false,
    );
    assert!(matches!(tombstones, Err(_)));

    // We should be able to verify tombstones assuming the client is accepting
    // of tombstoned states
    let tombstones = key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        true,
    )?;
    assert_eq!(false, tombstones[0]);
    assert_eq!(false, tombstones[1]);
    assert_eq!(false, tombstones[2]);
    assert_eq!(true, tombstones[3]);
    assert_eq!(true, tombstones[4]);

    Ok(())
}

// Test coverage on issue #144, verification failures with
// small trees (<4 nodes) in both the tests below
// Note that the use of a VRF means that that the label
// depends on the hash function being used.
// The below two tests are identical except for the hash function being used.

// Test lookup in a smaller tree with 2 leaves, using the Blake3 hash function.
#[tokio::test]
async fn test_simple_lookup_for_small_tree_blake() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _, Blake3>::new(&storage, &vrf, false).await?;

    // Create a set with 2 updates, (label, value) pairs
    // ("hello10", "hello10")
    // ("hello11", "hello11")
    let mut updates = vec![];
    for i in 0..1 {
        updates.push((
            AkdLabel(format!("hello1{}", i).as_bytes().to_vec()),
            AkdValue(format!("hello1{}", i).as_bytes().to_vec()),
        ));
    }
    // Publish the updates. Now the akd's epoch will be 1.
    akd.publish(updates).await?;

    // The label we will lookup is "hello10"
    let target_label = AkdLabel(format!("hello1{}", 0).as_bytes().to_vec());

    // retrieve the lookup proof
    let lookup_proof = akd.lookup(target_label.clone()).await?;

    // retrieve the root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash(&current_azks).await?;

    // Get the VRF public key
    let vrf_pk = vrf.get_vrf_public_key().await?;

    // perform the "traditional" AKD verification
    let akd_result = crate::client::lookup_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        target_label.clone(),
        lookup_proof,
    );

    // check the two results to make sure they both verify
    assert!(matches!(akd_result, Ok(())));

    Ok(())
}

// Test lookup in a smaller tree with 2 leaves, using the Sha3 hash function.
#[tokio::test]
async fn test_simple_lookup_for_small_tree_sha256() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(&db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _, Sha3>::new(&storage, &vrf, false).await?;

    // Create a set with 2 updates, (label, value) pairs
    // ("hello10", "hello10")
    // ("hello11", "hello11")
    let mut updates = vec![];
    for i in 0..1 {
        updates.push((
            AkdLabel(format!("hello{}", i).as_bytes().to_vec()),
            AkdValue(format!("hello{}", i).as_bytes().to_vec()),
        ));
    }

    // Publish the updates. Now the akd's epoch will be 1.
    akd.publish(updates).await?;

    // The label we will lookup is "hello10"
    let target_label = AkdLabel(format!("hello{}", 0).as_bytes().to_vec());

    // retrieve the lookup proof
    let lookup_proof = akd.lookup(target_label.clone()).await?;
    // retrieve the root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash(&current_azks).await?;

    // Get the VRF public key
    let vrf_pk = vrf.get_vrf_public_key().await?;

    // perform the "traditional" AKD verification
    let akd_result =
        crate::client::lookup_verify(&vrf_pk, root_hash, target_label.clone(), lookup_proof);

    // check the two results to make sure they both verify
    assert!(matches!(akd_result, Ok(())), "{:?}", akd_result);

    Ok(())
}

/*
=========== Test Helpers ===========
*/

async fn async_poll_helper_proof<T: Storage + Sync + Send, V: VRFKeyStorage, H: Hasher>(
    reader: &Directory<T, V, H>,
    value: AkdValue,
) -> Result<(), AkdError> {
    // reader should read "hello" and this will populate the "cache" a log
    let lookup_proof = reader.lookup(AkdLabel::from_utf8_str("hello")).await?;
    assert_eq!(value, lookup_proof.plaintext_value);
    let current_azks = reader.retrieve_current_azks().await?;
    let root_hash = reader.get_root_hash(&current_azks).await?;
    let pk = reader.get_public_key().await?;
    lookup_verify(
        &pk,
        root_hash,
        AkdLabel::from_utf8_str("hello"),
        lookup_proof,
    )?;
    Ok(())
}
