#![cfg(test)]
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the tests for the high-level API (directory, auditor, client)

use std::collections::HashMap;

use crate::{
    auditor::audit_verify,
    client::{key_history_verify, lookup_verify},
    directory::{Directory, PublishCorruption},
    ecvrf::{HardCodedAkdVRF, VRFKeyStorage},
    errors::{AkdError, StorageError},
    storage::{
        manager::StorageManager,
        memory::AsyncInMemoryDatabase,
        types::{DbRecord, KeyData, ValueState, ValueStateRetrievalFlag},
        Database, DbSetState, Storable,
    },
    tree_node::TreeNodeWithPreviousValue,
    AkdLabel, AkdValue, Azks, HistoryParams, HistoryVerificationParams, VerifyResult,
};

#[derive(Clone)]
pub struct LocalDatabase;

unsafe impl Send for LocalDatabase {}
unsafe impl Sync for LocalDatabase {}

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

    let tmp_db = test_db.clone();
    db.expect_batch_get::<Azks>()
        .returning(move |key| futures::executor::block_on(tmp_db.batch_get::<Azks>(key)));

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

// A simple test to ensure that the empty tree hashes to the correct value
#[tokio::test]
async fn test_empty_tree_root_hash() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;

    let current_azks = akd.retrieve_current_azks().await?;
    #[allow(unused)]
    let hash = akd.get_root_hash(&current_azks).await?;
    // Ensuring that the root hash of an empty tree is equal to the following constant
    #[cfg(feature = "blake3")]
    assert_eq!(
        "f48ded419214732a2c610c1e280543744bab3c17aec33e444997fa2d8f79792a",
        hex::encode(hash)
    );
    #[cfg(feature = "sha256")]
    assert_eq!(
        "e60055537d90faaccb2be51f744b9b4a759ff758c1fe1f361d773294dae4f03f",
        hex::encode(hash)
    );
    #[cfg(feature = "sha512")]
    assert_eq!(
        "720a0846fab801639e172ebe779c3212e9c1802e9fc94454a66285ed168db950c79bb1085fd72b076736412a06a7de37b861ace95317e5dd3a42e7d1fe3ee97d",
        hex::encode(hash)
    );
    #[cfg(feature = "sha512_256")]
    assert_eq!(
        "eb9c26cb7d83343bb5b5549ea7206278f8a41ed565edf6e22de828cb89bbf68b",
        hex::encode(hash)
    );
    #[cfg(feature = "sha3_256")]
    assert_eq!(
        "fb0fac36b999155471cd9f5b075685a04bf345b82e248242ee3b396d9d001845",
        hex::encode(hash)
    );
    #[cfg(feature = "sha3_512")]
    assert_eq!(
        "09db818bf21f53f5443011d4e17d58f011fd64aaacb52ef484102e03ecd3bc6d47b2152dd8404e6e80d1052156635370621c08792b85373e810346948ac7632a",
        hex::encode(hash)
    );

    #[cfg(not(any(
        feature = "blake3",
        feature = "sha256",
        feature = "sha3_256",
        feature = "sha512",
        feature = "sha3_512",
        feature = "sha512_256"
    )))]
    panic!("Unsupported hashing function");

    #[allow(unreachable_code)]
    Ok(())
}

// A simple publish test to make sure a publish doesn't throw an error.
#[tokio::test]
async fn test_simple_publish() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;
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
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;
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
    let (lookup_proof, root_hash) = akd.lookup(AkdLabel::from_utf8_str("hello")).await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the lookup proof
    lookup_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
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
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;
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
    let (key_history_proof, root_hash) = akd
        .key_history(&AkdLabel::from_utf8_str("hello"), HistoryParams::default())
        .await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof
    let result = key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    assert_eq!(
        result,
        vec![
            VerifyResult {
                epoch: 2,
                version: 2,
                value: AkdValue::from_utf8_str("world2"),
            },
            VerifyResult {
                epoch: 1,
                version: 1,
                value: AkdValue::from_utf8_str("world"),
            },
        ]
    );

    Ok(())
}

// Checks history proof for labels with differing numbers of updates.
// Note that this test only performs some basic validation on the proofs and
// checks that the valid proofs verify. It doesn't do much more.
#[tokio::test]
async fn test_simple_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;
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
    let (key_history_proof, _) = akd
        .key_history(&AkdLabel::from_utf8_str("hello"), HistoryParams::default())
        .await?;
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
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    // Key history proof for "hello2"
    let (key_history_proof, _) = akd
        .key_history(&AkdLabel::from_utf8_str("hello2"), HistoryParams::default())
        .await?;
    // Check that the correct number of proofs are sent
    if key_history_proof.update_proofs.len() != 3 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 3 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello2"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    // Key history proof for "hello3"
    let (key_history_proof, _) = akd
        .key_history(&AkdLabel::from_utf8_str("hello3"), HistoryParams::default())
        .await?;
    // Check that the correct number of proofs are sent
    if key_history_proof.update_proofs.len() != 2 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 2 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello3"),
        key_history_proof,
        HistoryVerificationParams::default(),
    )?;

    // Key history proof for "hello4"
    let (key_history_proof, _) = akd
        .key_history(&AkdLabel::from_utf8_str("hello4"), HistoryParams::default())
        .await?;
    // Check that the correct number of proofs are sent
    if key_history_proof.update_proofs.len() != 2 {
        return Err(AkdError::TestErr(format!(
            "Key history proof should have 2 update_proofs but has {:?}",
            key_history_proof.update_proofs.len()
        )));
    }
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello4"),
        key_history_proof.clone(),
        HistoryVerificationParams::default(),
    )?;

    // history proof with updates of non-decreasing versions/epochs fail to verify
    let mut borked_proof = key_history_proof;
    borked_proof.update_proofs = borked_proof.update_proofs.into_iter().rev().collect();
    let result = key_history_verify(
        vrf_pk.as_bytes(),
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello4"),
        borked_proof,
        HistoryVerificationParams::default(),
    );
    assert!(matches!(result, Err(_)), "{:?}", result);

    Ok(())
}

// This test will publish many versions for a small set of users, each with varying frequencies of publish rate, and
// test the validity of lookup, key history, and audit proofs
#[tokio::test]
async fn test_complex_verification_many_versions() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new(storage_manager, vrf, false).await?;
    let vrf_pk = akd.get_public_key().await?;

    let num_labels = 4;
    let num_iterations = 20;
    let mut previous_hash = [0u8; crate::DIGEST_BYTES];
    for epoch in 1..num_iterations {
        let mut to_insert = vec![];
        for i in 0..num_labels {
            let index = 1 << i;
            let label = AkdLabel::from_utf8_str(format!("{index}").as_str());
            let value = AkdValue::from_utf8_str(format!("{index},{epoch}").as_str());
            if epoch % index == 0 {
                to_insert.push((label, value));
            }
        }
        let epoch_hash = akd.publish(to_insert).await?;

        if epoch > 1 {
            let audit_proof = akd
                .audit(epoch_hash.epoch() - 1, epoch_hash.epoch())
                .await?;
            crate::auditor::audit_verify(vec![previous_hash, epoch_hash.hash()], audit_proof)
                .await?;
        }

        previous_hash = epoch_hash.hash();

        for i in 0..num_labels {
            let index = 1 << i;
            if epoch < index {
                // Cannot produce proofs if there are no versions added yet for that user
                continue;
            }
            let latest_added_epoch = epoch_hash.epoch() - (epoch_hash.epoch() % index);
            let label = AkdLabel::from_utf8_str(format!("{index}").as_str());
            let lookup_value =
                AkdValue::from_utf8_str(format!("{index},{latest_added_epoch}").as_str());

            let (lookup_proof, epoch_hash_from_lookup) = akd.lookup(label.clone()).await?;
            assert_eq!(epoch_hash, epoch_hash_from_lookup);
            let lookup_verify_result = lookup_verify(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                label.clone(),
                lookup_proof,
            )?;
            assert_eq!(lookup_verify_result.epoch, latest_added_epoch);
            assert_eq!(lookup_verify_result.value, lookup_value);
            assert_eq!(lookup_verify_result.version, epoch / index);

            let (history_proof, epoch_hash_from_history) =
                akd.key_history(&label, HistoryParams::Complete).await?;
            assert_eq!(epoch_hash, epoch_hash_from_history);
            let history_results = key_history_verify(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                epoch_hash.epoch(),
                label,
                history_proof,
                HistoryVerificationParams::default(),
            )?;
            for (j, res) in history_results.iter().enumerate() {
                let added_in_epoch =
                    epoch_hash.epoch() - (epoch_hash.epoch() % index) - (j as u64) * index;
                let history_value =
                    AkdValue::from_utf8_str(format!("{index},{added_in_epoch}").as_str());
                assert_eq!(res.epoch, added_in_epoch);
                assert_eq!(res.value, history_value);
                assert_eq!(res.version, epoch / index - j as u64);
            }
        }
    }

    Ok(())
}

// This test is testing the key_history function with a limited history.
// We also want this update to verify.
#[tokio::test]
async fn test_limited_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new(storage_manager, vrf, false).await?;

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

    // Get the current epoch and the current root hash for this akd.
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();

    // "hello" was updated in epochs 1,2,3,5. Pull the latest item from the history (i.e. a lookup proof)
    let (history_proof, root_hash) = akd
        .key_history(
            &AkdLabel::from_utf8_str("hello"),
            HistoryParams::MostRecent(1),
        )
        .await?;
    assert_eq!(1, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);

    // Now check that the key history verifies
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        HistoryVerificationParams::default(),
    )?;

    // Take the top 3 results, and check that we're getting the right epoch updates
    let (history_proof, root_hash) = akd
        .key_history(
            &AkdLabel::from_utf8_str("hello"),
            HistoryParams::MostRecent(3),
        )
        .await?;
    assert_eq!(3, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);
    assert_eq!(3, history_proof.update_proofs[1].epoch);
    assert_eq!(2, history_proof.update_proofs[2].epoch);

    // Now check that the key history verifies
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        HistoryVerificationParams::default(),
    )?;

    // "hello" was updated in epochs 1,2,3,5. Pull the updates since epoch 3 (inclusive)
    let (history_proof, root_hash) = akd
        .key_history(
            &AkdLabel::from_utf8_str("hello"),
            HistoryParams::SinceEpoch(3),
        )
        .await?;
    assert_eq!(2, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);
    assert_eq!(3, history_proof.update_proofs[1].epoch);

    // Now check that the key history verifies
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        HistoryVerificationParams::default(),
    )?;

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
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;
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
    let (key_history_proof, root_hash) = akd
        .key_history(&AkdLabel::from_utf8_str("hello"), HistoryParams::default())
        .await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof: This should fail since the server did not mark the version 1 for
    // this username as stale, upon adding version 2.
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
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
    let (key_history_proof, root_hash) = akd
        .key_history(&AkdLabel::from_utf8_str("hello"), HistoryParams::default())
        .await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    // Verify the key history proof: This should still fail, since the server added the version number too late.
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from_utf8_str("hello"),
        key_history_proof,
        HistoryVerificationParams::default(),
    ).expect_err("The key history proof should fail here since the previous value was marked stale one epoch too late.");

    Ok(())
}

// This test ensures valid audit proofs pass for various epochs and
// that invalid audit proofs fail.
#[tokio::test]
async fn test_simple_audit() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;

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
    audit_verify(vec![root_hash_1, root_hash_2], audit_proof_1).await?;

    // This is to ensure that an audit of 3 consecutive epochs although not the most recent is calculated correctly.
    let audit_proof_2 = akd.audit(1, 3).await?;
    audit_verify(vec![root_hash_1, root_hash_2, root_hash_3], audit_proof_2).await?;

    // This is to ensure that an audit of 4 consecutive epochs is calculated correctly.
    let audit_proof_3 = akd.audit(1, 4).await?;
    audit_verify(
        vec![root_hash_1, root_hash_2, root_hash_3, root_hash_4],
        audit_proof_3,
    )
    .await?;

    // This is to ensure that an audit of 5 consecutive epochs is calculated correctly.
    let audit_proof_4 = akd.audit(1, 5).await?;
    audit_verify(
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
    audit_verify(vec![root_hash_2, root_hash_3], audit_proof_5).await?;

    // Test correct audit of 3 consecutive epochs but not starting at epoch 1.
    let audit_proof_6 = akd.audit(2, 4).await?;
    audit_verify(vec![root_hash_2, root_hash_3, root_hash_4], audit_proof_6).await?;

    // Test correct audit of 3 consecutive epochs ending at epoch 6 -- the last epoch
    let audit_proof_7 = akd.audit(4, 6).await?;
    audit_verify(vec![root_hash_4, root_hash_5, root_hash_6], audit_proof_7).await?;

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
    let storage = StorageManager::new_no_cache(db.clone());
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;

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
    let (history_proof, root_hash) = akd
        .key_history(&AkdLabel::from_utf8_str("hello"), HistoryParams::default())
        .await?;
    // Get the VRF public key
    let vrf_pk = akd.get_public_key().await?;
    key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        HistoryVerificationParams::default(),
    )?;

    // Lookup proof should contain the checkpoint epoch's value and still verify
    let (lookup_proof, root_hash) = akd.lookup(AkdLabel::from_utf8_str("hello")).await?;
    assert_eq!(AkdValue::from_utf8_str("world_2"), lookup_proof.value);
    lookup_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        AkdLabel::from_utf8_str("hello"),
        lookup_proof,
    )?;

    // Audit proof should only work up until checkpoint's epoch
    let audit_proof = akd.audit(1, 2).await?;
    audit_verify(vec![root_hash_1, root_hash_2], audit_proof).await?;

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
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // There is no AZKS object in the storage layer, directory construction should fail
    let akd = Directory::<_, _>::new(storage.clone(), vrf.clone(), true).await;
    assert!(matches!(akd, Err(_)));

    // now create the AZKS
    let akd = Directory::<_, _>::new(storage.clone(), vrf.clone(), false).await;
    assert!(matches!(akd, Ok(_)));

    // create another read-only dir now that the AZKS exists in the storage layer, and try to publish which should fail
    let akd = Directory::<_, _>::new(storage, vrf, true).await?;
    assert!(matches!(akd.publish(vec![]).await, Err(_)));

    Ok(())
}

// This test is meant to test the function poll_for_azks_change
// which is meant to detect changes in the azks, to prevent inconsistencies
// between the local cache and storage.
#[tokio::test]
async fn test_directory_polling_azks_change() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new(db, None, None, None);
    let vrf = HardCodedAkdVRF {};
    // writer will write the AZKS record
    let writer = Directory::<_, _>::new(storage.clone(), vrf.clone(), false).await?;

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
    let reader = Directory::<_, _>::new(storage, vrf, true).await?;

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

#[tokio::test]
async fn test_tombstoned_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new(storage.clone(), vrf, false).await?;

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
    storage.tombstone_value_states(&tombstones).await?;

    // Now get a history proof for this key
    let (history_proof, root_hash) = akd
        .key_history(&AkdLabel::from_utf8_str("hello"), HistoryParams::default())
        .await?;
    assert_eq!(5, history_proof.update_proofs.len());

    // If we request a proof with tombstones but without saying we're OK with tombstones, throw an err
    let tombstones = key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from_utf8_str("hello"),
        history_proof.clone(),
        HistoryVerificationParams::default(),
    );
    assert!(matches!(tombstones, Err(_)));

    // We should be able to verify tombstones assuming the client is accepting
    // of tombstoned states
    let results = key_history_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        root_hash.epoch(),
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        HistoryVerificationParams::AllowMissingValues,
    )?;
    assert_ne!(crate::TOMBSTONE, results[0].value.0);
    assert_ne!(crate::TOMBSTONE, results[1].value.0);
    assert_ne!(crate::TOMBSTONE, results[2].value.0);
    assert_eq!(crate::TOMBSTONE, results[3].value.0);
    assert_eq!(crate::TOMBSTONE, results[4].value.0);

    Ok(())
}

#[tokio::test]
async fn test_publish_op_makes_no_get_requests() {
    let test_db = AsyncInMemoryDatabase::new();

    let mut db = MockLocalDatabase {
        ..Default::default()
    };
    setup_mocked_db(&mut db, &test_db);

    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new(storage, vrf, false)
        .await
        .expect("Failed to create directory");

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
    let akd = Directory::<_, _>::new(storage, vrf, false)
        .await
        .expect("Failed to create directory");

    // create more updates
    let mut updates = vec![];
    for i in 0..1 {
        updates.push((
            AkdLabel(format!("hello1{}", i).as_bytes().to_vec()),
            AkdValue(format!("hello1{}", i + 1).as_bytes().to_vec()),
        ));
    }

    // try to publish again, this time with the "boom" returning from any mocked get-calls
    // on tree nodes
    akd.publish(updates)
        .await
        .expect("Failed to do subsequent publish");
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
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new(storage, vrf.clone(), false).await?;

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
    let (lookup_proof, root_hash) = akd.lookup(target_label.clone()).await?;

    // Get the VRF public key
    let vrf_pk = vrf.get_vrf_public_key().await?;

    // perform the "traditional" AKD verification
    let akd_result = crate::client::lookup_verify(
        vrf_pk.as_bytes(),
        root_hash.hash(),
        target_label.clone(),
        lookup_proof,
    )?;

    // check the two results to make sure they both verify
    assert_eq!(
        akd_result,
        VerifyResult {
            epoch: 1,
            version: 1,
            value: AkdValue::from_utf8_str("hello10"),
        },
    );

    Ok(())
}

// Test lookup in a smaller tree with 2 leaves, using the Sha3 hash function.
#[cfg(feature = "sha3_256")]
#[tokio::test]
async fn test_simple_lookup_for_small_tree_sha256() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new(storage, vrf, false).await?;

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
    let akd_result = crate::client::lookup_verify(
        vrf_pk.as_bytes(),
        root_hash,
        target_label.clone(),
        lookup_proof,
    )?;

    // check the two results to make sure they both verify
    assert_eq!(
        akd_result,
        VerifyResult {
            epoch: 1,
            version: 1,
            value: AkdValue::from_utf8_str("hello0"),
        },
    );

    Ok(())
}

/*
=========== Test Helpers ===========
*/

async fn async_poll_helper_proof<T: Database + 'static, V: VRFKeyStorage>(
    reader: &Directory<T, V>,
    value: AkdValue,
) -> Result<(), AkdError> {
    // reader should read "hello" and this will populate the "cache" a log
    let (lookup_proof, root_hash) = reader.lookup(AkdLabel::from_utf8_str("hello")).await?;
    assert_eq!(value, lookup_proof.value);
    let pk = reader.get_public_key().await?;
    lookup_verify(
        pk.as_bytes(),
        root_hash.hash(),
        AkdLabel::from_utf8_str("hello"),
        lookup_proof,
    )?;
    Ok(())
}
