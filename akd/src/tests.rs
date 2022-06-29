#![cfg(test)]
// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the tests for the high-level API (directory, auditor, client)

use crate::{
    auditor::audit_verify,
    client::{key_history_verify, lookup_verify},
    directory::{get_key_history_hashes, Directory},
    ecvrf::{HardCodedAkdVRF, VRFKeyStorage},
    errors::AkdError,
    storage::{
        memory::AsyncInMemoryDatabase,
        types::{AkdLabel, AkdValue, DbRecord},
        Storage,
    },
};
use winter_crypto::{
    hashers::{Blake3_256, Sha3_256},
    Digest,
};
use winter_math::fields::f128::BaseElement;
type Blake3 = Blake3_256<BaseElement>;

#[tokio::test]
async fn test_empty_tree_root_hash() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await?;

    let current_azks = akd.retrieve_current_azks().await?;
    let hash = akd
        .get_root_hash::<Blake3_256<BaseElement>>(&current_azks)
        .await?;
    // Ensuring that the root hash of an empty tree is equal to the following constant
    assert_eq!(
        "f48ded419214732a2c610c1e280543744bab3c17aec33e444997fa2d8f79792a",
        hex::encode(hash.as_bytes())
    );
    Ok(())
}

#[tokio::test]
async fn test_simple_publish() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world"),
    )])
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_simple_lookup() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    akd.publish::<Blake3>(vec![
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

    let lookup_proof = akd.lookup(AkdLabel::from_utf8_str("hello")).await?;
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
    let vrf_pk = akd.get_public_key().await?;
    lookup_verify::<Blake3_256<BaseElement>>(
        &vrf_pk,
        root_hash,
        AkdLabel::from_utf8_str("hello"),
        lookup_proof,
    )?;
    Ok(())
}

// This test also covers #144
#[tokio::test]
async fn test_small_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world"),
    )])
    .await?;

    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world2"),
    )])
    .await?;

    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
    let vrf_pk = akd.get_public_key().await?;
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
async fn test_simple_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    akd.publish::<Blake3>(vec![
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

    akd.publish::<Blake3>(vec![
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

    akd.publish::<Blake3>(vec![
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

    akd.publish::<Blake3>(vec![
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

    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world_updated"),
    )])
    .await?;

    akd.publish::<Blake3>(vec![
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

    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
    let vrf_pk = akd.get_public_key().await?;
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        false,
    )?;

    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello2")).await?;
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello2"),
        history_proof,
        false,
    )?;

    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello3")).await?;

    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello3"),
        history_proof,
        false,
    )?;

    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello4")).await?;
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello4"),
        history_proof,
        false,
    )?;

    Ok(())
}

#[tokio::test]
async fn test_simple_audit() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    akd.publish::<Blake3>(vec![
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

    let root_hash_1 = akd
        .get_root_hash::<Blake3>(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish::<Blake3>(vec![
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

    let root_hash_2 = akd
        .get_root_hash::<Blake3>(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish::<Blake3>(vec![
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

    let root_hash_3 = akd
        .get_root_hash::<Blake3>(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish::<Blake3>(vec![
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

    let root_hash_4 = akd
        .get_root_hash::<Blake3>(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world_updated"),
    )])
    .await?;

    let root_hash_5 = akd
        .get_root_hash::<Blake3>(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish::<Blake3>(vec![
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

    let audit_proof_1 = akd.audit(1, 2).await?;

    audit_verify::<Blake3>(vec![root_hash_1, root_hash_2], audit_proof_1).await?;

    let audit_proof_2 = akd.audit(1, 3).await?;
    audit_verify::<Blake3>(vec![root_hash_1, root_hash_2, root_hash_3], audit_proof_2).await?;

    let audit_proof_3 = akd.audit(1, 4).await?;
    audit_verify::<Blake3>(
        vec![root_hash_1, root_hash_2, root_hash_3, root_hash_4],
        audit_proof_3,
    )
    .await?;

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

    let audit_proof_5 = akd.audit(2, 3).await?;
    audit_verify::<Blake3>(vec![root_hash_2, root_hash_3], audit_proof_5).await?;

    let audit_proof_6 = akd.audit(2, 4).await?;
    audit_verify::<Blake3>(vec![root_hash_2, root_hash_3, root_hash_4], audit_proof_6).await?;

    let invalid_audit = akd.audit::<Blake3>(3, 3).await;
    assert!(matches!(invalid_audit, Err(_)));

    let invalid_audit = akd.audit::<Blake3>(3, 2).await;
    assert!(matches!(invalid_audit, Err(_)));

    let invalid_audit = akd.audit::<Blake3>(6, 7).await;
    assert!(matches!(invalid_audit, Err(_)));

    Ok(())
}

// #[tokio::test]
#[allow(dead_code)]
async fn test_read_during_publish() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    // Publish twice
    akd.publish::<Blake3>(vec![
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

    let root_hash_1 = akd
        .get_root_hash::<Blake3>(&akd.retrieve_current_azks().await?)
        .await?;

    akd.publish::<Blake3>(vec![
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

    let root_hash_2 = akd
        .get_root_hash::<Blake3>(&akd.retrieve_current_azks().await?)
        .await?;

    // Make the current azks a "checkpoint" to reset to later
    let checkpoint_azks = akd.retrieve_current_azks().await.unwrap();

    // Publish for the third time
    akd.publish::<Blake3>(vec![
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
    let history_proof = akd
        .key_history::<Blake3>(&AkdLabel::from_utf8_str("hello"))
        .await?;
    let (root_hashes, _) = get_key_history_hashes(&akd, &history_proof).await?;
    assert_eq!(2, root_hashes.len());
    let vrf_pk = akd.get_public_key().await?;
    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
    key_history_verify::<Blake3>(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof,
        false,
    )?;

    // Lookup proof should contain the checkpoint epoch's value and still verify
    let lookup_proof = akd
        .lookup::<Blake3>(AkdLabel::from_utf8_str("hello"))
        .await?;
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

    let invalid_audit = akd.audit::<Blake3>(2, 3).await;
    assert!(matches!(invalid_audit, Err(_)));

    Ok(())
}

#[tokio::test]
async fn test_directory_read_only_mode() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    // There is no AZKS object in the storage layer, directory construction should fail
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, true).await;
    assert!(matches!(akd, Err(_)));

    // now create the AZKS
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await;
    assert!(matches!(akd, Ok(_)));

    // create another read-only dir now that the AZKS exists in the storage layer, and try to publish which should fail
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, true).await?;
    assert!(matches!(akd.publish::<Blake3>(vec![]).await, Err(_)));

    Ok(())
}

#[tokio::test]
async fn test_directory_polling_azks_change() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    // writer will write the AZKS record
    let writer = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    writer
        .publish::<Blake3>(vec![
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
    let reader = Directory::<_, _>::new::<Blake3>(&db, &vrf, true).await?;

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
        .publish::<Blake3>(vec![
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
async fn test_limited_key_history() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    // epoch 1
    akd.publish::<Blake3>(vec![
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
    akd.publish::<Blake3>(vec![
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
    akd.publish::<Blake3>(vec![
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
    akd.publish::<Blake3>(vec![
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
    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world_updated"),
    )])
    .await?;

    // epoch 6
    akd.publish::<Blake3>(vec![
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
    akd.publish::<Blake3>(vec![
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

    let vrf_pk = akd.get_public_key().await?;

    // "hello" was updated in epochs 1,2,3,5. Pull the latest item from the history (i.e. a lookup proof)
    let history_proof = akd
        .limited_key_history::<Blake3>(1, &AkdLabel::from_utf8_str("hello"))
        .await?;
    assert_eq!(1, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);

    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
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
        .limited_key_history::<Blake3>(3, &AkdLabel::from_utf8_str("hello"))
        .await?;
    assert_eq!(3, history_proof.update_proofs.len());
    assert_eq!(5, history_proof.update_proofs[0].epoch);
    assert_eq!(3, history_proof.update_proofs[1].epoch);
    assert_eq!(2, history_proof.update_proofs[2].epoch);

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
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    // epoch 1
    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world"),
    )])
    .await?;

    // epoch 2
    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world2"),
    )])
    .await?;

    // epoch 3
    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world3"),
    )])
    .await?;

    // epoch 4
    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world4"),
    )])
    .await?;

    // epoch 5
    akd.publish::<Blake3>(vec![(
        AkdLabel::from_utf8_str("hello"),
        AkdValue::from_utf8_str("world5"),
    )])
    .await?;

    // Epochs 1-5, we're going to tombstone 1 & 2
    let vrf_pk = akd.get_public_key().await?;

    // tombstone epochs 1 & 2
    let tombstones = [
        crate::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 1u64),
        crate::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 2u64),
    ];
    db.tombstone_value_states(&tombstones).await?;

    let history_proof = akd
        .key_history::<Blake3>(&AkdLabel::from_utf8_str("hello"))
        .await?;
    assert_eq!(5, history_proof.update_proofs.len());

    let current_azks = akd.retrieve_current_azks().await?;
    let current_epoch = current_azks.get_latest_epoch();
    let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
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

#[tokio::test]
async fn test_simple_lookup_for_small_tree_blake() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    let mut updates = vec![];
    for i in 0..1 {
        updates.push((
            AkdLabel(format!("hello1{}", i).as_bytes().to_vec()),
            AkdValue(format!("hello1{}", i).as_bytes().to_vec()),
        ));
    }

    akd.publish::<Blake3>(updates).await?;

    let target_label = AkdLabel(format!("hello1{}", 0).as_bytes().to_vec());

    // retrieve the lookup proof
    let lookup_proof = akd.lookup(target_label.clone()).await?;
    // retrieve the root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;

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

#[tokio::test]
async fn test_simple_lookup_for_small_tree_sha256() -> Result<(), AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<_, _>::new::<Sha3_256<BaseElement>>(&db, &vrf, false).await?;

    let mut updates = vec![];
    for i in 0..1 {
        updates.push((
            AkdLabel(format!("hello{}", i).as_bytes().to_vec()),
            AkdValue(format!("hello{}", i).as_bytes().to_vec()),
        ));
    }

    akd.publish::<Sha3_256<BaseElement>>(updates).await?;

    let target_label = AkdLabel(format!("hello{}", 0).as_bytes().to_vec());

    // retrieve the lookup proof
    let lookup_proof = akd.lookup(target_label.clone()).await?;
    // retrieve the root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd
        .get_root_hash::<Sha3_256<BaseElement>>(&current_azks)
        .await?;

    let vrf_pk = vrf.get_vrf_public_key().await?;

    // perform the "traditional" AKD verification
    let akd_result = crate::client::lookup_verify::<Sha3_256<BaseElement>>(
        &vrf_pk,
        root_hash,
        target_label.clone(),
        lookup_proof,
    );

    // check the two results to make sure they both verify
    assert!(matches!(akd_result, Ok(())), "{:?}", akd_result);

    Ok(())
}

/*
=========== Test Helpers ===========
*/

async fn async_poll_helper_proof<T: Storage + Sync + Send, V: VRFKeyStorage>(
    reader: &Directory<T, V>,
    value: AkdValue,
) -> Result<(), AkdError> {
    // reader should read "hello" and this will populate the "cache" a log
    let lookup_proof = reader.lookup(AkdLabel::from_utf8_str("hello")).await?;
    assert_eq!(value, lookup_proof.plaintext_value);
    let current_azks = reader.retrieve_current_azks().await?;
    let root_hash = reader.get_root_hash::<Blake3>(&current_azks).await?;
    let pk = reader.get_public_key().await?;
    lookup_verify::<Blake3>(
        &pk,
        root_hash,
        AkdLabel::from_utf8_str("hello"),
        lookup_proof,
    )?;
    Ok(())
}
