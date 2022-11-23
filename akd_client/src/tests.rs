// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This crate contains the tests for the client library which make sure that the
//! base AKD library and this "lean" client result in the same outputs

use akd::ecvrf::HardCodedAkdVRF;

use akd::serialization::from_digest;
#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::vec;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;

use akd::errors::{AkdError, StorageError};
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue};
use winter_crypto::Hasher;

use crate::converters;
#[cfg(feature = "serde_serialization")]
use crate::VerificationError;
#[cfg(feature = "serde_serialization")]
use crate::VerificationErrorType;
#[cfg(test)]
use akd::directory::PublishCorruption;

// Feature specific test imports
#[cfg(feature = "blake3")]
type Hash = akd::Blake3;
#[cfg(feature = "sha3_256")]
type Hash = akd::Sha3;

type InMemoryDb = akd::storage::memory::AsyncInMemoryDatabase;
type Directory = akd::Directory<InMemoryDb, HardCodedAkdVRF, Hash>;

// ===================================
// Test helpers
// ===================================

/// Makes a JSON String unparsable by replacing "{"s with gibberish.
#[cfg(feature = "serde_serialization")]
fn make_unparsable_json(serialized_json: &str) -> String {
    serialized_json.replace('{', "t3845")
}

// ===================================
// Test cases
// ===================================

#[tokio::test]
async fn test_simple_lookup() -> Result<(), AkdError> {
    let database = InMemoryDb::new();
    let db = StorageManager::new_no_cache(&database);

    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new(&db, &vrf, false).await?;

    let mut updates = vec![];
    for i in 0..15 {
        updates.push((
            AkdLabel(format!("hello{}", i).as_bytes().to_vec()),
            AkdValue(format!("hello{}", i).as_bytes().to_vec()),
        ));
    }

    akd.publish(updates).await?;

    let target_label = AkdLabel(format!("hello{}", 10).as_bytes().to_vec());

    // retrieve the lookup proof
    let lookup_proof = akd.lookup(target_label.clone()).await?;
    // retrieve the root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash(&current_azks).await?;
    let vrf_pk = akd.get_public_key().await.unwrap();
    // create the "lean" lookup proof version
    let internal_lookup_proof = converters::convert_lookup_proof(&lookup_proof);

    // perform the "traditional" AKD verification
    let akd_result =
        akd::client::lookup_verify(&vrf_pk, root_hash, target_label.clone(), lookup_proof);

    let target_label_bytes = target_label.to_vec();
    #[cfg(not(feature = "serde_serialization"))]
    let lean_result = crate::verify::lookup_verify(
        &vrf_pk.to_bytes(),
        converters::to_digest::<Hash>(root_hash),
        target_label_bytes,
        internal_lookup_proof,
    )
    .map_err(|i_err| AkdError::Storage(StorageError::Other(format!("Internal: {:?}", i_err))));
    #[cfg(feature = "serde_serialization")]
    let lean_result = crate::verify::lookup_verify(
        &vrf_pk.to_bytes(),
        converters::to_digest::<Hash>(root_hash),
        target_label_bytes.clone(),
        internal_lookup_proof.clone(),
    )
    .map_err(|i_err| AkdError::Storage(StorageError::Other(format!("Internal: {:?}", i_err))));
    // check the two results to make sure they both verify
    assert!(
        matches!(akd_result, Ok(())),
        "AKD result was {:?}",
        akd_result
    );
    assert!(
        matches!(lean_result, Ok(())),
        "Lean result was {:?}",
        lean_result
    );
    #[cfg(feature = "serde_serialization")]
    {
        let serialized_internal_lookup_proof =
            crate::verify::serialize_lookup_proof(&internal_lookup_proof).unwrap();
        println!(
            "Serialized internal lookup proof: {:?}",
            serialized_internal_lookup_proof
        );
        // Check also the serialized proof verification result is the same.
        let serialized_lean_result = crate::verify::serialized_lookup_verify(
            &vrf_pk.to_bytes(),
            converters::to_digest::<Hash>(root_hash),
            target_label_bytes.clone(),
            &serialized_internal_lookup_proof,
        );
        assert!(
            serialized_lean_result.is_ok(),
            "Lean serialized result was {:?}",
            serialized_lean_result
        );

        // Fail parsing for a lookup proof.
        let serialized_internal_lookup_proof =
            make_unparsable_json(&serialized_internal_lookup_proof);
        let serialized_lean_result = crate::verify::serialized_lookup_verify(
            &vrf_pk.to_bytes(),
            converters::to_digest::<Hash>(root_hash),
            target_label_bytes,
            &serialized_internal_lookup_proof,
        );

        // Check deserialization failure.
        assert!(
            matches!(
                serialized_lean_result,
                Err(VerificationError {
                    error_message: _,
                    error_type: VerificationErrorType::ProofDeserializationFailed
                })
            ),
            "{:?}",
            serialized_lean_result
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_simple_lookup_for_small_tree() -> Result<(), AkdError> {
    let database = InMemoryDb::new();
    let db = StorageManager::new_no_cache(&database);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new(&db, &vrf, false).await?;

    let mut updates = vec![];
    for i in 0..1 {
        updates.push((
            AkdLabel(format!("hello{}", i).as_bytes().to_vec()),
            AkdValue(format!("hello{}", i).as_bytes().to_vec()),
        ));
    }

    akd.publish(updates).await?;

    let target_label = AkdLabel(format!("hello{}", 0).as_bytes().to_vec());

    // retrieve the lookup proof
    let lookup_proof = akd.lookup(target_label.clone()).await?;
    // retrieve the root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash(&current_azks).await?;

    // create the "lean" lookup proof version
    let internal_lookup_proof = converters::convert_lookup_proof(&lookup_proof);

    let vrf_pk = akd.get_public_key().await.unwrap();

    // perform the "traditional" AKD verification
    let akd_result =
        akd::client::lookup_verify(&vrf_pk, root_hash, target_label.clone(), lookup_proof);

    let target_label_bytes = target_label.to_vec();
    let lean_result = crate::verify::lookup_verify(
        &vrf_pk.to_bytes(),
        converters::to_digest::<Hash>(root_hash),
        target_label_bytes,
        internal_lookup_proof,
    )
    .map_err(|i_err| AkdError::Storage(StorageError::Other(format!("Internal: {:?}", i_err))));

    // check the two results to make sure they both verify
    assert!(
        matches!(akd_result, Ok(())),
        "AKD result was {:?}",
        akd_result
    );
    assert!(
        matches!(lean_result, Ok(())),
        "Lean result was {:?}",
        lean_result
    );

    Ok(())
}

#[tokio::test]
async fn test_history_proof_multiple_epochs() -> Result<(), AkdError> {
    let database = InMemoryDb::new();
    let db = StorageManager::new_no_cache(&database);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new(&db, &vrf, false).await?;
    let vrf_pk = akd.get_public_key().await.unwrap();
    let key = AkdLabel::from_utf8_str("label");
    let key_bytes = key.to_vec();
    const EPOCHS: usize = 10;

    // publishes key versions in multiple epochs
    for epoch in 1..=EPOCHS {
        let data = vec![(
            key.clone(),
            AkdValue(format!("value{}", epoch).as_bytes().to_vec()),
        )];
        akd.publish(data).await?;
    }

    // retrieves and verifies history proofs for the key
    let proof = akd.key_history(&key).await?;
    let internal_proof = converters::convert_history_proof(&proof);
    let (mut root_hash, current_epoch) =
        akd::directory::get_directory_root_hash_and_ep(&akd).await?;

    // verifies both traditional and lean history verification passes
    // in addition to the serialized history proof verification.
    {
        let akd_result = akd::client::key_history_verify(
            &vrf_pk,
            root_hash,
            current_epoch,
            key.clone(),
            proof.clone(),
            false,
        );
        let lean_result = crate::verify::key_history_verify(
            &vrf_pk.to_bytes(),
            from_digest::<Hash>(root_hash),
            current_epoch,
            key_bytes.clone(),
            internal_proof.clone(),
            false,
        );

        assert!(matches!(akd_result, Ok(_)), "{:?}", akd_result);
        assert!(matches!(lean_result, Ok(_)), "{:?}", lean_result);

        #[cfg(feature = "serde_serialization")]
        {
            let serialized_internal_history_proof =
                crate::verify::serialize_history_proof(&internal_proof).unwrap();
            println!(
                "Serialized internal history proof: {:?}",
                serialized_internal_history_proof
            );

            let serialized_lean_result = crate::verify::serialized_key_history_verify(
                &vrf_pk.to_bytes(),
                from_digest::<Hash>(root_hash),
                current_epoch,
                key_bytes.clone(),
                &serialized_internal_history_proof,
                false,
            );
            assert!(
                matches!(serialized_lean_result, Ok(_)),
                "{:?}",
                serialized_lean_result
            );

            // Fail parsing for a history proof.
            let serialized_internal_history_proof =
                make_unparsable_json(&serialized_internal_history_proof);
            let serialized_lean_result = crate::verify::serialized_key_history_verify(
                &vrf_pk.to_bytes(),
                from_digest::<Hash>(root_hash),
                current_epoch,
                key_bytes.clone(),
                &serialized_internal_history_proof,
                false,
            );
            // Check deserialization failure.
            assert!(
                matches!(
                    serialized_lean_result,
                    Err(VerificationError {
                        error_message: _,
                        error_type: VerificationErrorType::ProofDeserializationFailed
                    })
                ),
                "{:?}",
                serialized_lean_result
            );

            // performs "lean" serialized history verification
            let serialized_lean_result = crate::verify::serialized_key_history_verify(
                &vrf_pk.to_bytes(),
                from_digest::<Hash>(root_hash),
                current_epoch,
                key_bytes.clone(),
                &serialized_internal_history_proof,
                false,
            );

            assert!(
                serialized_lean_result.is_err(),
                "{:?}",
                serialized_lean_result
            );
        }
    }

    // corrupts the root hash and verifies both traditional and lean history verification fail
    {
        root_hash = Hash::hash(&[5u8; 32]);
        // performs traditional AKD verification
        let akd_result = akd::client::key_history_verify(
            &vrf_pk,
            root_hash,
            current_epoch,
            key.clone(),
            proof.clone(),
            false,
        );
        // performs "lean" history verification
        let lean_result = crate::verify::key_history_verify(
            &vrf_pk.to_bytes(),
            from_digest::<Hash>(root_hash),
            current_epoch,
            key_bytes.clone(),
            internal_proof.clone(),
            false,
        );
        assert!(akd_result.is_err(), "{:?}", akd_result);
        assert!(lean_result.is_err(), "{:?}", lean_result);
    }

    // history proof with updates of non-decreasing versions/epochs fail to verify
    let mut borked_proof = internal_proof.clone();
    borked_proof.update_proofs = borked_proof.update_proofs.into_iter().rev().collect();
    let lean_result = crate::verify::key_history_verify(
        &vrf_pk.to_bytes(),
        from_digest::<Hash>(root_hash),
        current_epoch,
        key_bytes,
        borked_proof,
        false,
    );
    assert!(matches!(lean_result, Err(_)), "{:?}", lean_result);

    Ok(())
}

#[tokio::test]
async fn test_history_proof_single_epoch() -> Result<(), AkdError> {
    let database = InMemoryDb::new();
    let db = StorageManager::new_no_cache(&database);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new(&db, &vrf, false).await?;
    let vrf_pk = akd.get_public_key().await.unwrap();
    let key = AkdLabel::from_utf8_str("label");
    let key_bytes = key.to_vec();

    // publishes single key-value
    akd.publish(vec![(key.clone(), AkdValue::from_utf8_str("value"))])
        .await?;

    // retrieves and verifies history proofs for the key
    let proof = akd.key_history(&key).await?;
    let internal_proof = converters::convert_history_proof(&proof);
    let (root_hash, current_epoch) = akd::directory::get_directory_root_hash_and_ep(&akd).await?;

    // verifies both traditional and lean history verification passes
    let akd_result =
        akd::client::key_history_verify(&vrf_pk, root_hash, current_epoch, key, proof, false);
    let lean_result = crate::verify::key_history_verify(
        &vrf_pk.to_bytes(),
        from_digest::<Hash>(root_hash),
        current_epoch,
        key_bytes,
        internal_proof,
        false,
    );
    assert!(matches!(akd_result, Ok(_)), "{:?}", akd_result);
    assert!(matches!(lean_result, Ok(_)), "{:?}", lean_result);
    Ok(())
}

#[tokio::test]
async fn test_tombstoned_key_history() -> Result<(), AkdError> {
    let database = InMemoryDb::new();
    let db = StorageManager::new_no_cache(&database);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::new(&db, &vrf, false).await?;

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
    let vrf_pk = akd.get_public_key().await?;

    // tombstone epochs 1 & 2
    let tombstones = [
        akd::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 1u64),
        akd::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 2u64),
    ];
    db.tombstone_value_states(&tombstones).await?;

    let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
    assert_eq!(5, history_proof.update_proofs.len());
    let (root_hash, current_epoch) = akd::directory::get_directory_root_hash_and_ep(&akd).await?;

    // If we request a proof with tombstones but without saying we're OK with tombstones, throw an err
    // check main client output
    let tombstones = akd::client::key_history_verify(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof.clone(),
        false,
    );
    assert!(matches!(tombstones, Err(_)));

    // check lean client output
    let internal_proof = converters::convert_history_proof(&history_proof);
    let tombstones = crate::verify::key_history_verify(
        &vrf_pk.to_bytes(),
        from_digest::<Hash>(root_hash),
        current_epoch,
        AkdLabel::from_utf8_str("hello").to_vec(),
        internal_proof,
        false,
    );
    assert!(matches!(tombstones, Err(_)));

    // We should be able to verify tombstones assuming the client is accepting
    // of tombstoned states
    // check main client output
    let tombstones = akd::client::key_history_verify(
        &vrf_pk,
        root_hash,
        current_epoch,
        AkdLabel::from_utf8_str("hello"),
        history_proof.clone(),
        true,
    )?;
    assert_eq!(false, tombstones[0]);
    assert_eq!(false, tombstones[1]);
    assert_eq!(false, tombstones[2]);
    assert_eq!(true, tombstones[3]);
    assert_eq!(true, tombstones[4]);

    // check lean client output
    let internal_proof = converters::convert_history_proof(&history_proof);
    let tombstones = crate::verify::key_history_verify(
        &vrf_pk.to_bytes(),
        from_digest::<Hash>(root_hash),
        current_epoch,
        AkdLabel::from_utf8_str("hello").to_vec(),
        internal_proof,
        true,
    )
    .map_err(|i_err| AkdError::Storage(StorageError::Other(format!("Internal: {:?}", i_err))))?;

    assert_eq!(false, tombstones[0]);
    assert_eq!(false, tombstones[1]);
    assert_eq!(false, tombstones[2]);
    assert_eq!(true, tombstones[3]);
    assert_eq!(true, tombstones[4]);

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
    let database = InMemoryDb::new();
    let db = StorageManager::new_no_cache(&database);
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new(&db, &vrf, false).await?;
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
    // check lean client output
    let internal_proof = converters::convert_history_proof::<Hash>(&key_history_proof);
    // Verify the key history proof: This should fail since the server did not mark the version 1 for
    // this username as stale, upon adding version 2.
    crate::verify::key_history_verify(
        &vrf_pk.to_bytes(),
        from_digest::<Hash>(root_hash),
        current_epoch,
        AkdLabel::from_utf8_str("hello").to_vec(),
        internal_proof,
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
    // check lean client output
    let internal_proof = converters::convert_history_proof::<Hash>(&key_history_proof);
    // Verify the key history proof: This should still fail, since the server added the version number too late.
    crate::verify::key_history_verify(
        &vrf_pk.to_bytes(),
        from_digest::<Hash>(root_hash),
        current_epoch,
        AkdLabel::from_utf8_str("hello").to_vec(),
        internal_proof,
        false,
    ).expect_err("The key history proof should fail here since the previous value was marked stale one epoch too late.");

    Ok(())
}
