// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Tests for the basic_lookup example.
//!
//! `test_config!` generates two variants of each generic test — one for
//! `WhatsAppV1Configuration` and one for `ExperimentalConfiguration` — matching
//! the project-wide convention for configuration coverage.

use akd::append_only_zks::AzksParallelismConfig;
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::NamedConfiguration;
use akd::{AkdLabel, AkdValue};

use crate::test_config;

// ── Generic multi-configuration tests ────────────────────────────────────────

/// Verifies the full publish → lookup → verify cycle works correctly under both
/// supported configurations.
test_config!(test_publish_lookup_verify);
async fn test_publish_lookup_verify<TC: NamedConfiguration>() {
    let akd = Directory::<TC, _, _>::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await
    .expect("directory init failed");

    // Publish two entries in a single epoch.
    let entries = vec![
        (
            AkdLabel::from("alice@example.com"),
            AkdValue::from("alice_public_key_v1"),
        ),
        (
            AkdLabel::from("bob@example.com"),
            AkdValue::from("bob_public_key_v1"),
        ),
    ];
    let epoch_hash = akd.publish(entries).await.expect("publish failed");
    assert_eq!(epoch_hash.epoch(), 1);

    // Generate and verify a lookup proof for alice.
    let label = AkdLabel::from("alice@example.com");
    let (proof, eh) = akd.lookup(label.clone()).await.expect("lookup failed");
    let pk = akd.get_public_key().await.expect("public key fetch failed");

    let result =
        akd::client::lookup_verify::<TC>(pk.as_bytes(), eh.hash(), eh.epoch(), label, proof)
            .expect("verification failed");

    assert_eq!(result.epoch, 1);
    assert_eq!(result.version, 1);
    assert_eq!(result.value, AkdValue::from("alice_public_key_v1"));
}

/// Verifies that a lookup proof for a user added in a later epoch references
/// the correct epoch number and version.
test_config!(test_lookup_reflects_correct_epoch);
async fn test_lookup_reflects_correct_epoch<TC: NamedConfiguration>() {
    let akd = Directory::<TC, _, _>::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await
    .expect("directory init failed");

    // Epoch 1: alice only.
    akd.publish(vec![(
        AkdLabel::from("alice@example.com"),
        AkdValue::from("alice_key_v1"),
    )])
    .await
    .expect("epoch 1 publish failed");

    // Epoch 2: bob joins.
    akd.publish(vec![(
        AkdLabel::from("bob@example.com"),
        AkdValue::from("bob_key_v1"),
    )])
    .await
    .expect("epoch 2 publish failed");

    // Bob's proof should reference epoch 2 (the epoch he was added in).
    let label = AkdLabel::from("bob@example.com");
    let (proof, eh) = akd.lookup(label.clone()).await.expect("lookup failed");
    let pk = akd.get_public_key().await.expect("public key fetch failed");

    let result =
        akd::client::lookup_verify::<TC>(pk.as_bytes(), eh.hash(), eh.epoch(), label, proof)
            .expect("verification failed");

    assert_eq!(result.epoch, 2, "bob was added in epoch 2");
    assert_eq!(result.version, 1);
    assert_eq!(result.value, AkdValue::from("bob_key_v1"));
}

// ── Direct run() integration tests ───────────────────────────────────────────

/// Running with default arguments (alice, 5 users) must succeed.
#[tokio::test]
async fn test_run_default_args() {
    super::run(super::Args {
        label: "alice@example.com".to_string(),
        users: 5,
    })
    .await
    .expect("run with default args failed");
}

/// Every label in the published pool must be individually verifiable.
#[tokio::test]
async fn test_run_each_label_in_pool() {
    let labels = [
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
        "dave@example.com",
        "erin@example.com",
    ];
    for label in labels {
        super::run(super::Args {
            label: label.to_string(),
            users: 5,
        })
        .await
        .unwrap_or_else(|e| panic!("run failed for label '{label}': {e}"));
    }
}

/// Requesting a label outside the published pool must return an error.
#[tokio::test]
async fn test_run_rejects_unpublished_label() {
    let result = super::run(super::Args {
        label: "nobody@example.com".to_string(),
        users: 3,
    })
    .await;
    assert!(result.is_err(), "expected error for unpublished label");
}

/// Publishing the maximum pool size (10 users) and looking up the last one.
#[tokio::test]
async fn test_run_max_pool() {
    super::run(super::Args {
        label: "judy@example.com".to_string(),
        users: 10,
    })
    .await
    .expect("run with max pool failed");
}
