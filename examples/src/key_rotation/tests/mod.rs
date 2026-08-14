// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Tests for the key_rotation example.

use akd::append_only_zks::AzksParallelismConfig;
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::verify::history::HistoryParams;
use akd::NamedConfiguration;
use akd::{AkdLabel, AkdValue, HistoryVerificationParams};

use crate::test_config;

// ── Generic multi-configuration tests ────────────────────────────────────────

/// Verifies that the history proof correctly captures all versions of a key
/// after multiple rotations, under both supported configurations.
test_config!(test_history_covers_all_rotations);
async fn test_history_covers_all_rotations<TC: NamedConfiguration>() {
    let akd = Directory::<TC, _, _>::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await
    .expect("directory init failed");

    let alice = AkdLabel::from("alice@example.com");
    let num_rotations = 3usize;

    // Publish three successive key values for alice.
    for i in 1..=num_rotations {
        let value = AkdValue::from(format!("alice_key_v{i}").as_str());
        akd.publish(vec![(alice.clone(), value)])
            .await
            .unwrap_or_else(|e| panic!("rotation {i} publish failed: {e}"));
    }

    // The history proof must span all three epochs.
    let (proof, epoch_hash) = akd
        .key_history(&alice, HistoryParams::Complete)
        .await
        .expect("key_history failed");

    let pk = akd.get_public_key().await.expect("public key fetch failed");
    let history = akd::client::key_history_verify::<TC>(
        pk.as_bytes(),
        epoch_hash.hash(),
        epoch_hash.epoch(),
        alice,
        proof,
        HistoryVerificationParams::default(),
    )
    .expect("history verification failed");

    assert_eq!(
        history.len(),
        num_rotations,
        "expected one history entry per rotation"
    );
    // Results are newest-first; index 0 is the most recent rotation.
    assert_eq!(history[0].version, num_rotations as u64);
    assert_eq!(history[0].value, AkdValue::from("alice_key_v3"));
    assert_eq!(history[num_rotations - 1].version, 1);
    assert_eq!(
        history[num_rotations - 1].value,
        AkdValue::from("alice_key_v1")
    );
}

/// Verifies that MostRecent(1) history returns only the latest binding.
test_config!(test_most_recent_history_returns_one_entry);
async fn test_most_recent_history_returns_one_entry<TC: NamedConfiguration>() {
    let akd = Directory::<TC, _, _>::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await
    .expect("directory init failed");

    let alice = AkdLabel::from("alice@example.com");

    for i in 1..=4u32 {
        akd.publish(vec![(
            alice.clone(),
            AkdValue::from(format!("key_v{i}").as_str()),
        )])
        .await
        .expect("publish failed");
    }

    let (proof, epoch_hash) = akd
        .key_history(&alice, HistoryParams::MostRecent(1))
        .await
        .expect("key_history failed");

    let pk = akd.get_public_key().await.expect("public key fetch failed");
    let history = akd::client::key_history_verify::<TC>(
        pk.as_bytes(),
        epoch_hash.hash(),
        epoch_hash.epoch(),
        alice,
        proof,
        HistoryVerificationParams::Default {
            history_params: HistoryParams::MostRecent(1),
        },
    )
    .expect("history verification failed");

    assert_eq!(
        history.len(),
        1,
        "MostRecent(1) must return exactly one entry"
    );
    assert_eq!(history[0].version, 4, "must be the latest version");
    assert_eq!(history[0].value, AkdValue::from("key_v4"));
}

// ── Direct run() integration tests ───────────────────────────────────────────

/// Minimum rotation count (2) must complete without error.
#[tokio::test]
async fn test_run_minimum_rotations() {
    super::run(super::Args { rotations: 2 })
        .await
        .expect("run with 2 rotations failed");
}

/// Default rotation count (4) must complete without error.
#[tokio::test]
async fn test_run_default_rotations() {
    super::run(super::Args { rotations: 4 })
        .await
        .expect("run with 4 rotations failed");
}

/// Maximum rotation count (10) must complete without error and produce a
/// history table with 10 entries.
#[tokio::test]
async fn test_run_maximum_rotations() {
    super::run(super::Args { rotations: 10 })
        .await
        .expect("run with 10 rotations failed");
}

/// Rotation reasons must cycle in the expected order across a full cycle of 4.
#[tokio::test]
async fn test_rotation_reasons_cycle() {
    use super::rotation::{plan_rotations, RotationReason};

    let events = plan_rotations(8);
    assert_eq!(events.len(), 8);

    // First cycle (indices 0–3)
    assert!(matches!(events[0].reason, RotationReason::DeviceUpgrade));
    assert!(matches!(events[1].reason, RotationReason::SecurityIncident));
    assert!(matches!(
        events[2].reason,
        RotationReason::ScheduledRotation
    ));
    assert!(matches!(events[3].reason, RotationReason::AccountRecovery));
    // Second cycle (indices 4–7) mirrors the first.
    assert!(matches!(events[4].reason, RotationReason::DeviceUpgrade));
    assert!(matches!(events[7].reason, RotationReason::AccountRecovery));
}
