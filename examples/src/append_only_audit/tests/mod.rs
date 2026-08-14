// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Tests for the append_only_audit example.

use akd::append_only_zks::AzksParallelismConfig;
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::hash::Digest;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::NamedConfiguration;
use akd::{AkdLabel, AkdValue, EpochHash};

use crate::test_config;

// ── Generic multi-configuration tests ────────────────────────────────────────

/// Verifies that an AppendOnlyProof generated for a two-epoch range is accepted
/// by `audit_verify` under both supported configurations.
test_config!(test_audit_proof_two_epochs);
async fn test_audit_proof_two_epochs<TC: NamedConfiguration>() {
    let akd = Directory::<TC, _, _>::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await
    .expect("directory init failed");

    // Epoch 1
    let EpochHash(e1, h1) = akd
        .publish(vec![
            (
                AkdLabel::from("alice@example.com"),
                AkdValue::from("alice_key_v1"),
            ),
            (
                AkdLabel::from("bob@example.com"),
                AkdValue::from("bob_key_v1"),
            ),
        ])
        .await
        .expect("epoch 1 publish failed");

    // Epoch 2: alice rotates, carol joins.
    let EpochHash(e2, h2) = akd
        .publish(vec![
            (
                AkdLabel::from("alice@example.com"),
                AkdValue::from("alice_key_v2"),
            ),
            (
                AkdLabel::from("carol@example.com"),
                AkdValue::from("carol_key_v1"),
            ),
        ])
        .await
        .expect("epoch 2 publish failed");

    assert_eq!(e1, 1);
    assert_eq!(e2, 2);

    let proof = akd
        .audit(e1, e2)
        .await
        .expect("audit proof generation failed");
    // audit_verify requires hashes in order: [h_start, ..., h_end]
    akd::auditor::audit_verify::<TC>(vec![h1, h2], proof)
        .await
        .expect("audit verification failed");
}

/// Verifies that a three-epoch audit proof is accepted after a sequence of
/// additions, updates, and new registrations.
test_config!(test_audit_proof_three_epochs);
async fn test_audit_proof_three_epochs<TC: NamedConfiguration>() {
    let akd = Directory::<TC, _, _>::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await
    .expect("directory init failed");

    let mut hashes: Vec<Digest> = Vec::new();

    let batches: &[&[(&str, &str)]] = &[
        &[
            ("u1@example.com", "u1_key_v1"),
            ("u2@example.com", "u2_key_v1"),
        ],
        &[
            ("u1@example.com", "u1_key_v2"),
            ("u3@example.com", "u3_key_v1"),
        ],
        &[
            ("u2@example.com", "u2_key_v2"),
            ("u4@example.com", "u4_key_v1"),
        ],
    ];

    for batch in batches {
        let entries: Vec<(AkdLabel, AkdValue)> = batch
            .iter()
            .map(|(l, v)| (AkdLabel::from(*l), AkdValue::from(*v)))
            .collect();
        let EpochHash(_, h) = akd.publish(entries).await.expect("publish failed");
        hashes.push(h);
    }

    let proof = akd
        .audit(1, 3)
        .await
        .expect("audit proof generation failed");
    akd::auditor::audit_verify::<TC>(hashes, proof)
        .await
        .expect("audit verification failed for three-epoch range");
}

// ── Direct run() integration tests ───────────────────────────────────────────

/// Minimum epoch count (2) must complete without error.
#[tokio::test]
async fn test_run_minimum_epochs() {
    super::run(super::Args { epochs: 2 })
        .await
        .expect("run with 2 epochs failed");
}

/// Default epoch count (4) must complete without error.
#[tokio::test]
async fn test_run_default_epochs() {
    super::run(super::Args { epochs: 4 })
        .await
        .expect("run with 4 epochs failed");
}

/// Maximum epoch count (8) must complete without error.
#[tokio::test]
async fn test_run_maximum_epochs() {
    super::run(super::Args { epochs: 8 })
        .await
        .expect("run with 8 epochs failed");
}

// ── AuditorArchive unit tests ─────────────────────────────────────────────────

/// Verifies that `range_hashes` returns the correct subset of the archive.
#[test]
fn test_archive_range_hashes() {
    use super::archive::AuditorArchive;

    let mut archive = AuditorArchive::new();
    let hashes: Vec<Digest> = (1u8..=5).map(|i| [i; 32]).collect();

    for (i, h) in hashes.iter().enumerate() {
        archive.record(i as u64 + 1, *h, 1, format!("epoch {}", i + 1));
    }

    // Full range
    let all = archive.range_hashes(1, 5);
    assert_eq!(all.len(), 5);
    assert_eq!(all[0], hashes[0]);
    assert_eq!(all[4], hashes[4]);

    // Partial range
    let partial = archive.range_hashes(2, 4);
    assert_eq!(partial.len(), 3);
    assert_eq!(partial[0], hashes[1]); // epoch 2
    assert_eq!(partial[2], hashes[3]); // epoch 4
}
