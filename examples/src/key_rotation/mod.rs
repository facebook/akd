// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Demonstrates multi-epoch key rotation and history proof verification.
//!
//! A key-transparency system must let clients audit the *complete history* of
//! public keys for any account — not just the current one. This example simulates
//! a user (alice) rotating her key multiple times for different reasons, then
//! requests a HistoryProof spanning all versions and verifies that the full
//! chronological chain matches what was originally published.
//!
//! Module layout:
//!   rotation.rs — rotation event types, planning, and epoch publishing
//!   history.rs  — history proof request and client-side verification
//!   report.rs   — formatted output tables for the rotation log and history
//!
//! Run with:
//!   cargo run -p examples -- key-rotation
//!   cargo run -p examples -- key-rotation --rotations 6

mod history;
mod report;
mod rotation;

use akd::append_only_zks::AzksParallelismConfig;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::AkdLabel;
use anyhow::Result;
use clap::Parser;

/// Concrete directory type shared across this module's sub-files.
type AkdDir = akd::directory::Directory<
    akd::WhatsAppV1Configuration,
    AsyncInMemoryDatabase,
    HardCodedAkdVRF,
>;

#[derive(Parser, Debug, Clone)]
#[clap(
    author,
    about = "Simulate key rotations across multiple epochs and verify the complete history proof"
)]
pub(crate) struct Args {
    /// Number of key rotations to perform for alice (2–10).
    /// Each rotation is published as a new epoch with a distinct reason
    /// (device upgrade, security incident, scheduled rotation, account recovery).
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(2..=10))]
    rotations: u8,
}

pub(crate) async fn run(args: Args) -> Result<()> {
    let count = args.rotations as usize;

    // ── 1. Directory setup ───────────────────────────────────────────────────
    let akd = AkdDir::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await?;

    // Other users are also registered in epoch 1 to populate the tree so that
    // alice's proofs are non-trivial (i.e. the tree has more than one leaf).
    akd.publish(vec![
        (AkdLabel::from("bob@example.com"), akd::AkdValue::from("bob_key_v1")),
        (AkdLabel::from("carol@example.com"), akd::AkdValue::from("carol_key_v1")),
    ])
    .await?;

    let alice = AkdLabel::from("alice@example.com");
    println!("Directory initialised. Simulating {} key rotations for alice.\n", count);

    // ── 2. Plan and publish all rotations ────────────────────────────────────
    // Each rotation is modelled as a RotationEvent with a reason and a unique
    // key name. Applying the event calls publish() to advance the directory
    // to a new epoch.
    let events = rotation::plan_rotations(count);
    let mut published: Vec<rotation::PublishedRotation> = Vec::with_capacity(count);

    for event in events {
        let p = rotation::apply_rotation(&akd, &alice, event).await?;
        published.push(p);
    }

    report::print_rotation_log(&published);

    // ── 3. Request and verify the history proof ───────────────────────────────
    // The server generates a HistoryProof spanning all epochs in which alice's
    // label has a recorded value. The client verifies every version in one shot.
    let records = history::fetch_and_verify(&akd, &alice, &published).await?;

    report::print_history_table(&records);
    report::print_summary(count, records.len());

    Ok(())
}
