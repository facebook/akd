// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Demonstrates the auditor role: verifying that a directory evolved in an
//! append-only manner across a configurable range of epochs.
//!
//! An AKD guarantees that entries can only be added or updated — never silently
//! removed. An independent auditor enforces this by archiving the root hash
//! published at each epoch and periodically requesting an AppendOnlyProof from
//! the server. If any entry was deleted or rewritten between two epochs the
//! server cannot produce a valid proof, and verification fails.
//!
//! Module layout:
//!   population.rs — epoch content definitions and publish logic (server side)
//!   archive.rs    — the auditor's independent hash archive
//!   audit.rs      — AppendOnlyProof request and verification
//!
//! Run with:
//!   cargo run -p examples -- append-only-audit
//!   cargo run -p examples -- append-only-audit --epochs 7

mod archive;
mod audit;
mod population;

use akd::append_only_zks::AzksParallelismConfig;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
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
    about = "Populate the directory over multiple epochs and verify append-only integrity as an auditor"
)]
pub(crate) struct Args {
    /// Number of epochs to publish before auditing (2–8).
    /// Each epoch adds new users or updates existing ones.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(2..=8))]
    epochs: u8,
}

pub(crate) async fn run(args: Args) -> Result<()> {
    let num_epochs = args.epochs as usize;

    // ── 1. Directory setup ───────────────────────────────────────────────────
    let akd = AkdDir::new(
        StorageManager::new_no_cache(AsyncInMemoryDatabase::new()),
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await?;

    println!(
        "Directory initialised. Publishing {} epochs of user-key data.\n",
        num_epochs
    );

    // ── 2. Publish epochs and build the auditor's archive ────────────────────
    // The auditor collects the root hash of every epoch it observes. These
    // hashes must come from a source independent of the server (e.g. a public
    // transparency log) so the server cannot forge them retroactively.
    let mut archive = archive::AuditorArchive::new();

    for epoch_idx in 0..num_epochs {
        let (epoch, root_hash, change_count) = population::publish_epoch(&akd, epoch_idx).await?;
        let description = population::describe_epoch(epoch_idx);
        archive.record(epoch, root_hash, change_count, description.clone());
        println!(
            "  Epoch {:>2} — {} change(s) — {} — root: {}",
            epoch,
            change_count,
            description,
            hex::encode(&root_hash[..8])
        );
    }

    // ── 3. Print the auditor's archive ───────────────────────────────────────
    archive.print_log();

    // ── 4. Request and verify the append-only proof ───────────────────────────
    let start_epoch = 1u64;
    let end_epoch = num_epochs as u64;

    let proof = audit::request_proof(&akd, start_epoch, end_epoch).await?;

    // The auditor supplies its archived hashes — not hashes from the server —
    // so the verification is independent of the party being audited.
    let hashes = archive.range_hashes(start_epoch, end_epoch);
    audit::verify_proof(hashes, proof).await?;
    audit::print_result(start_epoch, end_epoch, num_epochs);

    Ok(())
}
