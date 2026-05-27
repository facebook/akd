// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! The auditor's independent hash archive.
//!
//! In a real deployment an auditor collects the root hash published at each
//! epoch from a source that is independent of the directory server — for example
//! a public transparency log, a certificate-transparency-like witness network,
//! or a gossip protocol among peers. The independence is what makes the audit
//! meaningful: if the auditor accepted hashes from the server itself, the server
//! could supply forged hashes that validate a tampered proof.
//!
//! `AuditorArchive` models this independent store. It holds one `EpochRecord`
//! per epoch and provides slice views used by `audit_verify`.

use akd::hash::Digest;

/// One entry in the auditor's archive, corresponding to a single epoch.
pub(super) struct EpochRecord {
    /// The epoch number assigned by the directory (1-based, monotonically increasing).
    pub(super) epoch: u64,
    /// The 256-bit root hash of the Merkle tree at this epoch.
    /// This is the cryptographic commitment the auditor obtained from its
    /// trusted source and will use to anchor the append-only proof.
    pub(super) root_hash: Digest,
    /// Number of (label, value) pairs committed in this epoch.
    pub(super) change_count: usize,
    /// Human-readable description of what changed (for display purposes only).
    pub(super) description: String,
}

/// The auditor's archive of epoch root hashes, collected independently from
/// the directory server over the lifetime of the directory.
pub(super) struct AuditorArchive {
    records: Vec<EpochRecord>,
}

impl AuditorArchive {
    pub(super) fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Records a newly observed epoch.
    pub(super) fn record(
        &mut self,
        epoch: u64,
        root_hash: Digest,
        change_count: usize,
        description: String,
    ) {
        self.records.push(EpochRecord {
            epoch,
            root_hash,
            change_count,
            description,
        });
    }

    /// Returns the root hashes for epochs in `[start_epoch, end_epoch]`
    /// in ascending epoch order. The caller passes this slice to `audit_verify`,
    /// which requires exactly `(end_epoch - start_epoch + 1)` hashes.
    pub(super) fn range_hashes(&self, start_epoch: u64, end_epoch: u64) -> Vec<Digest> {
        self.records
            .iter()
            .filter(|r| r.epoch >= start_epoch && r.epoch <= end_epoch)
            .map(|r| r.root_hash)
            .collect()
    }

    /// Prints a tabular view of the archive to stdout.
    pub(super) fn print_log(&self) {
        println!("\n── Auditor's hash archive ────────────────────────────────────────");
        println!(
            "{:<8} {:<10} {:<32} {:<24}",
            "Epoch", "Changes", "Root hash (first 16 hex)", "Description"
        );
        println!("{}", "─".repeat(80));
        for r in &self.records {
            println!(
                "{:<8} {:<10} {:<32} {}",
                r.epoch,
                r.change_count,
                hex::encode(&r.root_hash[..8]),
                r.description,
            );
        }
        println!();
    }
}
