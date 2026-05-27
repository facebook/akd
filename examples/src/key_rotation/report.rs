// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Formatted output tables for the key_rotation example.

use super::history::HistoryRecord;
use super::rotation::PublishedRotation;

/// Prints the publish-time rotation log: what was committed to the directory
/// and in which epoch, in chronological order.
pub(super) fn print_rotation_log(published: &[PublishedRotation]) {
    println!("\n── Rotation publish log ──────────────────────────────────────────");
    println!(
        "{:<6} {:<8} {:<24} {:<28} {:<16}",
        "Rot.", "Epoch", "Reason", "Key name", "Root hash (12 hex)"
    );
    println!("{}", "─".repeat(72));
    for p in published {
        println!(
            "{:<6} {:<8} {:<24} {:<28} root: {}",
            p.event.index,
            p.epoch,
            p.event.reason.to_string(),
            p.event.key_name,
            hex::encode(&p.root_hash[..6]),
        );
    }
    println!();
}

/// Prints the client-verified history table: the result of `key_history_verify`,
/// enriched with the rotation reason from the original publish record.
///
/// Entries are displayed in chronological order (oldest first) so that readers
/// can trace the key lifecycle from registration through each rotation.
pub(super) fn print_history_table(records: &[HistoryRecord]) {
    println!("── Verified key history (client-side proof check passed) ─────────");
    println!(
        "{:<8} {:<10} {:<24} {:<24}",
        "Epoch", "Version", "Reason", "Key name"
    );
    println!("{}", "─".repeat(72));
    for r in records {
        println!(
            "{:<8} {:<10} {:<24} {}",
            r.epoch, r.version, r.reason, r.key_name
        );
    }
    println!();
}

/// Prints a one-line summary confirming the counts match.
pub(super) fn print_summary(rotations_applied: usize, entries_verified: usize) {
    println!(
        "Summary: {} rotation(s) published, {} history entr{} verified.",
        rotations_applied,
        entries_verified,
        if entries_verified == 1 { "y" } else { "ies" }
    );
}
