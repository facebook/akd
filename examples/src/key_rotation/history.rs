// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! History proof generation (server side) and verification (client side).
//!
//! `fetch_and_verify` ties the two halves together and enriches each verified
//! entry with the rotation reason stored in the corresponding `PublishedRotation`.

use super::rotation::PublishedRotation;
use super::AkdDir;
use akd::verify::history::HistoryParams;
use akd::{AkdLabel, HistoryVerificationParams};
use anyhow::Result;

/// A fully verified history entry, enriched with the rotation reason from the
/// original publish record so the report can display it alongside the proof data.
pub(super) struct HistoryRecord {
    /// Epoch in which this version was published.
    pub(super) epoch: u64,
    /// Monotonically increasing version counter for this label (1-based).
    pub(super) version: u64,
    /// The key name stored as AkdValue (human-readable in this example).
    pub(super) key_name: String,
    /// The business reason recorded at publish time.
    pub(super) reason: String,
}

/// Requests a `HistoryProof` from the server for `label`, verifies it on the
/// client side, and joins each result with the corresponding `PublishedRotation`
/// to produce enriched `HistoryRecord` entries.
///
/// ## Server side
/// `Directory::key_history` with `HistoryParams::Complete` generates a proof
/// covering every epoch in which the label has a recorded value. The server
/// returns the proof alongside the current `EpochHash`.
///
/// ## Client side
/// `akd::client::key_history_verify` checks:
///   - VRF proofs for every version (each label position was derived correctly).
///   - Merkle inclusion paths for every version up to the current root hash.
///   - Freshness / ordering invariants across versions.
///
/// Results come back in **reverse-chronological order** (newest first).
/// We re-order them to chronological order before returning so the caller
/// can index them in the same direction as `published`.
pub(super) async fn fetch_and_verify(
    dir: &AkdDir,
    label: &AkdLabel,
    published: &[PublishedRotation],
) -> Result<Vec<HistoryRecord>> {
    // ── Server side ──────────────────────────────────────────────────────────
    let (history_proof, epoch_hash) = dir.key_history(label, HistoryParams::Complete).await?;

    // ── Client side ──────────────────────────────────────────────────────────
    let public_key = dir.get_public_key().await?;

    // HistoryVerificationParams::default() pairs with HistoryParams::Complete.
    // If HistoryParams::MostRecent(n) were used above, the params here must
    // carry the same n via HistoryVerificationParams::Default { history_params }.
    let results = akd::client::key_history_verify::<akd::WhatsAppV1Configuration>(
        public_key.as_bytes(),
        epoch_hash.hash(),
        epoch_hash.epoch(),
        label.clone(),
        history_proof,
        HistoryVerificationParams::default(),
    )
    .map_err(|e| anyhow::anyhow!("History proof verification failed: {e:?}"))?;

    // results[0] is the newest version; reverse so index 0 → oldest rotation.
    let num = results.len();
    let records: Vec<HistoryRecord> = results
        .into_iter()
        .rev() // now chronological order
        .enumerate()
        .map(|(i, r)| {
            // published[i] corresponds to the (i+1)-th rotation (1-based).
            // Both slices are now in chronological order, so indices align.
            let reason = published
                .get(i)
                .map(|p| p.event.reason.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            HistoryRecord {
                epoch: r.epoch,
                version: r.version,
                key_name: String::from_utf8_lossy(&r.value.0).to_string(),
                reason,
            }
        })
        .collect();

    assert_eq!(records.len(), num, "record count mismatch after reversal");
    Ok(records)
}
