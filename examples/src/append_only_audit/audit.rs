// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! AppendOnlyProof request (server side) and verification (auditor side).
//!
//! `audit_verify` is an async function because verifying a multi-epoch proof
//! can be CPU-intensive and is designed to be run inside a Tokio task.

use super::AkdDir;
use akd::hash::Digest;
use akd::AppendOnlyProof;
use anyhow::Result;

/// Requests an `AppendOnlyProof` from the directory server for the epoch range
/// `[start_epoch, end_epoch]`.
///
/// The proof contains one sub-proof per epoch transition in the range. Each
/// sub-proof demonstrates that the tree state at the end of the transition
/// is a valid superset of the tree state at the beginning — i.e., no previously
/// committed entry was deleted or overwritten.
///
/// The verifier must supply `(end_epoch - start_epoch + 1)` root hashes when
/// calling `verify_proof`, one per boundary epoch.
pub(super) async fn request_proof(
    dir: &AkdDir,
    start_epoch: u64,
    end_epoch: u64,
) -> Result<AppendOnlyProof> {
    println!(
        "Requesting AppendOnlyProof from epoch {} to {} ...",
        start_epoch, end_epoch
    );
    let proof = dir.audit(start_epoch, end_epoch).await?;
    println!(
        "  Proof received: {} sub-proof(s) covering {} transition(s).",
        proof.proofs.len(),
        proof.epochs.len(),
    );
    Ok(proof)
}

/// Verifies an `AppendOnlyProof` against `hashes`.
///
/// `hashes` must be in ascending epoch order and must contain exactly
/// `(end_epoch - start_epoch + 1)` entries — one for each boundary epoch,
/// including both endpoints.
///
/// `akd::auditor::audit_verify` checks each consecutive pair `(hashes[i],
/// hashes[i+1])` against `proof.proofs[i]`. If any sub-proof is invalid the
/// call returns an error, indicating that the directory is **not** append-only
/// between those epochs.
///
/// The hashes must originate from the auditor's own archive (see `archive.rs`),
/// not from the server, so that the server cannot supply forged anchors.
pub(super) async fn verify_proof(hashes: Vec<Digest>, proof: AppendOnlyProof) -> Result<()> {
    akd::auditor::audit_verify::<akd::WhatsAppV1Configuration>(hashes, proof)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Append-only verification FAILED — directory may have been tampered with: {e:?}"
            )
        })
}

/// Prints a success summary after a passed audit.
pub(super) fn print_result(start_epoch: u64, end_epoch: u64, num_epochs: usize) {
    println!("── Audit result ──────────────────────────────────────────────────");
    println!(
        "  Append-only proof PASSED for epoch {} → {} ({} epoch(s)).",
        start_epoch, end_epoch, num_epochs
    );
    println!("  No entries were deleted or rewritten across these epochs.");
    println!("  The directory is tamper-evident within the audited range.");
}
