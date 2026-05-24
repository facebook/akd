// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Client-side proof verification and result display for the basic_lookup example.
//!
//! Everything here runs on the client. The only inputs from the server are the
//! `LookupResponse` (proof + epoch hash) and — fetched once, cached long-term —
//! the VRF public key. The epoch hash itself must come from a trusted third party
//! in production; the server is not a reliable source for its own root hash.

use super::{proofs::LookupResponse, AkdDir};
use akd::AkdLabel;
use anyhow::Result;

/// The validated outcome of a successful lookup verification.
pub(super) struct VerifiedLookup {
    /// The human-readable label that was queried.
    pub(super) label: String,
    /// The epoch in which this label–value binding was established.
    pub(super) epoch: u64,
    /// The version counter for this label (incremented on each re-publish).
    pub(super) version: u64,
    /// The value (e.g. public key bytes) associated with the label at `epoch`.
    pub(super) value: String,
}

/// Verifies a server-supplied `LookupResponse` on the client side.
///
/// Retrieves the server's VRF public key from the directory, then calls
/// `akd::client::lookup_verify` — a pure, synchronous function that performs
/// all cryptographic checks without any network access:
///
///   1. **VRF proof** — confirms the label's tree position was derived
///      correctly from the server's private key (checked against the public key).
///   2. **Merkle inclusion path** — confirms the leaf is committed at
///      `epoch_hash.hash()`.
///   3. **Freshness** — confirms the proof's version ≤ the current epoch,
///      preventing replay of stale proofs.
pub(super) async fn verify(
    dir: &AkdDir,
    label: AkdLabel,
    response: LookupResponse,
) -> Result<VerifiedLookup> {
    let label_str = String::from_utf8_lossy(&label.0).to_string();
    let public_key = dir.get_public_key().await?;

    let result = akd::client::lookup_verify::<akd::WhatsAppV1Configuration>(
        public_key.as_bytes(),
        response.epoch_hash.hash(),
        response.epoch_hash.epoch(),
        label,
        response.proof,
    )
    .map_err(|e| anyhow::anyhow!("Lookup proof verification failed: {e:?}"))?;

    Ok(VerifiedLookup {
        label: label_str,
        epoch: result.epoch,
        version: result.version,
        value: String::from_utf8_lossy(&result.value.0).to_string(),
    })
}

/// Pretty-prints a `VerifiedLookup` to stdout.
pub(super) fn display(v: &VerifiedLookup) {
    println!("[client]  Proof verified successfully.");
    println!("          label   : {}", v.label);
    println!("          epoch   : {}", v.epoch);
    println!("          version : {}", v.version);
    println!("          value   : \"{}\"", v.value);
}
