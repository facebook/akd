// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Server-side LookupProof generation for the basic_lookup example.
//!
//! In a real deployment these functions run on the server. The proof is then
//! transmitted to the client, which verifies it in `client.rs` without needing
//! to contact the server again.

use super::AkdDir;
use akd::{AkdLabel, EpochHash, LookupProof};
use anyhow::Result;

/// Bundles the server's response to a lookup request.
pub(super) struct LookupResponse {
    /// The cryptographic proof that the queried label exists in the directory
    /// with the value returned, at the epoch represented by `epoch_hash`.
    ///
    /// The proof contains two components:
    ///   1. A VRF proof — shows the label's position in the Merkle tree was
    ///      derived correctly from the server's private key, preventing the
    ///      server from placing the same label at different positions for
    ///      different clients.
    ///   2. A Merkle inclusion path — sibling hashes from the leaf up to the
    ///      root, proving the entry is committed at the tree root.
    pub(super) proof: LookupProof,

    /// The epoch number and root hash the proof is anchored to.
    /// Clients must obtain this value from a trusted third party
    /// (transparency log, auditor) rather than from the server alone.
    pub(super) epoch_hash: EpochHash,
}

/// Requests a lookup proof from the directory server for `label`.
///
/// This corresponds to the server-side half of a key-transparency query.
/// After calling this the server transmits `LookupResponse` to the client,
/// which verifies it independently using only the VRF public key and the
/// epoch hash obtained from a trusted source.
pub(super) async fn request_lookup(dir: &AkdDir, label: AkdLabel) -> Result<LookupResponse> {
    let (proof, epoch_hash) = dir.lookup(label).await?;
    Ok(LookupResponse { proof, epoch_hash })
}
