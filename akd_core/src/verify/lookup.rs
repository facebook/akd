// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Verification of lookup proofs

use super::base::{verify_existence, verify_existence_with_val, verify_nonexistence};
use super::VerificationError;

use crate::configuration::Configuration;
use crate::hash::Digest;
use crate::{AkdLabel, LookupProof, VerifyResult, VersionFreshness};

/// Verifies a lookup with respect to the root_hash
pub fn lookup_verify<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash: Digest,
    current_epoch: u64,
    akd_label: AkdLabel,
    proof: LookupProof,
) -> Result<VerifyResult, VerificationError> {
    if proof.version > current_epoch {
        return Err(VerificationError::LookupProof(alloc::format!(
            "Proof version {} is greater than current epoch {}",
            proof.version,
            current_epoch
        )));
    }

    verify_existence_with_val::<TC>(
        vrf_public_key,
        root_hash,
        &akd_label,
        &proof.value,
        proof.epoch,
        &proof.commitment_nonce,
        VersionFreshness::Fresh,
        proof.version,
        &proof.existence_vrf_proof,
        &proof.existence_proof,
    )?;

    let marker_version = 1 << crate::utils::get_marker_version_log2(proof.version);
    verify_existence::<TC>(
        vrf_public_key,
        root_hash,
        &akd_label,
        VersionFreshness::Fresh,
        marker_version,
        &proof.marker_vrf_proof,
        &proof.marker_proof,
    )?;

    verify_nonexistence::<TC>(
        vrf_public_key,
        root_hash,
        &akd_label,
        VersionFreshness::Stale,
        proof.version,
        &proof.freshness_vrf_proof,
        &proof.freshness_proof,
    )?;

    Ok(VerifyResult {
        epoch: proof.epoch,
        version: proof.version,
        value: proof.value,
    })
}
