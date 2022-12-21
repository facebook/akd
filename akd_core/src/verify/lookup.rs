// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Verification of lookup proofs

use super::base::{verify_label, verify_membership, verify_nonmembership};
use super::VerificationError;
use crate::utils::hash_leaf_with_value;

use crate::hash::Digest;
use crate::{AkdLabel, LookupProof, VerifyResult};
#[cfg(feature = "nostd")]
use alloc::string::ToString;

/// Verifies a lookup with respect to the root_hash
pub fn lookup_verify(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: AkdLabel,
    proof: LookupProof,
) -> Result<VerifyResult, VerificationError> {
    let version = proof.version;

    let marker_version = 1 << crate::utils::get_marker_version(version);
    let existence_proof = proof.existence_proof;
    let marker_proof = proof.marker_proof;
    let freshness_proof = proof.freshness_proof;

    let fresh_label = existence_proof.label;

    if hash_leaf_with_value(&proof.plaintext_value, proof.epoch, &proof.commitment_proof)
        != existence_proof.hash_val
    {
        return Err(VerificationError::LookupProof(
            "Hash of plaintext value did not match existence proof hash".to_string(),
        ));
    }

    verify_label(
        vrf_public_key,
        &akd_label,
        false,
        version,
        &proof.existence_vrf_proof,
        fresh_label,
    )?;
    verify_membership(root_hash, &existence_proof)?;

    let marker_label = marker_proof.label;
    verify_label(
        vrf_public_key,
        &akd_label,
        false,
        marker_version,
        &proof.marker_vrf_proof,
        marker_label,
    )?;

    verify_membership(root_hash, &marker_proof)?;

    let stale_label = freshness_proof.label;
    verify_label(
        vrf_public_key,
        &akd_label,
        true,
        version,
        &proof.freshness_vrf_proof,
        stale_label,
    )?;

    verify_nonmembership(root_hash, &freshness_proof)?;

    Ok(VerifyResult {
        epoch: proof.epoch,
        version: proof.version,
        value: proof.plaintext_value,
    })
}
