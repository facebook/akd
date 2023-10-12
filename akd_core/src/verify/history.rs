// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Verification of key history proofs

use super::base::{
    verify_existence, verify_existence_with_commitment, verify_existence_with_val,
    verify_nonexistence,
};
use super::VerificationError;

use crate::configuration::Configuration;
use crate::hash::Digest;
use crate::{AkdLabel, HistoryProof, UpdateProof, VerifyResult, VersionFreshness};
#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::ToString;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;

/// Parameters for customizing how history proof verification proceeds
#[derive(Copy, Clone)]
pub enum HistoryVerificationParams {
    /// No customization to the verification procedure
    Default,
    /// Allows for the encountering of missing (tombstoned) values
    /// instead of attempting to check if their hash matches the leaf node
    /// hash
    AllowMissingValues,
}

impl Default for HistoryVerificationParams {
    fn default() -> Self {
        Self::Default
    }
}

/// Verifies a key history proof, given the corresponding sequence of hashes.
/// Returns a vector of whether the validity of a hash could be verified.
/// When false, the value <=> hash validity at the position could not be
/// verified because the value has been removed ("tombstoned") from the storage layer.
pub fn key_history_verify<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash: Digest,
    current_epoch: u64,
    akd_label: AkdLabel,
    proof: HistoryProof,
    params: HistoryVerificationParams,
) -> Result<Vec<VerifyResult>, VerificationError> {
    let mut results = Vec::new();
    let mut last_version = 0;

    let num_proofs = proof.update_proofs.len();

    // Make sure the update proofs are non-empty
    if num_proofs == 0 {
        return Err(VerificationError::HistoryProof(format!(
            "No update proofs included in the proof of user {akd_label:?} at epoch {current_epoch:?}!"
        )));
    }

    // Check that the sent proofs are for a contiguous sequence of decreasing versions
    for count in 0..num_proofs {
        if count > 0 {
            // Make sure this proof is for a version 1 more than the previous one.
            if proof.update_proofs[count].version + 1 != proof.update_proofs[count - 1].version {
                return Err(VerificationError::HistoryProof(format!(
                    "Update proofs should be ordered consecutively and in decreasing order. 
                    Error detected with version {} = {}, followed by version {} = {}",
                    count,
                    proof.update_proofs[count].version,
                    count - 1,
                    proof.update_proofs[count - 1].version
                )));
            }
        }
    }

    // Verify all individual update proofs
    let mut maybe_previous_update_epoch = None;
    for update_proof in proof.update_proofs.into_iter() {
        // Get the highest version sent among the update proofs.
        last_version = if update_proof.version > last_version {
            update_proof.version
        } else {
            last_version
        };

        if let Some(previous_update_epoch) = maybe_previous_update_epoch {
            // Make sure this this epoch is more than the previous epoch you checked
            if update_proof.epoch > previous_update_epoch {
                return Err(VerificationError::HistoryProof(format!(
                    "Version numbers for updates are decreasing, but their corresponding
                    epochs are not decreasing: epoch = {}, previous epoch = {}",
                    update_proof.epoch, previous_update_epoch
                )));
            }
        }
        maybe_previous_update_epoch = Some(update_proof.epoch);
        let result = verify_single_update_proof::<TC>(
            root_hash,
            vrf_public_key,
            update_proof,
            &akd_label,
            params,
        )?;
        results.push(result);
    }

    // Get the least and greatest marker entries for the current version
    let next_marker = crate::utils::get_marker_version_log2(last_version) + 1;
    let final_marker = crate::utils::get_marker_version_log2(current_epoch);

    // Perform checks for expected number of until-marker proofs
    let expected_num_until_marker_proofs = (1 << next_marker) - last_version - 1;
    if expected_num_until_marker_proofs != proof.until_marker_vrf_proofs.len() as u64 {
        return Err(VerificationError::HistoryProof(format!(
            "Expected {} until-marker proofs, but got {}",
            expected_num_until_marker_proofs,
            proof.until_marker_vrf_proofs.len()
        )));
    }
    if proof.until_marker_vrf_proofs.len() != proof.non_existence_until_marker_proofs.len() {
        return Err(VerificationError::HistoryProof(format!(
            "Expected equal number of until-marker proofs, but got ({}, {})",
            proof.until_marker_vrf_proofs.len(),
            proof.non_existence_until_marker_proofs.len()
        )));
    }

    // Verify the non-existence of future entries, up to the next marker
    for (i, version) in (last_version + 1..(1 << next_marker)).enumerate() {
        verify_nonexistence::<TC>(
            vrf_public_key,
            root_hash,
            &akd_label,
            VersionFreshness::Fresh,
            version,
            &proof.until_marker_vrf_proofs[i],
            &proof.non_existence_until_marker_proofs[i],
        )
        .map_err(|_| {
            VerificationError::HistoryProof(format!(
                "Non-existence of next few proof of label {:?} with version
                {:?} at epoch {:?} does not verify",
                &akd_label, version, current_epoch
            ))
        })?;
    }

    // Perform checks for expected number of future-marker proofs
    let expected_num_future_marker_proofs = final_marker + 1 - next_marker;
    if expected_num_future_marker_proofs != proof.future_marker_vrf_proofs.len() as u64 {
        return Err(VerificationError::HistoryProof(format!(
            "Expected {} future-marker proofs, but got {}",
            expected_num_future_marker_proofs,
            proof.future_marker_vrf_proofs.len()
        )));
    }
    if proof.future_marker_vrf_proofs.len() != proof.non_existence_of_future_marker_proofs.len() {
        return Err(VerificationError::HistoryProof(format!(
            "Expected equal number of future-marker proofs, but got ({}, {})",
            proof.future_marker_vrf_proofs.len(),
            proof.non_existence_of_future_marker_proofs.len()
        )));
    }

    // Verify the VRFs and non-membership proofs for future markers
    for (i, pow) in (next_marker..final_marker + 1).enumerate() {
        let version = 1 << pow;
        verify_nonexistence::<TC>(
            vrf_public_key,
            root_hash,
            &akd_label,
            VersionFreshness::Fresh,
            version,
            &proof.future_marker_vrf_proofs[i],
            &proof.non_existence_of_future_marker_proofs[i],
        )
        .map_err(|_| {
            VerificationError::HistoryProof(format!(
                "Non-existence of future marker proof of label {akd_label:?} with
                version {version:?} at epoch {current_epoch:?} does not verify"
            ))
        })?;
    }

    Ok(results)
}

/// Verifies a single update proof
fn verify_single_update_proof<TC: Configuration>(
    root_hash: Digest,
    vrf_public_key: &[u8],
    proof: UpdateProof,
    akd_label: &AkdLabel,
    params: HistoryVerificationParams,
) -> Result<VerifyResult, VerificationError> {
    // Verify the VRF and membership proof for the corresponding label for the version being updated to.
    match (params, &proof.value) {
        (HistoryVerificationParams::AllowMissingValues, bytes) if bytes.0 == crate::TOMBSTONE => {
            // A tombstone was encountered, we need to just take the
            // hash of the value at "face value" since we don't have
            // the real value available
            verify_existence::<TC>(
                vrf_public_key,
                root_hash,
                akd_label,
                VersionFreshness::Fresh,
                proof.version,
                &proof.existence_vrf_proof,
                &proof.existence_proof,
            )?;
        }
        (_, akd_value) => {
            // No tombstone so hash the value found, and compare to the existence proof's value
            verify_existence_with_val::<TC>(
                vrf_public_key,
                root_hash,
                akd_label,
                akd_value,
                proof.epoch,
                &proof.commitment_nonce,
                VersionFreshness::Fresh,
                proof.version,
                &proof.existence_vrf_proof,
                &proof.existence_proof,
            )?;
        }
    };

    let verify_result = VerifyResult {
        epoch: proof.epoch,
        version: proof.version,
        value: proof.value,
    };

    if proof.version <= 1 {
        // There is no previous version, so we can just return here
        return Ok(verify_result);
    }

    // ***** PART 2 ***************************
    // Verify the membership proof the for stale label of the previous version

    let previous_version_proof = proof.previous_version_proof.as_ref().ok_or_else(|| {
        VerificationError::HistoryProof("Missing membership proof for previous version".to_string())
    })?;
    let previous_version_vrf_proof =
        proof.previous_version_vrf_proof.as_ref().ok_or_else(|| {
            VerificationError::HistoryProof("Missing VRF proof for previous version".to_string())
        })?;

    verify_existence_with_commitment::<TC>(
        vrf_public_key,
        root_hash,
        akd_label,
        TC::stale_azks_value(),
        proof.epoch,
        VersionFreshness::Stale,
        proof.version - 1,
        previous_version_vrf_proof,
        previous_version_proof,
    )?;

    Ok(verify_result)
}
