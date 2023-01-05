// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Verification of key history proofs

use super::base::{verify_label, verify_membership, verify_nonmembership};
use super::VerificationError;
use crate::utils::hash_leaf_with_value;

use crate::hash::{hash, merge_with_int, Digest};
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
pub fn key_history_verify(
    vrf_public_key: &[u8],
    root_hash: Digest,
    current_epoch: u64,
    akd_key: AkdLabel,
    proof: HistoryProof,
    params: HistoryVerificationParams,
) -> Result<Vec<VerifyResult>, VerificationError> {
    let mut results = Vec::new();
    let mut last_version = 0;

    let num_proofs = proof.update_proofs.len();

    // Make sure the update proofs are non-empty
    if num_proofs == 0 {
        return Err(VerificationError::HistoryProof(format!(
            "No update proofs included in the proof of user {:?} at epoch {:?}!",
            akd_key, current_epoch
        )));
    }

    // Check that the sent proofs are for a contiguous sequence of decreasing versions
    for count in 0..num_proofs {
        if count > 0 {
            // Make sure this proof is for a version 1 more than the previous one.
            if proof.update_proofs[count].version + 1 != proof.update_proofs[count - 1].version {
                return Err(VerificationError::HistoryProof(format!("Why did you give me consecutive update proofs without version numbers decrementing by 1? Version {} = {}; version {} = {}",
                count, proof.update_proofs[count].version,
                count-1, proof.update_proofs[count-1].version
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
                    "Why are your versions decreasing in updates and epochs not?!,
                    epoch = {}, previous epoch = {}",
                    update_proof.epoch, previous_update_epoch
                )));
            }
        }
        maybe_previous_update_epoch = Some(update_proof.epoch);
        let result =
            verify_single_update_proof(root_hash, vrf_public_key, update_proof, &akd_key, params)?;
        results.push(result);
    }

    // Get the least and greatest marker entries for the current version
    let next_marker = crate::utils::get_marker_version_log2(last_version) + 1;
    let final_marker = crate::utils::get_marker_version_log2(current_epoch);

    // ***** Future checks below ***************************
    // Verify the VRFs and non-membership of future entries, up to the next marker
    for (i, ver) in (last_version + 1..(1 << next_marker)).enumerate() {
        let pf = &proof.non_existence_until_marker_proofs[i];
        let vrf_pf = &proof.until_marker_vrf_proofs[i];
        let ver_label = pf.label;
        verify_label(
            vrf_public_key,
            &akd_key,
            VersionFreshness::Fresh,
            ver,
            vrf_pf,
            ver_label,
        )?;
        if verify_nonmembership(root_hash, pf).is_err() {
            return Err(VerificationError::HistoryProof(format!("Non-existence of next few proof of user {:?}'s version {:?} at epoch {:?} does not verify",
            &akd_key, ver, current_epoch)));
        }
    }

    // Verify the VRFs and non-membership proofs for future markers
    for (i, pow) in (next_marker + 1..final_marker).enumerate() {
        let ver = 1 << pow;
        let pf = &proof.non_existence_of_future_marker_proofs[i];
        let vrf_pf = &proof.future_marker_vrf_proofs[i];
        let ver_label = pf.label;
        verify_label(
            vrf_public_key,
            &akd_key,
            VersionFreshness::Fresh,
            ver,
            vrf_pf,
            ver_label,
        )?;
        if verify_nonmembership(root_hash, pf).is_err() {
            return Err(VerificationError::HistoryProof(format!("Non-existence of future marker proof of user {:?}'s version {:?} at epoch {:?} does not verify",
            akd_key, ver, current_epoch)));
        }
    }

    Ok(results)
}

/// Verifies a single update proof
fn verify_single_update_proof(
    root_hash: Digest,
    vrf_public_key: &[u8],
    proof: UpdateProof,
    uname: &AkdLabel,
    params: HistoryVerificationParams,
) -> Result<VerifyResult, VerificationError> {
    let epoch = proof.epoch;
    let version = proof.version;
    let existence_at_ep = &proof.existence_proof;

    let value_hash_valid = match (params, &proof.value) {
        (HistoryVerificationParams::AllowMissingValues, bytes) if bytes.0 == crate::TOMBSTONE => {
            // A tombstone was encountered, we need to just take the
            // hash of the value at "face value" since we don't have
            // the real value available
            true
        }
        (_, bytes) => {
            // No tombstone so hash the value found, and compare to the existence proof's value
            hash_leaf_with_value(bytes, proof.epoch, &proof.commitment_nonce)
                == existence_at_ep.hash_val
        }
    };
    if !value_hash_valid {
        return Err(VerificationError::HistoryProof(
            "Hash of plaintext value did not match existence proof hash".to_string(),
        ));
    }

    // ***** PART 1 ***************************
    // Verify the VRF and membership proof for the corresponding label for the version being updated to.
    verify_label(
        vrf_public_key,
        uname,
        VersionFreshness::Fresh,
        version,
        &proof.existence_vrf_proof,
        existence_at_ep.label,
    )?;
    verify_membership(root_hash, existence_at_ep)?;

    // ***** PART 2 ***************************
    // Edge case here! We need to account for version = 1 where the previous version won't have a proof.
    if version > 1 {
        // Verify the membership proof the for stale label of the previous version
        let previous_version_stale_proof =
            proof.previous_version_proof.as_ref().ok_or_else(|| {
                VerificationError::HistoryProof(format!(
                    "Staleness proof of user {:?}'s version {:?} at epoch {:?} is None",
                    uname,
                    (version - 1),
                    epoch
                ))
            })?;
        // Check that the correct value is included in the previous stale proof
        if merge_with_int(hash(&crate::EMPTY_VALUE), epoch) != previous_version_stale_proof.hash_val
        {
            return Err(VerificationError::HistoryProof(format!(
                "Staleness proof of user {:?}'s version {:?} at epoch {:?} is doesn't include the right hash.",
                uname,
                (version - 1),
                epoch
            )));
        }
        verify_membership(root_hash, previous_version_stale_proof)?;

        // Verify the VRF for the stale label corresponding to the previous version for this username
        let previous_version_vrf_proof =
            proof.previous_version_vrf_proof.as_ref().ok_or_else(|| {
                VerificationError::HistoryProof(format!(
                    "Staleness proof of user {:?}'s version {:?} at epoch {:?} is None",
                    uname,
                    (version - 1),
                    epoch
                ))
            })?;
        verify_label(
            vrf_public_key,
            uname,
            VersionFreshness::Stale,
            version - 1,
            previous_version_vrf_proof,
            previous_version_stale_proof.label,
        )?;
    }

    Ok(VerifyResult {
        epoch: proof.epoch,
        version: proof.version,
        value: proof.value,
    })
}
