// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the client verification calls to verify different membership types

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::ToString;
#[cfg(feature = "vrf")]
use core::convert::TryFrom;

use crate::hash::*;
use crate::types::*;
use crate::{verify_error, VerificationError, VerificationErrorType, ARITY};

/// Verify the membership proof
fn verify_membership(root_hash: Digest, proof: &MembershipProof) -> Result<(), VerificationError> {
    if proof.label.len == 0 {
        let final_hash = merge(&[proof.hash_val, proof.label.hash()]);
        if final_hash == root_hash {
            return Ok(());
        } else {
            return Err(verify_error!(
                MembershipProof,
                (),
                "Membership proof for root did not verify".to_string()
            ));
        }
    }

    let mut final_hash = merge(&[proof.hash_val, proof.label.hash()]);
    for parent in proof.layer_proofs.iter().rev() {
        let hashes = parent
            .siblings
            .iter()
            .map(|s| merge(&[s.hash, s.label.hash()]))
            .collect();
        final_hash = build_and_hash_layer(hashes, parent.direction, final_hash, parent.label)?;
    }

    if final_hash == root_hash {
        Ok(())
    } else {
        Err(verify_error!(
            MembershipProof,
            (),
            format!(
                "Membership proof for label {:?} did not verify",
                proof.label
            )
        ))
    }
}

/// Verifies the non-membership proof with respect to the root hash
fn verify_nonmembership(
    root_hash: Digest,
    proof: &NonMembershipProof,
) -> Result<bool, VerificationError> {
    let mut verified = true;

    let mut lcp_real = proof.longest_prefix_children[0].label;

    let child_hash_left = merge(&[
        proof.longest_prefix_children[0].hash,
        proof.longest_prefix_children[0].label.hash(),
    ]);

    let child_hash_right = merge(&[
        proof.longest_prefix_children[1].hash,
        proof.longest_prefix_children[1].label.hash(),
    ]);

    for i in 0..ARITY {
        lcp_real = lcp_real.get_longest_common_prefix(proof.longest_prefix_children[i].label);
    }

    if lcp_real == EMPTY_LABEL {
        lcp_real = NodeLabel {
            val: [0u8; 32],
            len: 0,
        };
    }

    let lcp_hash = merge(&[child_hash_left, child_hash_right]);

    verified = verified && (lcp_hash == proof.longest_prefix_membership_proof.hash_val);

    if !verified {
        return Err(verify_error!(
            LookupProof,
            bool,
            "lcp_hash != longest_prefix_hash".to_string()
        ));
    }

    verify_membership(root_hash, &proof.longest_prefix_membership_proof)?;

    // The audit must have checked that this node is indeed the lcp of its children.
    // So we can just check that one of the children's lcp is = the proof.longest_prefix
    verified = verified && (proof.longest_prefix == lcp_real);
    if !verified {
        return Err(verify_error!(
            LookupProof,
            bool,
            "longest_prefix != lcp".to_string()
        ));
    }
    Ok(verified)
}

fn hash_leaf_with_value(value: &crate::AkdValue, epoch: u64, proof: &[u8]) -> Digest {
    let single_hash = crate::utils::generate_commitment_from_proof_client(value, proof);
    merge_with_int(single_hash, epoch)
}

/// This function is called to verify that a given NodeLabel is indeed
/// the VRF for a given version (fresh or stale) for a username.
/// Hence, it also takes as input the server's public key.
#[cfg(feature = "vrf")]
fn verify_vrf(
    vrf_public_key: &[u8],
    uname: &AkdLabel,
    stale: bool,
    version: u64,
    pi: &[u8],
    label: NodeLabel,
) -> Result<(), VerificationError> {
    let vrf_pk = crate::ecvrf::VRFPublicKey::try_from(vrf_public_key)?;
    vrf_pk.verify_label(uname, stale, version, pi, label)
}

/// Verifies a lookup with respect to the root_hash
pub fn lookup_verify(
    _vrf_public_key: &[u8],
    root_hash: Digest,
    _akd_key: AkdLabel,
    proof: LookupProof,
) -> Result<(), VerificationError> {
    let _epoch = proof.epoch;

    #[cfg(feature = "vrf")]
    let version = proof.version;

    #[cfg(feature = "vrf")]
    let marker_version = 1 << crate::utils::get_marker_version(version);
    let existence_proof = proof.existence_proof;
    let marker_proof = proof.marker_proof;
    let freshness_proof = proof.freshness_proof;

    let fresh_label = existence_proof.label;

    if hash_leaf_with_value(&proof.plaintext_value, proof.epoch, &proof.commitment_proof)
        != existence_proof.hash_val
    {
        return Err(verify_error!(
            LookupProof,
            bool,
            "Hash of plaintext value did not match existence proof hash".to_string()
        ));
    }

    #[cfg(feature = "vrf")]
    {
        verify_vrf(
            _vrf_public_key,
            &_akd_key,
            false,
            version,
            &proof.existence_vrf_proof,
            fresh_label,
        )?;
    }
    verify_membership(root_hash, &existence_proof)?;

    #[cfg(feature = "vrf")]
    {
        let marker_label = marker_proof.label;
        verify_vrf(
            _vrf_public_key,
            &_akd_key,
            false,
            marker_version,
            &proof.marker_vrf_proof,
            marker_label,
        )?;
    }

    verify_membership(root_hash, &marker_proof)?;

    #[cfg(feature = "vrf")]
    {
        let stale_label = freshness_proof.label;
        verify_vrf(
            _vrf_public_key,
            &_akd_key,
            true,
            version,
            &proof.freshness_vrf_proof,
            stale_label,
        )?;
    }

    verify_nonmembership(root_hash, &freshness_proof)?;

    Ok(())
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
    allow_tombstones: bool,
) -> Result<Vec<bool>, VerificationError> {
    let mut tombstones = vec![];
    let mut last_version = 0;

    let num_proofs = proof.update_proofs.len();

    // Make sure the update proofs are non-empty
    if num_proofs == 0 {
        return Err(VerificationError {
            error_message: format!(
                "No update proofs included in the proof of user {:?} at epoch {:?}!",
                akd_key, current_epoch
            ),
            error_type: VerificationErrorType::HistoryProof,
        });
    }

    // Make sure this proof has the same number of epochs as update proofs.
    if num_proofs != proof.epochs.len() {
        return Err(VerificationError {
            error_message: format!(
                "The number of epochs included in the proofs for user {:?} 
                did not match the number of update proofs!",
                akd_key
            ),
            error_type: VerificationErrorType::HistoryProof,
        });
    }

    // Check that the sent proofs are for a contiguous sequence of decreasing versions
    for count in 0..num_proofs {
        if count > 0 {
            // Make sure this proof is for a version 1 more than the previous one.
            if proof.update_proofs[count].version + 1 != proof.update_proofs[count - 1].version {
                return Err(VerificationError {
                    error_message:
                        format!("Why did you give me consecutive update proofs without version numbers decrememting by 1? Version {} = {}; version {} = {}",
                        count, proof.update_proofs[count].version,
                        count-1, proof.update_proofs[count-1].version
                        ),
                    error_type: VerificationErrorType::HistoryProof});
            }
        }
    }

    // Check that all the individual update proofs check
    for (count, update_proof) in proof.update_proofs.into_iter().enumerate() {
        // Get the highest version sent among the update proofs.
        last_version = if update_proof.version > last_version {
            update_proof.version
        } else {
            last_version
        };
        let ep_match = proof.epochs[count] == update_proof.epoch;
        if count > 0 {
            // Make sure this this epoch is more than the previous epoch you checked
            if proof.epochs[count] > proof.epochs[count - 1] {
                return Err(VerificationError {
                    error_message: format!(
                        "Why are your versions decreasing in updates and epochs not?!,
                    epochs = {:?}",
                        proof.epochs
                    ),
                    error_type: VerificationErrorType::HistoryProof,
                });
            }
        }
        let is_tombstone = verify_single_update_proof(
            root_hash,
            vrf_public_key,
            update_proof,
            &akd_key,
            allow_tombstones,
        )?;
        tombstones.push(is_tombstone && ep_match);
    }

    // Get the least and greatest marker entries for the current version
    let next_marker = crate::utils::get_marker_version(last_version) + 1;
    let final_marker = crate::utils::get_marker_version(current_epoch);

    // ***** Future checks below ***************************
    // Verify the VRFs and non-membership of future entries, up to the next marker
    for (i, ver) in (last_version + 1..(1 << next_marker)).enumerate() {
        let pf = &proof.non_existence_of_next_few[i];
        #[cfg(feature = "vrf")]
        {
            let vrf_pf = &proof.next_few_vrf_proofs[i];
            let ver_label = pf.label;
            verify_vrf(vrf_public_key, &akd_key, false, ver, vrf_pf, ver_label)?;
        }
        if !verify_nonmembership(root_hash, pf)? {
            return Err(VerificationError {error_message:
                    format!("Non-existence of next few proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    &akd_key, ver, current_epoch), error_type: VerificationErrorType::HistoryProof});
        }
    }

    // Verify the VRFs and non-membership proofs for future markers
    for (i, pow) in (next_marker + 1..final_marker).enumerate() {
        let ver = 1 << pow;
        let pf = &proof.non_existence_of_future_markers[i];
        #[cfg(feature = "vrf")]
        {
            let vrf_pf = &proof.future_marker_vrf_proofs[i];
            let ver_label = pf.label;
            verify_vrf(vrf_public_key, &akd_key, false, ver, vrf_pf, ver_label)?;
        }
        if !verify_nonmembership(root_hash, pf)? {
            return Err(VerificationError {error_message:
                    format!("Non-existence of future marker proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    akd_key, ver, current_epoch), error_type: VerificationErrorType::HistoryProof});
        }
    }

    Ok(tombstones)
}

/// Verifies a single update proof
fn verify_single_update_proof(
    root_hash: Digest,
    vrf_public_key: &[u8],
    proof: UpdateProof,
    uname: &AkdLabel,
    allow_tombstone: bool,
) -> Result<bool, VerificationError> {
    let epoch = proof.epoch;
    let _plaintext_value = &proof.plaintext_value;
    let version = proof.version;

    let existence_at_ep = &proof.existence_at_ep;

    let previous_val_stale_at_ep = &proof.previous_val_stale_at_ep;

    let (is_tombstone, value_hash_valid) = match (allow_tombstone, &proof.plaintext_value) {
        (true, bytes) if bytes == crate::TOMBSTONE => {
            // A tombstone was encountered, we need to just take the
            // hash of the value at "face value" since we don't have
            // the real value available
            (true, true)
        }
        (_, bytes) => {
            // No tombstone so hash the value found, and compare to the existence proof's value
            (
                false,
                hash_leaf_with_value(bytes, proof.epoch, &proof.commitment_proof)
                    == existence_at_ep.hash_val,
            )
        }
    };
    if !value_hash_valid {
        return Err(verify_error!(
            HistoryProof,
            bool,
            "Hash of plaintext value did not match existence proof hash".to_string()
        ));
    }

    // ***** PART 1 ***************************
    // Verify the VRF and membership proof for the corresponding label for the version being updated to.
    #[cfg(feature = "vrf")]
    {
        verify_vrf(
            vrf_public_key,
            uname,
            false,
            version,
            &proof.existence_vrf_proof,
            existence_at_ep.label,
        )?;
    }
    verify_membership(root_hash, existence_at_ep)?;
    // ***** PART 2 ***************************
    // Edge case here! We need to account for version = 1 where the previous version won't have a proof.
    if version > 1 {
        // Verify the membership proof the for stale label of the previous version
        let err_str = format!(
            "Staleness proof of user {:?}'s version {:?} at epoch {:?} is None",
            uname,
            (version - 1),
            epoch
        );
        let previous_null_err = VerificationError {
            error_message: err_str,
            error_type: VerificationErrorType::HistoryProof,
        };
        let previous_val_stale_at_ep =
            previous_val_stale_at_ep.as_ref().ok_or(previous_null_err)?;
        verify_membership(root_hash, previous_val_stale_at_ep)?;

        #[cfg(feature = "vrf")]
        {
            let vrf_err_str = format!(
                "Staleness proof of user {:?}'s version {:?} at epoch {:?} is None",
                uname,
                (version - 1),
                epoch
            );

            // Verify the VRF for the stale label corresponding to the previous version for this username
            let vrf_previous_null_err = VerificationError {
                error_message: vrf_err_str,
                error_type: VerificationErrorType::HistoryProof,
            };
            let previous_val_vrf_proof = proof
                .previous_val_vrf_proof
                .as_ref()
                .ok_or(vrf_previous_null_err)?;
            verify_vrf(
                vrf_public_key,
                uname,
                true,
                version - 1,
                previous_val_vrf_proof,
                previous_val_stale_at_ep.label,
            )?;
        }
    }

    // return indicator of if the value <=> hash mapping was verified
    // or if the hash was simply taken at face-value. True = hash mapping verified
    Ok(is_tombstone)
}
