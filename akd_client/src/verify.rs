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
        let hashes = parent.siblings.iter().map(|s| s.hash).collect();
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
    let mut lcp_hash = hash(&EMPTY_VALUE);
    let mut lcp_real = proof.longest_prefix_children[0].label;
    for i in 0..ARITY {
        let child_hash = merge(&[
            proof.longest_prefix_children[i].hash,
            proof.longest_prefix_children[i].label.hash(),
        ]);
        lcp_hash = merge(&[lcp_hash, child_hash]);
        lcp_real = lcp_real.get_longest_common_prefix(proof.longest_prefix_children[i].label);
    }
    if lcp_real == EMPTY_LABEL {
        lcp_real = NodeLabel {
            val: [0u8; 32],
            len: 0,
        };
    }
    // lcp_hash = H::merge(&[lcp_hash, hash_label::<H>(proof.longest_prefix)]);
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

    // let _plaintext_value = proof.plaintext_value;
    #[cfg(feature = "vrf")]
    let version = proof.version;

    #[cfg(feature = "vrf")]
    let marker_version = 1 << crate::utils::get_marker_version(version);
    let existence_proof = proof.existence_proof;
    let marker_proof = proof.marker_proof;
    let freshness_proof = proof.freshness_proof;

    #[cfg(feature = "vrf")]
    {
        let fresh_label = existence_proof.label;
        verify_vrf(
            _vrf_public_key,
            &_akd_key,
            false,
            version,
            &proof.exisitence_vrf_proof,
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
pub fn key_history_verify(
    _vrf_public_key: &[u8],
    root_hashes: Vec<Digest>,
    previous_root_hashes: Vec<Option<Digest>>,
    _akd_key: AkdLabel,
    proof: HistoryProof,
) -> Result<(), VerificationError> {
    for (count, update_proof) in proof.proofs.into_iter().enumerate() {
        let root_hash = root_hashes[count];
        let previous_root_hash = previous_root_hashes[count];
        verify_single_update_proof(
            root_hash,
            &_vrf_public_key,
            previous_root_hash,
            update_proof,
            &_akd_key,
        )?;
    }
    // use crate::VerificationErrorType;
    // Err(VerificationError {error_message: "Not implemented".to_string(), error_type: VerificationErrorType::Unknown})
    Ok(())
}

/// Verifies a single update proof
fn verify_single_update_proof(
    root_hash: Digest,
    _vrf_public_key: &[u8],
    previous_root_hash: Option<Digest>,
    proof: UpdateProof,
    uname: &AkdLabel,
) -> Result<(), VerificationError> {
    let epoch = proof.epoch;
    let _plaintext_value = &proof.plaintext_value;
    let version = proof.version;

    let existence_at_ep_ref = &proof.existence_at_ep;
    let existence_at_ep = existence_at_ep_ref;

    let previous_val_stale_at_ep = &proof.previous_val_stale_at_ep;
    let non_existence_before_ep = &proof.non_existence_before_ep;

    // ***** PART 1 ***************************
    // Verify the VRF and membership proof for the corresponding label for the version being updated to.
    #[cfg(feature = "vrf")]
    {
        verify_vrf(
            &_vrf_public_key,
            &uname,
            false,
            version,
            &proof.existence_vrf_proof,
            existence_at_ep_ref.label,
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
                &_vrf_public_key,
                &uname,
                true,
                version - 1,
                &previous_val_vrf_proof,
                previous_val_stale_at_ep.label,
            )?;
        }
    }

    // ***** PART 3 ***************************
    // Verify that the current version was only added in this epoch and didn't exist before.
    if epoch > 1 {
        let root_hash = previous_root_hash.ok_or(VerificationError {
            error_message: "No previous root hash given".to_string(),
            error_type: VerificationErrorType::HistoryProof,
        })?;
        verify_nonmembership(
            root_hash,
            non_existence_before_ep.as_ref().ok_or_else(|| VerificationError {error_message: format!(
                "Non-existence before this epoch proof of user {:?}'s version {:?} at epoch {:?} is None",
                uname,
                version,
                epoch
            ), error_type: VerificationErrorType::HistoryProof})?
        )?;
    }

    // Get the least and greatest marker entries for the current version
    let next_marker = crate::utils::get_marker_version(version) + 1;
    let final_marker = crate::utils::get_marker_version(epoch);

    // ***** PART 4 ***************************
    // Verify the VRFs and non-membership of future entries, up to the next marker
    for (i, ver) in (version + 1..(1 << next_marker)).enumerate() {
        let pf = &proof.non_existence_of_next_few[i];
        #[cfg(feature = "vrf")]
        {
            let vrf_pf = &proof.next_few_vrf_proofs[i];
            let ver_label = pf.label;
            verify_vrf(&_vrf_public_key, uname, false, ver, &vrf_pf, ver_label)?;
        }
        if !verify_nonmembership(root_hash, pf)? {
            return Err(VerificationError {error_message:
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, ver, epoch-1), error_type: VerificationErrorType::HistoryProof});
        }
    }

    // ***** PART 5 ***************************
    // Verify the VRFs and non-membership proofs for future markers
    for (i, pow) in (next_marker + 1..final_marker).enumerate() {
        let ver = 1 << pow;
        let pf = &proof.non_existence_of_future_markers[i];
        #[cfg(feature = "vrf")]
        {
            let vrf_pf = &proof.future_marker_vrf_proofs[i];
            let ver_label = pf.label;
            verify_vrf(&_vrf_public_key, uname, false, ver, &vrf_pf, ver_label)?;
        }
        if !verify_nonmembership(root_hash, pf)? {
            return Err(VerificationError {error_message:
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, ver, epoch-1), error_type: VerificationErrorType::HistoryProof});
        }
    }
    Ok(())
}
