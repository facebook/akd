// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the client verification calls to verify different membership types

#[cfg(feature = "nostd")]
use crate::alloc::string::ToString;
#[cfg(feature = "vrf")]
use crate::VerificationErrorType;
#[cfg(feature = "nostd")]
use alloc::format;

use crate::hash::*;
use crate::types::*;
use crate::{verify_error, VerificationError, ARITY};

#[cfg(feature = "vrf")]
use vrf::openssl::CipherSuite;
#[cfg(feature = "vrf")]
use vrf::{openssl::ECVRF, VRF};

/// Verify the membership proof
pub fn verify_membership(
    root_hash: Digest,
    proof: &MembershipProof,
) -> Result<(), VerificationError> {
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
pub fn verify_nonmembership(
    root_hash: Digest,
    proof: &NonMembershipProof,
) -> Result<bool, VerificationError> {
    let mut verified = true;
    let mut lcp_hash = hash(&[]);
    let mut lcp_real = proof.longest_prefix_children[0].label;
    for i in 0..ARITY {
        let child_hash = merge(&[
            proof.longest_prefix_children[i].hash,
            proof.longest_prefix_children[i].label.hash(),
        ]);
        lcp_hash = merge(&[lcp_hash, child_hash]);
        lcp_real = lcp_real.get_longest_common_prefix(proof.longest_prefix_children[i].label);
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
    let _sib_len = proof.longest_prefix_membership_proof.layer_proofs.len();
    let _longest_prefix_verified =
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
pub fn verify_vrf(
    vrf_public_key: &[u8],
    uname: &AkdLabel,
    stale: bool,
    version: u64,
    pi: &Vec<u8>,
    label: NodeLabel,
) -> Result<(), VerificationError> {
    let name_hash_bytes = hash(uname);
    let stale_bytes = if stale { &[0u8] } else { &[1u8] };

    let message = merge(&[name_hash_bytes, merge_with_int(hash(stale_bytes), version)]);

    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).map_err(|vrf_err| {
        VerificationError {
            error_type: VerificationErrorType::Vrf,
            error_message: format!("Could not construct ECVRF struct: {}", vrf_err),
        }
    })?;
    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(vrf_public_key, pi, &message);

    match beta {
        Ok(vec) => {
            let expected_label = NodeLabel {
                len: 256u32,
                val: crate::utils::vec_to_u8_arr(vec),
            };

            if label == expected_label {
                Ok(())
            } else {
                Err(VerificationError {
                    error_type: VerificationErrorType::Vrf,
                    error_message:
                        "VRF Verification failed: Stale label not equal to the value from the VRF"
                            .to_string(),
                })
            }
        }
        Err(e) => Err(VerificationError {
            error_type: VerificationErrorType::Vrf,
            error_message: format!("VRF Verification failed: {:?}", e),
        }),
    }
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
