// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the client verification calls to verify different membership types

#[cfg(feature = "nostd")]
use crate::alloc::string::ToString;
#[cfg(feature = "nostd")]
use alloc::format;

use crate::hash::*;
use crate::types::*;
use crate::{verify_error, VerificationError, ARITY};

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

/// Verifies a lookup with respect to the root_hash
pub fn lookup_verify(
    root_hash: Digest,
    _akd_key: AkdLabel,
    proof: LookupProof,
) -> Result<(), VerificationError> {
    let _epoch = proof.epoch;

    let _plaintext_value = proof.plaintext_value;
    let version = proof.version;

    let _marker_version = 1 << crate::utils::get_marker_version(version);
    let existence_proof = proof.existence_proof;
    let marker_proof = proof.marker_proof;
    let freshness_proof = proof.freshness_proof;

    // TODO: merge VRF verification changes

    verify_membership(root_hash, &existence_proof)?;
    verify_membership(root_hash, &marker_proof)?;

    verify_nonmembership(root_hash, &freshness_proof)?;

    Ok(())
}
