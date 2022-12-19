// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Base functionality for verification operations (membership, non-membership, etc)

use super::VerificationError;

use crate::hash::{build_and_hash_layer, merge, merge_with_int, Digest};
use crate::{AkdLabel, MembershipProof, NodeLabel, NonMembershipProof, ARITY, EMPTY_LABEL};

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::ToString;
use core::convert::TryFrom;

/// Verify the membership proof
pub fn verify_membership(
    root_hash: Digest,
    proof: &MembershipProof,
) -> Result<(), VerificationError> {
    if proof.label.label_len == 0 {
        let final_hash = merge(&[proof.hash_val, proof.label.hash()]);
        if final_hash == root_hash {
            return Ok(());
        } else {
            return Err(VerificationError::MembershipProof(
                "Membership proof for root did not verify".to_string(),
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
        Err(VerificationError::MembershipProof(format!(
            "Membership proof for label {:?} did not verify",
            proof.label
        )))
    }
}

/// Verifies the non-membership proof with respect to the root hash
pub fn verify_nonmembership(
    root_hash: Digest,
    proof: &NonMembershipProof,
) -> Result<(), VerificationError> {
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
        lcp_real =
            lcp_real.get_longest_common_prefix(proof.longest_prefix_children[i as usize].label);
    }

    if lcp_real == EMPTY_LABEL {
        lcp_real = NodeLabel {
            label_val: [0u8; 32],
            label_len: 0,
        };
    }

    let lcp_hash = merge(&[child_hash_left, child_hash_right]);

    verified = verified && (lcp_hash == proof.longest_prefix_membership_proof.hash_val);

    if !verified {
        return Err(VerificationError::NonMembershipProof(
            "lcp_hash != longest_prefix_hash".to_string(),
        ));
    }

    verify_membership(root_hash, &proof.longest_prefix_membership_proof)?;

    // The audit must have checked that this node is indeed the lcp of its children.
    // So we can just check that one of the children's lcp is = the proof.longest_prefix
    verified = verified && (proof.longest_prefix == lcp_real);
    if !verified {
        return Err(VerificationError::NonMembershipProof(
            "longest_prefix != lcp".to_string(),
        ));
    }
    Ok(())
}

/// Hash a leaf epoch and proof with a given [AkdValue]
pub fn hash_leaf_with_value(value: &crate::AkdValue, epoch: u64, proof: &[u8]) -> Digest {
    let single_hash = crate::utils::generate_commitment_from_proof_client(value, proof);
    merge_with_int(single_hash, epoch)
}

/// This function is called to verify that a given NodeLabel is indeed
/// the VRF for a given version (fresh or stale) for a username.
/// Hence, it also takes as input the server's public key.
pub fn verify_vrf(
    vrf_public_key: &[u8],
    uname: &AkdLabel,
    stale: bool,
    version: u64,
    pi: &[u8],
    label: NodeLabel,
) -> Result<(), VerificationError> {
    let vrf_pk = crate::ecvrf::VRFPublicKey::try_from(vrf_public_key)?;
    vrf_pk.verify_label(uname, stale, version, pi, label)?;
    Ok(())
}
