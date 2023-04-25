// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Base functionality for verification operations (membership, non-membership, etc)

use super::VerificationError;

use crate::crypto::{
    compute_parent_hash_from_children, compute_root_hash_from_val, get_hash_from_label_input,
    hash_leaf_with_commitment, hash_leaf_with_value,
};
use crate::ecvrf::{Proof, VrfError};
use crate::hash::Digest;
use crate::{
    AkdLabel, AkdValue, AzksValue, Direction, MembershipProof, NodeLabel, NonMembershipProof,
    VersionFreshness, EMPTY_LABEL,
};

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
    let mut curr_val = proof.hash_val;
    let mut curr_label = proof.label;

    for sibling_proof in proof.sibling_proofs.iter().rev() {
        let sibling = sibling_proof.siblings[0];
        let (left_val, left_label, right_val, right_label) = match sibling_proof.direction {
            Direction::Left => (
                curr_val,
                curr_label.hash(),
                sibling.value,
                sibling.label.hash(),
            ),
            Direction::Right => (
                sibling.value,
                sibling.label.hash(),
                curr_val,
                curr_label.hash(),
            ),
        };
        curr_val =
            compute_parent_hash_from_children(&left_val, &left_label, &right_val, &right_label);
        curr_label = sibling_proof.label;
    }

    if compute_root_hash_from_val(&curr_val) == root_hash {
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
    // Verify that the proof's label is not equal to either of the children's labels
    if proof.label == proof.longest_prefix_children[0].label
        || proof.label == proof.longest_prefix_children[1].label
    {
        return Err(VerificationError::NonMembershipProof(
            "Proof's label is equal to one of the children's labels".to_string(),
        ));
    }

    // Verify that the proof's label is a prefix of proof.longest_prefix
    if !proof.longest_prefix.is_prefix_of(&proof.label) {
        return Err(VerificationError::NonMembershipProof(
            "Proof's label is not a prefix of longest_prefix".to_string(),
        ));
    }

    // Verify that proof.longest_prefix is the longest common prefix of the children
    let mut lcp_children = proof.longest_prefix_children[0]
        .label
        .get_longest_common_prefix(proof.longest_prefix_children[1].label);
    if lcp_children == EMPTY_LABEL {
        // This is a special case that only occurs when the lcp is the root node and
        // it is missing one of its children
        lcp_children = NodeLabel::root();
    }
    if proof.longest_prefix != lcp_children {
        return Err(VerificationError::NonMembershipProof(
            "longest_prefix != computed lcp".to_string(),
        ));
    }

    let lcp_hash = compute_parent_hash_from_children(
        &proof.longest_prefix_children[0].value,
        &proof.longest_prefix_children[0].label.hash(),
        &proof.longest_prefix_children[1].value,
        &proof.longest_prefix_children[1].label.hash(),
    );
    if lcp_children != proof.longest_prefix_membership_proof.label
        || lcp_hash != proof.longest_prefix_membership_proof.hash_val
    {
        return Err(VerificationError::NonMembershipProof(
            "lcp_hash != longest_prefix_hash".to_string(),
        ));
    }
    verify_membership(root_hash, &proof.longest_prefix_membership_proof)?;

    Ok(())
}

/// This function is called to verify that a given [NodeLabel] is indeed
/// the VRF for a given version (fresh or stale) for a [AkdLabel].
/// Hence, it also takes as input the server's public key.
fn verify_label(
    vrf_public_key: &[u8],
    akd_label: &AkdLabel,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    node_label: NodeLabel,
) -> Result<(), VerificationError> {
    let vrf_pk = crate::ecvrf::VRFPublicKey::try_from(vrf_public_key)?;
    let hashed_label = get_hash_from_label_input(akd_label, freshness, version);

    // VRF proof verification (returns VRF hash output)
    let proof = Proof::try_from(vrf_proof)?;
    vrf_pk.verify(&proof, &hashed_label)?;
    let output: crate::ecvrf::Output = (&proof).into();

    if NodeLabel::new(output.to_truncated_bytes(), 256) != node_label {
        return Err(VerificationError::Vrf(VrfError::Verification(
            "Expected first 32 bytes of the proof output did NOT match the supplied label"
                .to_string(),
        )));
    }
    Ok(())
}

pub(crate) fn verify_existence(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    membership_proof: &MembershipProof,
) -> Result<(), VerificationError> {
    verify_label(
        vrf_public_key,
        akd_label,
        freshness,
        version,
        vrf_proof,
        membership_proof.label,
    )?;
    verify_membership(root_hash, membership_proof)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_existence_with_val(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    akd_value: &AkdValue,
    epoch: u64,
    commitment_nonce: &[u8],
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    membership_proof: &MembershipProof,
) -> Result<(), VerificationError> {
    if hash_leaf_with_value(akd_value, epoch, commitment_nonce).0 != membership_proof.hash_val.0 {
        return Err(VerificationError::MembershipProof(
            "Hash of plaintext value did not match existence proof hash".to_string(),
        ));
    }
    verify_existence(
        vrf_public_key,
        root_hash,
        akd_label,
        freshness,
        version,
        vrf_proof,
        membership_proof,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_existence_with_commitment(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    commitment: AzksValue,
    epoch: u64,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    membership_proof: &MembershipProof,
) -> Result<(), VerificationError> {
    if hash_leaf_with_commitment(commitment, epoch).0 != membership_proof.hash_val.0 {
        return Err(VerificationError::MembershipProof(
            "Hash of plaintext value did not match existence proof hash".to_string(),
        ));
    }
    verify_existence(
        vrf_public_key,
        root_hash,
        akd_label,
        freshness,
        version,
        vrf_proof,
        membership_proof,
    )?;

    Ok(())
}

pub(crate) fn verify_nonexistence(
    vrf_public_key: &[u8],
    root_hash: Digest,
    akd_label: &AkdLabel,
    freshness: VersionFreshness,
    version: u64,
    vrf_proof: &[u8],
    nonmembership_proof: &NonMembershipProof,
) -> Result<(), VerificationError> {
    verify_label(
        vrf_public_key,
        akd_label,
        freshness,
        version,
        vrf_proof,
        nonmembership_proof.label,
    )?;
    verify_nonmembership(root_hash, nonmembership_proof)?;
    Ok(())
}
