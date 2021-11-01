// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use winter_crypto::Hasher;

use crate::{
    directory::get_marker_version,
    errors::{AzksError, DirectoryError, VkdError},
    node_state::{hash_label, NodeLabel},
    proof_structs::{HistoryProof, LookupProof, MembershipProof, NonMembershipProof, UpdateProof},
    storage::types::VkdKey,
    Direction, ARITY,
};

pub fn verify_membership<H: Hasher>(
    root_hash: H::Digest,
    proof: &MembershipProof<H>,
) -> Result<(), VkdError> {
    if proof.label.len == 0 {
        let final_hash = H::merge(&[proof.hash_val, hash_label::<H>(proof.label)]);
        if final_hash == root_hash {
            return Ok(());
        } else {
            return Err(VkdError::AzksErr(AzksError::MembershipProofDidNotVerify(
                "Membership proof for root did not verify".to_string(),
            )));
        }
    }
    let mut final_hash = H::merge(&[proof.hash_val, hash_label::<H>(proof.label)]);
    for i in (0..proof.dirs.len()).rev() {
        final_hash = build_and_hash_layer::<H>(
            proof.sibling_hashes[i],
            proof.dirs[i],
            final_hash,
            proof.parent_labels[i],
        )?;
    }

    if final_hash == root_hash {
        Ok(())
    } else {
        return Err(VkdError::AzksErr(AzksError::MembershipProofDidNotVerify(
            format!(
                "Membership proof for label {:?} did not verify",
                proof.label
            ),
        )));
    }
}

pub fn verify_nonmembership<H: Hasher>(
    root_hash: H::Digest,
    proof: &NonMembershipProof<H>,
) -> Result<bool, VkdError> {
    let mut verified = true;
    let mut lcp_hash = H::hash(&[]);
    let mut lcp_real = proof.longest_prefix_children_labels[0];
    for i in 0..ARITY {
        let child_hash = H::merge(&[
            proof.longest_prefix_children_values[i],
            hash_label::<H>(proof.longest_prefix_children_labels[i]),
        ]);
        lcp_hash = H::merge(&[lcp_hash, child_hash]);
        lcp_real = lcp_real.get_longest_common_prefix(proof.longest_prefix_children_labels[i]);
    }
    // lcp_hash = H::merge(&[lcp_hash, hash_label::<H>(proof.longest_prefix)]);
    verified = verified && (lcp_hash == proof.longest_prefix_membership_proof.hash_val);
    assert!(verified, "lcp_hash != longest_prefix_hash");
    let _sib_len = proof.longest_prefix_membership_proof.sibling_hashes.len();
    let _longest_prefix_verified =
        verify_membership(root_hash, &proof.longest_prefix_membership_proof)?;
    // The audit must have checked that this node is indeed the lcp of its children.
    // So we can just check that one of the children's lcp is = the proof.longest_prefix
    verified = verified && (proof.longest_prefix == lcp_real);
    assert!(verified, "longest_prefix != lcp");
    Ok(verified)
}

pub fn lookup_verify<H: Hasher>(
    root_hash: H::Digest,
    _uname: VkdKey,
    proof: LookupProof<H>,
) -> Result<(), VkdError> {
    let _epoch = proof.epoch;

    let _plaintext_value = proof.plaintext_value;
    let version = proof.version;

    let _marker_version = 1 << get_marker_version(version);
    let existence_proof = proof.existence_proof;
    let marker_proof = proof.marker_proof;
    let freshness_proof = proof.freshness_proof;
    /*
    // These need to be changed to VRF verifications later.
    let existence_label = SeemlessDirectory::<S, H>::get_nodelabel(&uname, false, version);
    if existence_label != existence_proof.label {
        return Err(SeemlessError::SeemlessDirectoryErr(
            SeemlessDirectoryError::LookupVerificationErr(
                "Existence proof label does not match computed label".to_string(),
            ),
        ));
    }
    let non_existence_label = SeemlessDirectory::<S, H>::get_nodelabel(&uname, true, version);
    if non_existence_label != freshness_proof.label {
        return Err(SeemlessError::SeemlessDirectoryErr(
            SeemlessDirectoryError::LookupVerificationErr(
                "Freshness proof label does not match computed label".to_string(),
            ),
        ));
    }
    let marker_label = SeemlessDirectory::<S, H>::get_nodelabel(&uname, false, marker_version);
    if marker_label != marker_proof.label {
        return Err(SeemlessError::SeemlessDirectoryErr(
            SeemlessDirectoryError::LookupVerificationErr(
                "Marker proof label does not match computed label".to_string(),
            ),
        ));
    }
    */
    verify_membership::<H>(root_hash, &existence_proof)?;
    verify_membership::<H>(root_hash, &marker_proof)?;

    verify_nonmembership::<H>(root_hash, &freshness_proof)?;

    Ok(())
}

pub fn key_history_verify<H: Hasher>(
    root_hashes: Vec<H::Digest>,
    previous_root_hashes: Vec<Option<H::Digest>>,
    uname: VkdKey,
    proof: HistoryProof<H>,
) -> Result<(), VkdError> {
    for (count, update_proof) in proof.proofs.into_iter().enumerate() {
        let root_hash = root_hashes[count];
        let previous_root_hash = previous_root_hashes[count];
        verify_single_update_proof::<H>(root_hash, previous_root_hash, update_proof, &uname)?;
    }
    Ok(())
}

pub fn verify_single_update_proof<H: Hasher>(
    root_hash: H::Digest,
    previous_root_hash: Option<H::Digest>,
    proof: UpdateProof<H>,
    uname: &VkdKey,
) -> Result<(), VkdError> {
    let epoch = proof.epoch;
    let _plaintext_value = &proof.plaintext_value;
    let version = proof.version;

    let existence_at_ep_ref = &proof.existence_at_ep;
    let existence_at_ep = existence_at_ep_ref;
    // let existence_at_ep_label = existence_at_ep_ref.label;
    let previous_val_stale_at_ep = &proof.previous_val_stale_at_ep;

    let non_existence_before_ep = &proof.non_existence_before_ep;
    // Need to include vrf verification
    // if label_at_ep != existence_at_ep_label {
    //     return Err(SeemlessError::SeemlessDirectoryErr(
    //         SeemlessDirectoryError::KeyHistoryVerificationErr(
    //             format!("Label of user {:?}'s version {:?} at epoch {:?} does not match the one in the proof",
    //             uname, version, epoch))));
    // }
    verify_membership(root_hash, existence_at_ep)?;
    //     return Err(SeemlessError::SeemlessDirectoryErr(
    //         SeemlessDirectoryError::KeyHistoryVerificationErr(format!(
    //             "Existence proof of user {:?}'s version {:?} at epoch {:?} does not verify",
    //             uname, version, epoch
    //         )),
    //     ));
    // }

    // Edge case here! We need to account for version = 1 where the previous version won't have a proof.
    if version > 1 {
        let err_str = format!(
            "Staleness proof of user {:?}'s version {:?} at epoch {:?} is None",
            uname,
            (version - 1),
            epoch
        );
        let previous_null_err =
            VkdError::DirectoryErr(DirectoryError::KeyHistoryVerificationErr(err_str));
        let previous_val_stale_at_ep =
            previous_val_stale_at_ep.as_ref().ok_or(previous_null_err)?;
        verify_membership(root_hash, previous_val_stale_at_ep)?;
    }

    if epoch > 1 {
        let root_hash = previous_root_hash.ok_or(VkdError::NoEpochGiven)?;
        verify_nonmembership(
            root_hash,
            non_existence_before_ep.as_ref().ok_or_else(|| VkdError::DirectoryErr(DirectoryError::KeyHistoryVerificationErr(format!(
                "Non-existence before this epoch proof of user {:?}'s version {:?} at epoch {:?} is None",
                uname,
                version,
                epoch
            ))))?
        )?;
    }

    let next_marker = get_marker_version(version) + 1;
    let final_marker = get_marker_version(epoch);
    for (i, ver) in (version + 1..(1 << next_marker)).enumerate() {
        let pf = &proof.non_existence_of_next_few[i];
        if !verify_nonmembership(root_hash, pf)? {
            return Err(VkdError::DirectoryErr(
                DirectoryError::KeyHistoryVerificationErr(
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, ver, epoch-1))));
        }
    }

    for (i, pow) in (next_marker + 1..final_marker).enumerate() {
        let ver = 1 << pow;
        let pf = &proof.non_existence_of_future_markers[i];
        if !verify_nonmembership(root_hash, pf)? {
            return Err(VkdError::DirectoryErr(
                DirectoryError::KeyHistoryVerificationErr(
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, ver, epoch-1))));
        }
    }

    Ok(())
}

fn build_and_hash_layer<H: Hasher>(
    hashes: [H::Digest; ARITY - 1],
    dir: Direction,
    ancestor_hash: H::Digest,
    parent_label: NodeLabel,
) -> Result<H::Digest, VkdError> {
    let direction = dir.ok_or(VkdError::NoDirectionError)?;
    let mut hashes_as_vec = hashes.to_vec();
    hashes_as_vec.insert(direction, ancestor_hash);
    Ok(hash_layer::<H>(hashes_as_vec, parent_label))
}

fn hash_layer<H: Hasher>(hashes: Vec<H::Digest>, parent_label: NodeLabel) -> H::Digest {
    let mut new_hash = H::hash(&[]); //hash_label::<H>(parent_label);
    for child_hash in hashes.iter().take(ARITY) {
        new_hash = H::merge(&[new_hash, *child_hash]);
    }
    new_hash = H::merge(&[new_hash, hash_label::<H>(parent_label)]);
    new_hash
}
