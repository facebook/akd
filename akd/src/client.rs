// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Code for a client of a auditable key directory

use vrf::{
    openssl::{CipherSuite, ECVRF},
    VRF,
};
use winter_crypto::Hasher;

use crate::{
    directory::get_marker_version,
    errors::{self, AkdError, AzksError, DirectoryError},
    node_state::{hash_label, NodeLabel},
    proof_structs::{HistoryProof, LookupProof, MembershipProof, NonMembershipProof, UpdateProof},
    serialization::from_digest,
    storage::types::AkdKey,
    Direction, ARITY,
};

/// Verifies membership, with respect to the root_hash
pub fn verify_membership<H: Hasher>(
    root_hash: H::Digest,
    proof: &MembershipProof<H>,
) -> Result<(), AkdError> {
    if proof.label.len == 0 {
        let final_hash = H::merge(&[proof.hash_val, hash_label::<H>(proof.label)]);
        if final_hash == root_hash {
            return Ok(());
        } else {
            return Err(AkdError::AzksErr(AzksError::MembershipProofDidNotVerify(
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
        return Err(AkdError::AzksErr(AzksError::MembershipProofDidNotVerify(
            format!(
                "Membership proof for label {:?} did not verify",
                proof.label
            ),
        )));
    }
}

/// Verifies the non-membership proof with respect to the root hash
pub fn verify_nonmembership<H: Hasher>(
    root_hash: H::Digest,
    proof: &NonMembershipProof<H>,
) -> Result<bool, AkdError> {
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
    if !verified {
        return Err(AkdError::DirectoryErr(
            DirectoryError::LookupVerificationErr("lcp_hash != longest_prefix_hash".to_string()),
        ));
    }
    let _sib_len = proof.longest_prefix_membership_proof.sibling_hashes.len();
    let _longest_prefix_verified =
        verify_membership(root_hash, &proof.longest_prefix_membership_proof)?;
    // The audit must have checked that this node is indeed the lcp of its children.
    // So we can just check that one of the children's lcp is = the proof.longest_prefix
    verified = verified && (proof.longest_prefix == lcp_real);
    if !verified {
        return Err(AkdError::DirectoryErr(
            DirectoryError::LookupVerificationErr("longest_prefix != lcp".to_string()),
        ));
    }
    Ok(verified)
}

/// This function is called to verify that a given NodeLabel is indeed
/// the VRF for a given version (fresh or stale) for a username.
/// Hence, it also takes as input the server's public key.
pub fn verify_vrf<H: Hasher>(
    vrf_pk: &[u8],
    uname: &AkdKey,
    stale: bool,
    version: u64,
    pi: Vec<u8>,
    label: NodeLabel,
) -> Result<(), AkdError> {
    // Initialization of VRF context by providing a curve
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();

    let name_hash_bytes = H::hash(uname.0.as_bytes());
    let mut stale_bytes = &[1u8];
    if stale {
        stale_bytes = &[0u8];
    }

    let hashed_label = H::merge(&[
        name_hash_bytes,
        H::merge_with_int(H::hash(stale_bytes), version),
    ]);
    // let label_slice = hashed_label.as_bytes();
    let message_vec = from_digest::<H>(hashed_label).unwrap();
    let message: &[u8] = message_vec.as_slice();

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(vrf_pk, &pi, message);

    match beta {
        Ok(vec) => {
            if NodeLabel::new(vec_to_u8_arr(vec), 256u32) == label {
                Ok(())
            } else {
                Err(errors::AkdError::DirectoryErr(DirectoryError::VRFLabelErr(
                    "Stale label not equal to the value from the VRF".to_string(),
                )))
            }
        }
        Err(e) => Err(errors::AkdError::DirectoryErr(DirectoryError::VRFErr(e))),
    }
}

/// Verifies a lookup with respect to the root_hash
pub fn lookup_verify<H: Hasher>(
    vrf_pk: &[u8],
    root_hash: H::Digest,
    akd_key: AkdKey,
    proof: LookupProof<H>,
) -> Result<(), AkdError> {
    let _plaintext_value = proof.plaintext_value;
    let version = proof.version;

    let marker_version = 1 << get_marker_version(version);
    let existence_proof = proof.existence_proof;
    let marker_proof = proof.marker_proof;
    let freshness_proof = proof.freshness_proof;

    let fresh_label = existence_proof.label;
    verify_vrf::<H>(
        vrf_pk,
        &akd_key,
        false,
        version,
        proof.exisitence_vrf_proof,
        fresh_label,
    )?;
    verify_membership::<H>(root_hash, &existence_proof)?;

    let marker_label = marker_proof.label;
    verify_vrf::<H>(
        vrf_pk,
        &akd_key,
        false,
        marker_version,
        proof.marker_vrf_proof,
        marker_label,
    )?;
    verify_membership::<H>(root_hash, &marker_proof)?;

    let stale_label = freshness_proof.label;
    verify_vrf::<H>(
        vrf_pk,
        &akd_key,
        true,
        version,
        proof.freshness_vrf_proof,
        stale_label,
    )?;
    verify_nonmembership::<H>(root_hash, &freshness_proof)?;

    Ok(())
}

/// Verifies a key history proof, given the corresponding sequence of hashes.
pub fn key_history_verify<H: Hasher>(
    vrf_pk: &[u8],
    root_hashes: Vec<H::Digest>,
    previous_root_hashes: Vec<Option<H::Digest>>,
    uname: AkdKey,
    proof: HistoryProof<H>,
) -> Result<(), AkdError> {
    for (count, update_proof) in proof.proofs.into_iter().enumerate() {
        let root_hash = root_hashes[count];
        let previous_root_hash = previous_root_hashes[count];
        verify_single_update_proof::<H>(
            root_hash,
            vrf_pk,
            previous_root_hash,
            update_proof,
            &uname,
        )?;
    }
    Ok(())
}

/// Verifies a single update proof
fn verify_single_update_proof<H: Hasher>(
    root_hash: H::Digest,
    vrf_pk: &[u8],
    previous_root_hash: Option<H::Digest>,
    proof: UpdateProof<H>,
    uname: &AkdKey,
) -> Result<(), AkdError> {
    let epoch = proof.epoch;
    let _plaintext_value = &proof.plaintext_value;
    let version = proof.version;

    let existence_vrf_proof = proof.existence_vrf_proof;
    let existence_at_ep_ref = &proof.existence_at_ep;
    let existence_at_ep = existence_at_ep_ref;
    let existence_at_ep_label = existence_at_ep_ref.label;

    let previous_val_stale_at_ep = &proof.previous_val_stale_at_ep;

    let non_existence_before_ep = &proof.non_existence_before_ep;

    // ***** PART 1 ***************************
    // Verify the VRF and membership proof for the corresponding label for the version being updated to.
    verify_vrf::<H>(
        vrf_pk,
        uname,
        false,
        version,
        existence_vrf_proof,
        existence_at_ep_label,
    )?;
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
        let previous_null_err =
            AkdError::DirectoryErr(DirectoryError::KeyHistoryVerificationErr(err_str));
        let previous_val_stale_at_ep =
            previous_val_stale_at_ep.as_ref().ok_or(previous_null_err)?;
        verify_membership(root_hash, previous_val_stale_at_ep)?;

        let vrf_err_str = format!(
            "Staleness proof of user {:?}'s version {:?} at epoch {:?} is None",
            uname,
            (version - 1),
            epoch
        );

        // Verify the VRF for the stale label corresponding to the previous version for this username
        let vrf_previous_null_err =
            AkdError::DirectoryErr(DirectoryError::KeyHistoryVerificationErr(vrf_err_str));
        let previous_val_vrf_proof = proof
            .previous_val_vrf_proof
            .as_ref()
            .ok_or(vrf_previous_null_err)?;
        verify_vrf::<H>(
            vrf_pk,
            uname,
            true,
            version - 1,
            previous_val_vrf_proof.to_vec(),
            previous_val_stale_at_ep.label,
        )?;
    }

    // ***** PART 3 ***************************
    // Verify that the current version was only added in this epoch and didn't exist before.
    if epoch > 1 {
        let root_hash = previous_root_hash.ok_or(AkdError::NoEpochGiven)?;
        verify_nonmembership(
            root_hash,
            non_existence_before_ep.as_ref().ok_or_else(|| AkdError::DirectoryErr(DirectoryError::KeyHistoryVerificationErr(format!(
                "Non-existence before this epoch proof of user {:?}'s version {:?} at epoch {:?} is None",
                uname,
                version,
                epoch
            ))))?
        )?;
    }

    // Get the least and greatest marker entries for the current version
    let next_marker = get_marker_version(version) + 1;
    let final_marker = get_marker_version(epoch);

    // ***** PART 4 ***************************
    // Verify the VRFs and non-membership of future entries, up to the next marker
    for (i, ver) in (version + 1..(1 << next_marker)).enumerate() {
        let pf = &proof.non_existence_of_next_few[i];
        let vrf_pf = &proof.next_few_vrf_proofs[i];
        let ver_label = pf.label;
        verify_vrf::<H>(vrf_pk, uname, false, ver, vrf_pf.clone(), ver_label)?;
        if !verify_nonmembership(root_hash, pf)? {
            return Err(AkdError::DirectoryErr(
                DirectoryError::KeyHistoryVerificationErr(
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, ver, epoch-1))));
        }
    }

    // ***** PART 5 ***************************
    // Verify the VRFs and non-membership proofs for future markers
    for (i, pow) in (next_marker + 1..final_marker).enumerate() {
        let ver = 1 << pow;
        let pf = &proof.non_existence_of_future_markers[i];
        let vrf_pf = &proof.future_marker_vrf_proofs[i];
        let ver_label = pf.label;
        verify_vrf::<H>(vrf_pk, uname, false, ver, vrf_pf.clone(), ver_label)?;
        if !verify_nonmembership(root_hash, pf)? {
            return Err(AkdError::DirectoryErr(
                DirectoryError::KeyHistoryVerificationErr(
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, ver, epoch-1))));
        }
    }

    Ok(())
}

/// Hashes all the children of a node, as well as their labels
fn build_and_hash_layer<H: Hasher>(
    hashes: [H::Digest; ARITY - 1],
    dir: Direction,
    ancestor_hash: H::Digest,
    parent_label: NodeLabel,
) -> Result<H::Digest, AkdError> {
    let direction = dir.ok_or(AkdError::NoDirectionError)?;
    let mut hashes_as_vec = hashes.to_vec();
    hashes_as_vec.insert(direction, ancestor_hash);
    Ok(hash_layer::<H>(hashes_as_vec, parent_label))
}

/// Helper for build_and_hash_layer
fn hash_layer<H: Hasher>(hashes: Vec<H::Digest>, parent_label: NodeLabel) -> H::Digest {
    let mut new_hash = H::hash(&[]); //hash_label::<H>(parent_label);
    for child_hash in hashes.iter().take(ARITY) {
        new_hash = H::merge(&[new_hash, *child_hash]);
    }
    new_hash = H::merge(&[new_hash, hash_label::<H>(parent_label)]);
    new_hash
}

fn vec_to_u8_arr(vector_u8: Vec<u8>) -> [u8; 32] {
    let mut out_arr = [0u8; 32];
    out_arr[..vector_u8.len()].clone_from_slice(&vector_u8[..]);
    out_arr
}
