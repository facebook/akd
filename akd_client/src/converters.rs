// Copyright (c) Meta, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Converters from akd types to akd_client types

use crate::hash::DIGEST_BYTES;
use akd;
use winter_utils::Serializable;

/// Converts a Digest type to a byte array of size DIGEST_BYTES.
pub fn to_digest<H>(hash: H::Digest) -> crate::types::Digest
where
    H: winter_crypto::Hasher,
{
    let digest = hash.to_bytes();
    if digest.len() == DIGEST_BYTES {
        // OK
        let ptr = digest.as_ptr() as *const [u8; DIGEST_BYTES];
        unsafe { *ptr }
    } else {
        panic!("Hash digest is not {} bytes", DIGEST_BYTES);
    }
}

fn convert_label(proof: akd::node_label::NodeLabel) -> crate::types::NodeLabel {
    crate::types::NodeLabel {
        label_len: proof.label_len,
        label_val: proof.label_val,
    }
}

fn convert_node<H>(node: akd::Node<H>) -> crate::types::Node
where
    H: winter_crypto::Hasher,
{
    crate::types::Node {
        label: convert_label(node.label),
        hash: to_digest::<H>(node.hash),
    }
}

fn convert_layer_proof<H>(
    parent: akd::NodeLabel,
    direction: akd::Direction,
    sibling: akd::Node<H>,
) -> crate::types::LayerProof
where
    H: winter_crypto::Hasher,
{
    crate::types::LayerProof {
        direction,
        label: convert_label(parent),
        siblings: [convert_node(sibling)],
    }
}

fn convert_membership_proof<H>(
    proof: &akd::proof_structs::MembershipProof<H>,
) -> crate::types::MembershipProof
where
    H: winter_crypto::Hasher,
{
    crate::types::MembershipProof {
        hash_val: to_digest::<H>(proof.hash_val),
        label: convert_label(proof.label),
        layer_proofs: proof
            .layer_proofs
            .iter()
            .map(|lp| convert_layer_proof(lp.label, lp.direction, lp.siblings[0]))
            .collect::<Vec<_>>(),
    }
}

fn convert_non_membership_proof<H>(
    proof: &akd::proof_structs::NonMembershipProof<H>,
) -> crate::types::NonMembershipProof
where
    H: winter_crypto::Hasher,
{
    crate::types::NonMembershipProof {
        label: convert_label(proof.label),
        longest_prefix: convert_label(proof.longest_prefix),
        longest_prefix_children: [
            convert_node::<H>(proof.longest_prefix_children[0]),
            convert_node::<H>(proof.longest_prefix_children[1]),
        ],
        longest_prefix_membership_proof: convert_membership_proof(
            &proof.longest_prefix_membership_proof,
        ),
    }
}

/// Converts and AKD lookup proof to AKD_CLIENT lookup proof.
pub fn convert_lookup_proof<H>(
    proof: &akd::proof_structs::LookupProof<H>,
) -> crate::types::LookupProof
where
    H: winter_crypto::Hasher,
{
    crate::types::LookupProof {
        epoch: proof.epoch,
        version: proof.version,
        plaintext_value: proof.plaintext_value.to_vec(),
        existence_vrf_proof: proof.existence_vrf_proof.clone(),
        existence_proof: convert_membership_proof(&proof.existence_proof),
        marker_vrf_proof: proof.marker_vrf_proof.clone(),
        marker_proof: convert_membership_proof(&proof.marker_proof),
        freshness_vrf_proof: proof.freshness_vrf_proof.clone(),
        freshness_proof: convert_non_membership_proof(&proof.freshness_proof),
        commitment_proof: proof.commitment_proof.clone(),
    }
}

/// Converts an AKD history proof to an AKD_CLIENT history proof
pub fn convert_history_proof<H>(
    history_proof: &akd::proof_structs::HistoryProof<H>,
) -> crate::types::HistoryProof
where
    H: winter_crypto::Hasher,
{
    let mut res_update_proofs = Vec::<crate::types::UpdateProof>::new();
    for proof in &history_proof.update_proofs {
        let update_proof = crate::types::UpdateProof {
            epoch: proof.epoch,
            plaintext_value: proof.plaintext_value.to_vec(),
            version: proof.version,
            existence_vrf_proof: proof.existence_vrf_proof.clone(),
            existence_at_ep: convert_membership_proof(&proof.existence_at_ep),
            previous_version_vrf_proof: proof.previous_version_vrf_proof.clone(),
            previous_version_stale_at_ep: proof
                .previous_version_stale_at_ep
                .clone()
                .map(|val| convert_membership_proof(&val)),
            commitment_proof: proof.commitment_proof.clone(),
        };
        res_update_proofs.push(update_proof);
    }
    crate::types::HistoryProof {
        update_proofs: res_update_proofs,
        next_few_vrf_proofs: history_proof.next_few_vrf_proofs.clone(),
        non_existence_of_next_few: history_proof
            .non_existence_of_next_few
            .iter()
            .map(|non_memb_proof| convert_non_membership_proof(non_memb_proof))
            .collect(),
        future_marker_vrf_proofs: history_proof.future_marker_vrf_proofs.clone(),
        non_existence_of_future_markers: history_proof
            .non_existence_of_future_markers
            .iter()
            .map(|non_exist_markers| convert_non_membership_proof(non_exist_markers))
            .collect(),
    }
}
