// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This crate contains the tests for the client library which make sure that the
//! base AKD library and this "lean" client result in the same outputs

#[cfg(feature = "nostd")]
use crate::alloc::string::ToString;
#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::vec;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;

use akd::errors::AkdError;
use akd::storage::types::{AkdLabel, AkdValue};

use crate::hash::DIGEST_BYTES;
use winter_math::fields::f128::BaseElement;
use winter_utils::Serializable;

// Feature specific test imports
#[cfg(feature = "blake3")]
use winter_crypto::hashers::Blake3_256;
#[cfg(feature = "blake3")]
type Hash = Blake3_256<BaseElement>;
#[cfg(feature = "sha3_256")]
use winter_crypto::hashers::Sha3_256;
#[cfg(feature = "sha3_256")]
type Hash = Sha3_256<BaseElement>;

type InMemoryDb = akd::storage::memory::AsyncInMemoryDatabase;
type Directory = akd::directory::Directory<InMemoryDb>;

// ===================================
// Test helpers
// ===================================

fn to_digest<H>(hash: H::Digest) -> crate::types::Digest
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

fn convert_label(proof: akd::node_state::NodeLabel) -> crate::types::NodeLabel {
    crate::types::NodeLabel {
        len: proof.len,
        val: proof.val,
    }
}

fn convert_node<H>(node: akd::node_state::Node<H>) -> crate::types::Node
where
    H: winter_crypto::Hasher,
{
    crate::types::Node {
        label: convert_label(node.label),
        hash: to_digest::<H>(node.hash),
    }
}

fn convert_layer_proof<H>(
    parent: akd::node_state::NodeLabel,
    direction: akd::Direction,
    sibling: akd::node_state::Node<H>,
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

fn convert_lookup_proof<H>(proof: &akd::proof_structs::LookupProof<H>) -> crate::types::LookupProof
where
    H: winter_crypto::Hasher,
{
    crate::types::LookupProof {
        epoch: proof.epoch,
        version: proof.version,
        plaintext_value: proof.plaintext_value.0.as_bytes().to_vec(),
        marker_proof: convert_membership_proof(&proof.marker_proof),
        existence_proof: convert_membership_proof(&proof.existence_proof),
        freshness_proof: convert_non_membership_proof(&proof.freshness_proof),
    }
}

// ===================================
// Test cases
// ===================================

#[tokio::test]
async fn test_simple_lookup() -> Result<(), AkdError> {
    let db = InMemoryDb::new();
    let mut akd = Directory::new::<Hash>(&db).await?;

    let mut updates = vec![];
    for i in 0..15 {
        updates.push((
            AkdLabel(format!("hello{}", i)),
            AkdValue(format!("hello{}", i)),
        ));
    }

    akd.publish::<Hash>(updates, true).await?;

    let target_label = AkdLabel(format!("hello{}", 10));

    // retrieve the lookup proof
    let lookup_proof = akd.lookup(target_label.clone()).await?;
    // retrieve the root hash
    let current_azks = akd.retrieve_current_azks().await?;
    let root_hash = akd.get_root_hash::<Hash>(&current_azks).await?;

    // create the "lean" lookup proof version
    let internal_lookup_proof = convert_lookup_proof::<Hash>(&lookup_proof);

    // perform the "traditional" AKD verification
    let akd_result = akd::client::lookup_verify::<Hash>(root_hash, target_label, lookup_proof);

    let lean_result =
        crate::verify::lookup_verify(to_digest::<Hash>(root_hash), vec![], internal_lookup_proof)
            .map_err(|i_err| AkdError::AzksNotFound(format!("Internal: {:?}", i_err)));
    // check the two results to make sure they both verify
    assert!(matches!(akd_result, Ok(())));
    assert!(matches!(lean_result, Ok(())));

    Ok(())
}

// NOTE: There is a problem with "small" AKD trees that appears to only manifest with
// SHA3 256 hashing

// #[tokio::test]
// async fn test_simple_lookup_for_small_tree() -> Result<(), AkdError> {
//     let db = InMemoryDb::new();
//     let mut akd = Directory::new::<Hash>(&db).await?;

//     let mut updates = vec![];
//     for i in 0..1 {
//         updates.push((
//             AkdLabel(format!("hello{}", i)),
//             AkdValue(format!("hello{}", i)),
//         ));
//     }

//     akd.publish::<Hash>(updates, true).await?;

//     let target_label = AkdLabel(format!("hello{}", 0));

//     // retrieve the lookup proof
//     let lookup_proof = akd.lookup(target_label.clone()).await?;
//     // retrieve the root hash
//     let current_azks = akd.retrieve_current_azks().await?;
//     let root_hash = akd.get_root_hash::<Hash>(&current_azks).await?;

//     // create the "lean" lookup proof version
//     let internal_lookup_proof = convert_lookup_proof::<Hash>(&lookup_proof);

//     // perform the "traditional" AKD verification
//     let akd_result =
//         akd::client::lookup_verify::<Hash>(root_hash, target_label, lookup_proof);

//     let lean_result =
//         crate::verify::lookup_verify(to_digest::<Hash>(root_hash), vec![], internal_lookup_proof)
//             .map_err(|i_err| AkdError::AzksNotFound(format!("Internal: {:?}", i_err)));
//     // check the two results to make sure they both verify
//     assert!(matches!(akd_result, Ok(())));
//     assert!(matches!(lean_result, Ok(())));

//     Ok(())
// }
