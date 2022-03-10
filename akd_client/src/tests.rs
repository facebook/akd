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

use akd::ecvrf::HardCodedAkdVRF;

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::vec;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;

use akd::errors::{AkdError, StorageError};
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
type Directory = akd::directory::Directory<InMemoryDb, HardCodedAkdVRF>;

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

fn to_digest_vec<H>(hash_vec: Vec<H::Digest>) -> Vec<crate::types::Digest>
where
    H: winter_crypto::Hasher,
{
    let mut digest_vec = Vec::<crate::types::Digest>::new();
    for hash_elem in hash_vec {
        digest_vec.push(to_digest::<H>(hash_elem));
    }
    digest_vec
}

fn to_digest_vec_opt<H>(hash_vec: Vec<Option<H::Digest>>) -> Vec<Option<crate::types::Digest>>
where
    H: winter_crypto::Hasher,
{
    let mut digest_vec_opt = Vec::<Option<crate::types::Digest>>::new();
    for hash_elem in hash_vec {
        if let Some(h) = hash_elem {
            digest_vec_opt.push(Some(to_digest::<H>(h)));
        } else {
            digest_vec_opt.push(None);
        }
    }
    digest_vec_opt
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
        exisitence_vrf_proof: proof.exisitence_vrf_proof.clone(),
        existence_proof: convert_membership_proof(&proof.existence_proof),
        marker_vrf_proof: proof.marker_vrf_proof.clone(),
        marker_proof: convert_membership_proof(&proof.marker_proof),
        freshness_vrf_proof: proof.freshness_vrf_proof.clone(),
        freshness_proof: convert_non_membership_proof(&proof.freshness_proof),
    }
}

fn convert_history_proof<H>(
    history_proof: &akd::proof_structs::HistoryProof<H>,
) -> crate::types::HistoryProof
where
    H: winter_crypto::Hasher,
{
    let mut res_update_proofs = Vec::<crate::types::UpdateProof>::new();
    for proof in &history_proof.proofs {
        let update_proof = crate::types::UpdateProof {
            epoch: proof.epoch,
            plaintext_value: proof.plaintext_value.0.as_bytes().to_vec(),
            version: proof.version,
            existence_vrf_proof: proof.existence_vrf_proof.clone(),
            existence_at_ep: convert_membership_proof(&proof.existence_at_ep),
            previous_val_vrf_proof: proof.previous_val_vrf_proof.clone(),
            previous_val_stale_at_ep: proof
                .previous_val_stale_at_ep
                .clone()
                .map(|val| convert_membership_proof(&val)),
            non_existence_before_ep: proof
                .non_existence_before_ep
                .clone()
                .map(|val| convert_non_membership_proof(&val)),
            next_few_vrf_proofs: proof.next_few_vrf_proofs.clone(),
            non_existence_of_next_few: proof
                .non_existence_of_next_few
                .iter()
                .map(|non_memb_proof| convert_non_membership_proof(non_memb_proof))
                .collect(),
            future_marker_vrf_proofs: proof.future_marker_vrf_proofs.clone(),
            non_existence_of_future_markers: proof
                .non_existence_of_future_markers
                .iter()
                .map(|non_exist_markers| convert_non_membership_proof(non_exist_markers))
                .collect(),
        };
        res_update_proofs.push(update_proof);
    }
    crate::types::HistoryProof {
        proofs: res_update_proofs,
    }
}

// ===================================
// Test cases
// ===================================

#[tokio::test]
async fn test_simple_lookup() -> Result<(), AkdError> {
    let db = InMemoryDb::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new::<Hash>(&db, &vrf, false).await?;

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
    let vrf_pk = akd.get_public_key().await.unwrap();
    // create the "lean" lookup proof version
    let internal_lookup_proof = convert_lookup_proof::<Hash>(&lookup_proof);

    // perform the "traditional" AKD verification
    let akd_result =
        akd::client::lookup_verify::<Hash>(&vrf_pk, root_hash, target_label.clone(), lookup_proof);

    let target_label_bytes = target_label.0.as_bytes().to_vec();

    let lean_result = crate::verify::lookup_verify(
        &vrf_pk.to_bytes(),
        to_digest::<Hash>(root_hash),
        target_label_bytes,
        internal_lookup_proof,
    )
    .map_err(|i_err| AkdError::Storage(StorageError::Other(format!("Internal: {:?}", i_err))));
    // check the two results to make sure they both verify
    assert!(matches!(akd_result, Ok(())));
    assert!(matches!(lean_result, Ok(())));

    Ok(())
}

#[tokio::test]
async fn test_history_proof_multiple_epochs() -> Result<(), AkdError> {
    let db = InMemoryDb::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new::<Hash>(&db, &vrf, false).await?;
    let vrf_pk = akd.get_public_key().await.unwrap();
    let key = AkdLabel("label".to_string());
    let key_bytes = key.0.as_bytes().to_vec();
    const EPOCHS: usize = 10;

    // publishes key versions in multiple epochs
    for epoch in 1..=EPOCHS {
        let data = vec![(key.clone(), AkdValue(format!("value{}", epoch)))];
        akd.publish::<Hash>(data, true).await?;
    }

    // retrieves and verifies history proofs for the key
    let proof = akd.key_history::<Hash>(&key).await?;
    let internal_proof = convert_history_proof::<Hash>(&proof);
    let (mut root_hashes, previous_root_hashes) =
        akd::directory::get_key_history_hashes::<_, Hash, HardCodedAkdVRF>(&akd, &proof)
            .await
            .unwrap();

    // verifies num of root hashes created
    assert_eq!(root_hashes.len(), EPOCHS);

    // verifies both traditional and lean history verification passes
    {
        let akd_result = akd::client::key_history_verify::<Hash>(
            &vrf_pk,
            root_hashes.clone(),
            previous_root_hashes.clone(),
            key.clone(),
            proof.clone(),
        );
        let lean_result = crate::verify::key_history_verify(
            &vrf_pk.to_bytes(),
            to_digest_vec::<Hash>(root_hashes.clone()),
            to_digest_vec_opt::<Hash>(previous_root_hashes.clone()),
            key_bytes.clone(),
            internal_proof.clone(),
        );
        assert!(matches!(akd_result, Ok(())), "{:?}", akd_result);
        assert!(matches!(lean_result, Ok(())), "{:?}", lean_result);
    }

    // corrupts root_hashes[0] and verifies both traditional and lean history verification fail
    {
        root_hashes[0] = root_hashes[1];
        // performs traditional AKD verification
        let akd_result = akd::client::key_history_verify::<Hash>(
            &vrf_pk,
            root_hashes.clone(),
            previous_root_hashes.clone(),
            key.clone(),
            proof.clone(),
        );
        // performs "lean" history verification
        let lean_result = crate::verify::key_history_verify(
            &vrf_pk.to_bytes(),
            to_digest_vec::<Hash>(root_hashes),
            to_digest_vec_opt::<Hash>(previous_root_hashes),
            key_bytes,
            internal_proof,
        );
        assert!(akd_result.is_err(), "{:?}", akd_result);
        assert!(lean_result.is_err(), "{:?}", lean_result);
    }
    Ok(())
}

#[tokio::test]
async fn test_history_proof_single_epoch() -> Result<(), AkdError> {
    let db = InMemoryDb::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::new::<Hash>(&db, &vrf, false).await?;
    let vrf_pk = akd.get_public_key().await.unwrap();
    let key = AkdLabel("label".to_string());
    let key_bytes = key.0.as_bytes().to_vec();

    // publishes single key-value
    akd.publish::<Hash>(vec![(key.clone(), AkdValue("value".to_string()))], true)
        .await?;

    // retrieves and verifies history proofs for the key
    let proof = akd.key_history::<Hash>(&key).await?;
    let internal_proof = convert_history_proof::<Hash>(&proof);
    let (root_hashes, previous_root_hashes) =
        akd::directory::get_key_history_hashes::<_, Hash, HardCodedAkdVRF>(&akd, &proof)
            .await
            .unwrap();
    assert_eq!(root_hashes.len(), 1);

    // verifies both traditional and lean history verification passes
    let akd_result = akd::client::key_history_verify::<Hash>(
        &vrf_pk,
        root_hashes.clone(),
        previous_root_hashes.clone(),
        key,
        proof,
    );
    let lean_result = crate::verify::key_history_verify(
        &vrf_pk.to_bytes(),
        to_digest_vec::<Hash>(root_hashes),
        to_digest_vec_opt::<Hash>(previous_root_hashes),
        key_bytes,
        internal_proof,
    );
    assert!(matches!(akd_result, Ok(())), "{:?}", akd_result);
    assert!(matches!(lean_result, Ok(())), "{:?}", lean_result);
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
