// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

// 1. Create a hashmap of all prefixes of all elements of the insertion set
// 2. For each node in current_nodes set, check if each child is in prefix hashmap
// 3. If so, add child label to batch set

use crate::{
    node_state::{hash_label, NodeLabel},
    storage::types::AkdValue,
    EMPTY_LABEL, EMPTY_VALUE,
};
use std::collections::HashSet;
use winter_crypto::{Digest, Hasher};

// Builds a set of all prefixes of the input labels
pub(crate) fn build_prefixes_set(labels: &[NodeLabel]) -> HashSet<NodeLabel> {
    let mut prefixes_set = HashSet::new();
    for label in labels {
        for len in 0..(label.get_len() + 1) {
            prefixes_set.insert(label.get_prefix(len));
        }
    }
    prefixes_set
}

pub(crate) fn build_lookup_prefixes_set(labels: &[NodeLabel]) -> HashSet<NodeLabel> {
    let mut lookup_prefixes_set = HashSet::new();
    for label in labels {
        // We need the actual node for lookup too
        lookup_prefixes_set.insert(*label);
        for len in 0..(label.get_len() + 1) {
            // Sibling prefixes unfortunately do not cover all the nodes we will need for
            // a lookup proof. Although we can figure out which nodes are exactly needed
            // this will require basically doing a pre-lookup.
            // Instead here we load the prefixes as well.
            // This combination (sibling- + self-prefixes) covers all the nodes we need.
            lookup_prefixes_set.insert(label.get_prefix(len));
            lookup_prefixes_set.insert(label.get_sibling_prefix(len));
        }
    }
    lookup_prefixes_set
}

pub(crate) fn empty_node_hash<H: Hasher>() -> H::Digest {
    H::merge(&[H::hash(&EMPTY_VALUE), hash_label::<H>(EMPTY_LABEL)])
}

pub(crate) fn empty_node_hash_no_label<H: Hasher>() -> H::Digest {
    H::hash(&EMPTY_VALUE)
}

// Corresponds to the I2OSP() function from RFC8017, prepending the length of
// a byte array to the byte array (so that it is ready for serialization and hashing)
//
// Input byte array cannot be > 2^64-1 in length
pub(crate) fn i2osp_array(input: &[u8]) -> Vec<u8> {
    [&(input.len() as u64).to_be_bytes(), input].concat()
}

// Commitment helper functions

// Used by the server to produce a commitment proof for an AkdLabel, version, and AkdValue
pub(crate) fn get_commitment_proof<H: Hasher>(
    commitment_key: &[u8],
    label: &NodeLabel,
    value: &AkdValue,
) -> H::Digest {
    H::hash(&[commitment_key, &label.val, &i2osp_array(value)].concat())
}

// Used by the server to produce a commitment for an AkdLabel, version, and AkdValue
//
// proof = H(commitment_key, label, version, value)
// commmitment = H(value, proof)
//
// The proof value is a nonce used to create a hiding and binding commitment using a
// cryptographic hash function. Note that it is derived from the label, version, and
// value (even though the binding to value is somewhat optional).
//
// Note that this commitment needs to be a hash function (random oracle) output
pub(crate) fn commit_value<H: Hasher>(
    commitment_key: &[u8],
    label: &NodeLabel,
    value: &AkdValue,
) -> H::Digest {
    let proof = get_commitment_proof::<H>(commitment_key, label, value);
    H::hash(&[i2osp_array(value), i2osp_array(&proof.as_bytes())].concat())
}

// Used by the client to supply a commitment proof and value to reconstruct the commitment
pub(crate) fn bind_commitment<H: Hasher>(value: &AkdValue, proof: &[u8]) -> H::Digest {
    H::hash(&[i2osp_array(value), i2osp_array(proof)].concat())
}
