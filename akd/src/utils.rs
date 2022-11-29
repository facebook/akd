// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

// 1. Create a hashmap of all prefixes of all elements of the insertion set
// 2. For each node in current_nodes set, check if each child is in prefix hashmap
// 3. If so, add child label to batch set

use crate::{
    NodeLabel,
    EMPTY_LABEL, EMPTY_VALUE,
};
use std::collections::HashSet;

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

pub(crate) fn empty_node_hash() -> crate::Digest {
    akd_core::hash::merge(&[akd_core::hash::hash(&EMPTY_VALUE), EMPTY_LABEL.hash()])
}

pub(crate) fn empty_node_hash_no_label() -> crate::Digest {
    akd_core::hash::hash(&EMPTY_VALUE)
}


// Creates a byte array of 32 bytes from a u64
// Note that this representation is big-endian, and
// places the bits to the front of the output byte_array.
pub(crate) fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[cfg(any(test, feature = "public_tests"))]
pub(crate) fn random_label(rng: &mut rand::rngs::OsRng) -> crate::NodeLabel {
    use crate::rand::Rng;
    crate::NodeLabel {
        label_val: rng.gen::<[u8; 32]>(),
        label_len: 256,
    }
}