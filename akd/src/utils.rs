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
    EMPTY_LABEL, EMPTY_VALUE,
};
use std::collections::HashSet;
use winter_crypto::Hasher;

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

pub(crate) fn empty_node_hash<H: Hasher>() -> H::Digest {
    H::merge(&[H::hash(&EMPTY_VALUE), hash_label::<H>(EMPTY_LABEL)])
}

pub(crate) fn empty_node_hash_no_label<H: Hasher>() -> H::Digest {
    H::hash(&EMPTY_VALUE)
}

// FIXME: Make a real commitment here, alongwith a blinding factor. See issue #123
/// Gets the bytes for a value.
pub(crate) fn value_to_bytes(value: &crate::AkdValue) -> Vec<u8> {
    value.0.clone()
}
