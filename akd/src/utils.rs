// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

use std::collections::HashMap;
use rand::Rng;

/// Create a hashmap of all prefixes of all elements of the node set.
/// For each node in current_nodes set, check if each child is in the prefix hashmap.
/// If so, add child label to batch set.
fn create_batch_set(current_nodes: &[Node], prefix_map: &HashMap<NodeLabel, usize>) -> Vec<ChildLabel> {
    let mut batch_set = Vec::new();
    
    for node in current_nodes {
        for child in &node.children {
            if let Some(index) = prefix_map.get(&child.label) {
                batch_set.push(child.label.clone());
            }
        }
    }
    
    batch_set
}

/// Creates a byte array of 32 bytes from a u64.
/// Note that this representation is big-endian, and
/// places the bits to the front of the output byte_array.
#[cfg(any(test, feature = "public-tests"))]
pub(crate) fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[allow(unused)]
#[cfg(any(test, feature = "public-tests"))]
pub(crate) fn random_label(rng: &mut impl rand::Rng) -> crate::NodeLabel {
    crate::NodeLabel {
        label_val: rng.gen::<[u8; 32]>(),
        label_len: 256,
    }
}
