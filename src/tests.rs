// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::convert::TryInto;

use crypto::{hash::Blake3_256, Hasher};

use crate::{
    history_tree_node::get_empty_root,
    history_tree_node::get_interior_node,
    history_tree_node::get_leaf_node,
    history_tree_node::HistoryTreeNode,
    history_tree_node::NodeType,
    node_state::HistoryChildState,
    node_state::HistoryNodeState,
    node_state::{hash_label, NodeLabel},
    *,
};

////////// history_tree_node tests //////
//  Test set_child_without_hash and get_child_at_existing_epoch

#[test]
fn test_set_child_without_hash_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut root = &mut get_empty_root::<Blake3_256>(Option::None);
    let ep = 1;
    let mut child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3_256::hash(&[0u8]), ep);
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(1), child_hist_node_1))
            .is_ok(),
        "Setting the child without hash threw an error"
    );

    let set_child = root
        .get_child_at_existing_epoch(ep, Direction::Some(1))
        .map_err(|_| panic!("Child not set in test_set_child_without_hash_at_root"))?;
    assert!(
        set_child == child_hist_node_1,
        "Child in direction is not equal to the set value"
    );
    assert!(
        root.get_latest_epoch().unwrap_or(0) == 1,
        "Latest epochs don't match!"
    );
    assert!(root.epochs.len() == 1, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");
    assert!(
        root.state_map.keys().len() == 1,
        "State map has too many epochs"
    );

    Ok(())
}

#[test]
fn test_set_children_without_hash_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut root = &mut get_empty_root::<Blake3_256>(Option::None);
    let ep = 1;
    let child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3_256::hash(&[0u8]), ep);
    let child_hist_node_2: HistoryChildState<Blake3_256> =
        HistoryChildState::new(2, NodeLabel::new(0, 1), Blake3_256::hash(&[0u8]), ep);
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(1), child_hist_node_1))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(0), child_hist_node_2))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root.get_child_at_existing_epoch(ep, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_1,
            "Child in 1 is not equal to the set value"
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_existing_epoch(ep, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_2,
            "Child in 0 is not equal to the set value"
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 1, "Latest epochs don't match!");
    assert!(root.epochs.len() == 1, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");
    assert!(
        root.state_map.keys().len() == 1,
        "State map has too many epochs"
    );

    Ok(())
}

#[test]
fn test_set_children_without_hash_multiple_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut root = &mut get_empty_root::<Blake3_256>(Option::None);
    let mut ep = 1;
    let child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(11, 2), Blake3_256::hash(&[0u8]), ep);
    let child_hist_node_2: HistoryChildState<Blake3_256> =
        HistoryChildState::new(2, NodeLabel::new(00, 2), Blake3_256::hash(&[0u8]), ep);
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(1), child_hist_node_1))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(0), child_hist_node_2))
            .is_ok(),
        "Setting the child without hash threw an error"
    );

    ep = 2;

    let child_hist_node_3: HistoryChildState<Blake3_256> =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3_256::hash(&[0u8]), ep);
    let child_hist_node_4: HistoryChildState<Blake3_256> =
        HistoryChildState::new(2, NodeLabel::new(0, 1), Blake3_256::hash(&[0u8]), ep);
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(1), child_hist_node_3))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(0), child_hist_node_4))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root.get_child_at_existing_epoch(ep, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_3,
            "Child in 1 is not equal to the set value"
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_existing_epoch(ep, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_4,
            "Child in 0 is not equal to the set value"
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 2, "Latest epochs don't match!");
    assert!(root.epochs.len() == 2, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");
    assert!(
        root.state_map.keys().len() == 2,
        "State map has too many epochs"
    );

    Ok(())
}

#[test]
fn test_get_child_at_existing_epoch_multiple_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut root = &mut get_empty_root::<Blake3_256>(Option::None);
    let mut ep = 1;
    let child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(11, 2), Blake3_256::hash(&[0u8]), ep);
    let child_hist_node_2: HistoryChildState<Blake3_256> =
        HistoryChildState::new(2, NodeLabel::new(00, 2), Blake3_256::hash(&[0u8]), ep);
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(1), child_hist_node_1))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(0), child_hist_node_2))
            .is_ok(),
        "Setting the child without hash threw an error"
    );

    ep = 2;

    let child_hist_node_3: HistoryChildState<Blake3_256> =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3_256::hash(&[0u8]), ep);
    let child_hist_node_4: HistoryChildState<Blake3_256> =
        HistoryChildState::new(2, NodeLabel::new(0, 1), Blake3_256::hash(&[0u8]), ep);
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(1), child_hist_node_3))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, (Direction::Some(0), child_hist_node_4))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root.get_child_at_existing_epoch(1, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_1,
            "Child in 1 is not equal to the set value"
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_existing_epoch(1, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_2,
            "Child in 0 is not equal to the set value"
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 2, "Latest epochs don't match!");
    assert!(root.epochs.len() == 2, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");
    assert!(
        root.state_map.keys().len() == 2,
        "State map has too many epochs"
    );

    Ok(())
}

//  Test get_child_at_epoch
#[test]
pub fn test_get_child_at_epoch_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut root = &mut get_empty_root::<Blake3_256>(Option::None);

    for ep in 0u64..3u64 {
        let child_hist_node_1 = HistoryChildState::new(
            ep.try_into().unwrap(),
            NodeLabel::new(0b1u64 << ep.clone(), ep.try_into().unwrap()),
            Blake3_256::hash(&[0u8]),
            2 * ep,
        );
        let child_hist_node_2: HistoryChildState<Blake3_256> = HistoryChildState::new(
            ep.try_into().unwrap(),
            NodeLabel::new(0, ep.clone().try_into().unwrap()),
            Blake3_256::hash(&[0u8]),
            2 * ep,
        );
        assert!(
            root.set_child_without_hash(2 * ep, (Direction::Some(1), child_hist_node_1))
                .is_ok(),
            "Setting the child without hash threw an error"
        );
        assert!(
            root.set_child_without_hash(2 * ep, (Direction::Some(0), child_hist_node_2))
                .is_ok(),
            "Setting the child without hash threw an error"
        );
    }

    let ep_existing = 0u64;
    let ep_test = 1u64;

    let child_hist_node_1 = HistoryChildState::new(
        0,
        NodeLabel::new(
            0b1u64 << ep_existing.clone(),
            ep_existing.try_into().unwrap(),
        ),
        Blake3_256::hash(&[0u8]),
        2 * ep_existing,
    );
    let child_hist_node_2: HistoryChildState<Blake3_256> = HistoryChildState::new(
        0,
        NodeLabel::new(0, ep_existing.clone().try_into().unwrap()),
        Blake3_256::hash(&[0u8]),
        2 * ep_existing,
    );

    let set_child_1 = root.get_child_at_epoch(1, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_1,
            "Child in 1 is not equal to the set value = {:?}",
            child_st
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_epoch(1, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_2,
            "Child in 0 is not equal to the set value"
        ),
        Err(e) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 4, "Latest epochs don't match!");
    assert!(root.epochs.len() == 3, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");
    assert!(
        root.state_map.keys().len() == 3,
        "State map has too many epochs"
    );

    Ok(())
}

// update_hash tests
// #[test]
fn test_update_hash_root_children() -> Result<(), HistoryTreeNodeError> {
    let mut root = get_empty_root::<Blake3_256>(Option::None);
    let mut new_leaf: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b0u64, 1u32), 1, &[0u8], 0, 0);

    let mut leaf_1: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b1u64, 1u32), 2, &[1u8], 0, 0);

    root.set_node_child_without_hash(0, Direction::Some(0), new_leaf.clone());
    root.set_node_child_without_hash(0, Direction::Some(1), leaf_1.clone());

    let mut tree_repr = vec![root.clone(), new_leaf.clone(), leaf_1.clone()];

    let tree_repr_after_0 = new_leaf.clone().update_hash(0, tree_repr.clone());
    match tree_repr_after_0 {
        Ok(repr) => {
            tree_repr = repr.clone();
        }
        Err(e) => {
            eprintln!("Application error: {}", e);
            panic!("Node failed to update hash, the node is {:?}", new_leaf);
        }
    }
    let tree_repr_after_1 = leaf_1.clone().update_hash(0, tree_repr.clone());

    match tree_repr_after_1 {
        Ok(repr) => {
            tree_repr = repr.clone();
        }
        Err(e) => {
            eprintln!("Application error: {}", e);
            panic!("Node failed to update hash, the node is {:?}", leaf_1);
        }
    }

    root = tree_repr[0].clone();
    let tree_repr_after_root = root.update_hash(0, tree_repr.clone());
    match tree_repr_after_root {
        Ok(repr) => {
            tree_repr = repr.clone();
        }
        Err(e) => {
            eprintln!("Application error: {}", e);
            panic!("Node failed to update hash, the node is {:?}", root);
        }
    }

    let root_val = *root.get_value()?;

    let expected = Blake3_256::merge(&[
        Blake3_256::merge(&[
            hash_label::<Blake3_256>(root.label),
            Blake3_256::merge(&[
                hash_label::<Blake3_256>(new_leaf.label),
                Blake3_256::hash(&[0b0u8]),
            ]),
        ]),
        Blake3_256::merge(&[
            hash_label::<Blake3_256>(leaf_1.label),
            Blake3_256::hash(&[0b1u8]),
        ]),
    ]);
    assert!(root_val == expected, "Root hash not equal to expected");

    Ok(())
}

// insert_single_leaf tests

#[test]
fn test_insert_single_leaf_root() -> Result<(), HistoryTreeNodeError> {
    let mut root = get_empty_root::<Blake3_256>(Option::Some(0u64));
    let mut new_leaf: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b0u64, 1u32), 1, &[0u8], 0, 0);

    let mut leaf_1: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b1u64, 1u32), 2, &[1u8], 0, 0);
    let mut tree_repr = vec![root.clone()];

    let (new_root, repr) = root.insert_single_leaf(new_leaf.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let (new_root, repr) = root.insert_single_leaf(leaf_1.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let root_val = *root.get_value()?;

    let leaf_0_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b0u8])]),
        hash_label::<Blake3_256>(new_leaf.label),
    ]);

    let leaf_1_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b1u8])]),
        hash_label::<Blake3_256>(leaf_1.label),
    ]);

    let expected = Blake3_256::merge(&[
        Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), leaf_0_hash]),
            leaf_1_hash,
        ]),
        hash_label::<Blake3_256>(root.label),
    ]);
    assert!(root_val == expected, "Root hash not equal to expected");

    Ok(())
}

#[test]
fn test_insert_single_leaf_below_root() -> Result<(), HistoryTreeNodeError> {
    let mut root = get_empty_root::<Blake3_256>(Option::Some(0u64));
    let mut new_leaf: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b00u64, 2u32), 1, &[0u8], 0, 0);

    let mut leaf_1: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b11u64, 2u32), 2, &[1u8], 0, 0);

    let mut leaf_2: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b10u64, 2u32), 3, &[1u8, 1u8], 0, 0);

    let leaf_0_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b0u8])]),
        hash_label::<Blake3_256>(new_leaf.label),
    ]);

    let leaf_1_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b1u8])]),
        hash_label::<Blake3_256>(leaf_1.label),
    ]);

    let leaf_2_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[1u8, 1u8])]),
        hash_label::<Blake3_256>(leaf_2.label),
    ]);

    let right_child_expected_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), leaf_2_hash]),
            leaf_1_hash,
        ]),
        hash_label::<Blake3_256>(NodeLabel::new(0b1u64, 1u32)),
    ]);

    let mut leaf_1_as_child = leaf_1.to_node_child_state()?;
    leaf_1_as_child.hash_val = leaf_1_hash;

    let mut leaf_2_as_child = leaf_2.to_node_child_state()?;
    leaf_2_as_child.hash_val = leaf_2_hash;

    let mut tree_repr = vec![root.clone()];

    let (new_root, repr) = root.insert_single_leaf(new_leaf.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let (new_root, repr) = root.insert_single_leaf(leaf_1.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let (new_root, repr) = root.insert_single_leaf(leaf_2.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let root_val = *root.get_value()?;

    let expected = Blake3_256::merge(&[
        Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), leaf_0_hash]),
            right_child_expected_hash,
        ]),
        hash_label::<Blake3_256>(root.label),
    ]);
    assert!(root_val == expected, "Root hash not equal to expected");
    Ok(())
}

#[test]
fn test_insert_single_leaf_below_root_both_sides() -> Result<(), HistoryTreeNodeError> {
    let mut root = get_empty_root::<Blake3_256>(Option::Some(0u64));
    let mut new_leaf: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b000u64, 3u32), 1, &[0u8], 0, 0);

    let mut leaf_1: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b111u64, 3u32), 2, &[1u8], 0, 0);

    let mut leaf_2: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b100u64, 3u32), 3, &[1u8, 1u8], 0, 0);

    let mut leaf_3: HistoryTreeNode<Blake3_256> =
        get_leaf_node::<Blake3_256>(NodeLabel::new(0b010u64, 3u32), 4, &[0u8, 1u8], 0, 0);

    let leaf_0_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b0u8])]),
        hash_label::<Blake3_256>(new_leaf.label),
    ]);

    let leaf_1_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b1u8])]),
        hash_label::<Blake3_256>(leaf_1.label),
    ]);
    let leaf_2_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b1u8, 0b1u8])]),
        hash_label::<Blake3_256>(leaf_2.label),
    ]);

    let leaf_3_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&[0b0u8, 0b1u8])]),
        hash_label::<Blake3_256>(leaf_3.label),
    ]);

    let right_child_expected_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), leaf_2_hash]),
            leaf_1_hash,
        ]),
        hash_label::<Blake3_256>(NodeLabel::new(0b1u64, 1u32)),
    ]);

    let left_child_expected_hash = Blake3_256::merge(&[
        Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), leaf_0_hash]),
            leaf_3_hash,
        ]),
        hash_label::<Blake3_256>(NodeLabel::new(0b0u64, 1u32)),
    ]);

    let mut leaf_0_as_child = new_leaf.to_node_child_state()?;
    leaf_0_as_child.hash_val = leaf_0_hash;

    let mut leaf_3_as_child = leaf_3.to_node_child_state()?;
    leaf_3_as_child.hash_val = leaf_3_hash;

    let mut tree_repr = vec![root.clone()];

    let (new_root, repr) = root.insert_single_leaf(new_leaf.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let (new_root, repr) = root.insert_single_leaf(leaf_1.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let (new_root, repr) = root.insert_single_leaf(leaf_2.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let (new_root, repr) = root.insert_single_leaf(leaf_3.clone(), 0, tree_repr)?;
    root = new_root;
    tree_repr = repr;

    let root_val = *root.get_value()?;

    let expected = Blake3_256::merge(&[
        Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), left_child_expected_hash]),
            right_child_expected_hash,
        ]),
        hash_label::<Blake3_256>(root.label),
    ]);
    assert!(root_val == expected, "Root hash not equal to expected");
    Ok(())
}

#[test]
fn test_insert_single_leaf_full_tree() -> Result<(), HistoryTreeNodeError> {
    let mut root = get_empty_root::<Blake3_256>(Option::Some(0u64));
    let mut tree_repr = vec![root.clone()];
    let mut leaves = Vec::<HistoryTreeNode<Blake3_256>>::new();
    let mut leaf_hashes = Vec::new();
    for i in 0u64..8u64 {
        let mut new_leaf: HistoryTreeNode<Blake3_256> = get_leaf_node::<Blake3_256>(
            NodeLabel::new(i.clone(), 3u32),
            leaves.len(),
            &i.to_ne_bytes(),
            0,
            0,
        );
        leaf_hashes.push(Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), Blake3_256::hash(&i.to_ne_bytes())]),
            hash_label::<Blake3_256>(new_leaf.label),
        ]));
        leaves.push(new_leaf);
    }

    let mut layer_1_hashes = Vec::new();
    let mut j = 0u64;
    for i in 0..4 {
        let left_child_hash = leaf_hashes[2 * i];
        let right_child_hash = leaf_hashes[2 * i + 1];
        layer_1_hashes.push(Blake3_256::merge(&[
            Blake3_256::merge(&[
                Blake3_256::merge(&[Blake3_256::hash(&[]), left_child_hash]),
                right_child_hash,
            ]),
            hash_label::<Blake3_256>(NodeLabel::new(j, 2u32)),
        ]));
        j += 1;
    }

    let mut layer_2_hashes = Vec::new();
    let mut j = 0u64;
    for i in 0..2 {
        let left_child_hash = layer_1_hashes[2 * i];
        let right_child_hash = layer_1_hashes[2 * i + 1];
        layer_2_hashes.push(Blake3_256::merge(&[
            Blake3_256::merge(&[
                Blake3_256::merge(&[Blake3_256::hash(&[]), left_child_hash]),
                right_child_hash,
            ]),
            hash_label::<Blake3_256>(NodeLabel::new(j, 1u32)),
        ]));
        j += 1;
    }

    let expected = Blake3_256::merge(&[
        Blake3_256::merge(&[
            Blake3_256::merge(&[Blake3_256::hash(&[]), layer_2_hashes[0]]),
            layer_2_hashes[1],
        ]),
        hash_label::<Blake3_256>(root.label),
    ]);

    for i in 0..8 {
        let (new_root, repr) = root.insert_single_leaf(leaves[7 - i].clone(), 0, tree_repr)?;
        root = new_root;
        tree_repr = repr;
    }

    let root_val = *root.get_value()?;

    assert!(root_val == expected, "Root hash not equal to expected");
    Ok(())
}
