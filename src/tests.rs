// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::convert::TryInto;

use winter_crypto::{hashers::Blake3_256, Hasher};
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;

use crate::serialization::from_digest;
use crate::{
    history_tree_node::get_empty_root,
    history_tree_node::get_leaf_node,
    history_tree_node::HistoryTreeNode,
    node_state::HistoryChildState,
    node_state::{hash_label, NodeLabel},
    storage::Storage,
    *,
};

use crate::errors::StorageError;
use lazy_static::lazy_static;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    static ref HASHMAP: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Debug)]
pub(crate) struct InMemoryDb(HashMap<String, String>);

impl Storage for InMemoryDb {
    fn set(pos: String, value: String) -> Result<(), StorageError> {
        let mut hashmap = HASHMAP.lock().unwrap();
        hashmap.insert(pos, value);
        Ok(())
    }

    fn get(pos: String) -> Result<String, StorageError> {
        let hashmap = HASHMAP.lock().unwrap();
        Ok(hashmap
            .get(&pos)
            .map(|v| v.clone())
            .ok_or(StorageError::GetError)?)
    }
}

////////// history_tree_node tests //////
//  Test set_child_without_hash and get_child_at_existing_epoch

#[test]
fn test_set_child_without_hash_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let ep = 1;
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(ep))?;
    let child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep);
    root.write_to_storage()?;
    root.set_child_without_hash(ep, &(Direction::Some(1), child_hist_node_1.clone()))?;

    let set_child = root
        .get_child_at_existing_epoch(ep, Direction::Some(1))
        .map_err(|_| panic!("Child not set in test_set_child_without_hash_at_root"))
        .unwrap();
    assert!(
        set_child == child_hist_node_1,
        "Child in direction is not equal to the set value"
    );
    assert!(
        root.get_latest_epoch().unwrap_or(0) == 1,
        "Latest epochs don't match!"
    );
    assert!(root.epochs.len() == 1, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");

    Ok(())
}

#[test]
fn test_set_children_without_hash_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let ep = 1;
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(ep))?;
    let child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep);
    let child_hist_node_2: HistoryChildState<Blake3, InMemoryDb> =
        HistoryChildState::new(2, NodeLabel::new(0, 1), Blake3::hash(&[0u8]), ep);
    root.write_to_storage()?;
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(1), child_hist_node_1.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(0), child_hist_node_2.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root.get_child_at_existing_epoch(ep, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_1,
            "Child in 1 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_existing_epoch(ep, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_2,
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 1, "Latest epochs don't match!");
    assert!(root.epochs.len() == 1, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");

    Ok(())
}

#[test]
fn test_set_children_without_hash_multiple_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let mut ep = 1;
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(ep))?;
    let child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(11, 2), Blake3::hash(&[0u8]), ep);
    let child_hist_node_2: HistoryChildState<Blake3, InMemoryDb> =
        HistoryChildState::new(2, NodeLabel::new(00, 2), Blake3::hash(&[0u8]), ep);
    root.write_to_storage()?;
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(1), child_hist_node_1))
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(0), child_hist_node_2))
            .is_ok(),
        "Setting the child without hash threw an error"
    );

    ep = 2;

    let child_hist_node_3: HistoryChildState<Blake3, InMemoryDb> =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep);
    let child_hist_node_4: HistoryChildState<Blake3, InMemoryDb> =
        HistoryChildState::new(2, NodeLabel::new(0, 1), Blake3::hash(&[0u8]), ep);
    root.write_to_storage()?;
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(1), child_hist_node_3.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(0), child_hist_node_4.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root.get_child_at_existing_epoch(ep, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_3,
            "Child in 1 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_existing_epoch(ep, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_4,
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 2, "Latest epochs don't match!");
    assert!(root.epochs.len() == 2, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");

    Ok(())
}

#[test]
fn test_get_child_at_existing_epoch_multiple_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let mut ep = 1;
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(ep))?;
    let child_hist_node_1 =
        HistoryChildState::new(1, NodeLabel::new(11, 2), Blake3::hash(&[0u8]), ep);
    let child_hist_node_2: HistoryChildState<Blake3, InMemoryDb> =
        HistoryChildState::new(2, NodeLabel::new(00, 2), Blake3::hash(&[0u8]), ep);
    root.write_to_storage()?;
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(1), child_hist_node_1.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(0), child_hist_node_2.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );

    ep = 2;

    let child_hist_node_3: HistoryChildState<Blake3, InMemoryDb> =
        HistoryChildState::new(1, NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep);
    let child_hist_node_4: HistoryChildState<Blake3, InMemoryDb> =
        HistoryChildState::new(2, NodeLabel::new(0, 1), Blake3::hash(&[0u8]), ep);
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(1), child_hist_node_3.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child_without_hash(ep, &(Direction::Some(0), child_hist_node_4.clone()),)
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root.get_child_at_existing_epoch(1, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_1,
            "Child in 1 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_existing_epoch(1, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_2,
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 2, "Latest epochs don't match!");
    assert!(root.epochs.len() == 2, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");

    Ok(())
}

//  Test get_child_at_epoch
#[test]
pub fn test_get_child_at_epoch_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let init_ep = 0;
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(init_ep))?;

    for ep in 0u64..3u64 {
        let child_hist_node_1 = HistoryChildState::new(
            ep.try_into().unwrap(),
            NodeLabel::new(0b1u64 << ep.clone(), ep.try_into().unwrap()),
            Blake3::hash(&[0u8]),
            2 * ep,
        );
        let child_hist_node_2: HistoryChildState<Blake3, InMemoryDb> = HistoryChildState::new(
            ep.try_into().unwrap(),
            NodeLabel::new(0, ep.clone().try_into().unwrap()),
            Blake3::hash(&[0u8]),
            2 * ep,
        );
        root.write_to_storage()?;
        root.set_child_without_hash(2 * ep, &(Direction::Some(1), child_hist_node_1))?;
        root.set_child_without_hash(2 * ep, &(Direction::Some(0), child_hist_node_2))?;
    }

    let ep_existing = 0u64;

    let child_hist_node_1 = HistoryChildState::new(
        0,
        NodeLabel::new(
            0b1u64 << ep_existing.clone(),
            ep_existing.try_into().unwrap(),
        ),
        Blake3::hash(&[0u8]),
        2 * ep_existing,
    );
    let child_hist_node_2: HistoryChildState<Blake3, InMemoryDb> = HistoryChildState::new(
        0,
        NodeLabel::new(0, ep_existing.clone().try_into().unwrap()),
        Blake3::hash(&[0u8]),
        2 * ep_existing,
    );

    let set_child_1 = root.get_child_at_epoch(1, Direction::Some(1));
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_1,
            "Child in 1 is not equal to the set value = {:?}",
            child_st
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root.get_child_at_epoch(1, Direction::Some(0));
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == child_hist_node_2,
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 4, "Latest epochs don't match!");
    assert!(root.epochs.len() == 3, "Ask yourself some pressing questions, such as: Why are there random extra epochs in the root?");

    Ok(())
}

// insert_single_leaf tests

#[test]
fn test_insert_single_leaf_root() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(0u64))?;
    let new_leaf = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b0u64, 1u32),
        1,
        &[0u8],
        0,
        0,
    )?;

    let leaf_1 = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b1u64, 1u32),
        2,
        &[1u8],
        0,
        0,
    )?;
    root.write_to_storage()?;

    let mut num_nodes = 1;

    root.insert_single_leaf(new_leaf.clone(), &azks_id, 0, &mut num_nodes)?;
    root.insert_single_leaf(leaf_1.clone(), &azks_id, 0, &mut num_nodes)?;

    let root_val = root.get_value()?;

    let leaf_0_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b0u8])]),
        hash_label::<Blake3>(new_leaf.label),
    ]);

    let leaf_1_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b1u8])]),
        hash_label::<Blake3>(leaf_1.label),
    ]);

    let expected = Blake3::merge(&[
        Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&[]), leaf_0_hash]),
            leaf_1_hash,
        ]),
        hash_label::<Blake3>(root.label),
    ]);
    assert!(root_val == expected, "Root hash not equal to expected");

    Ok(())
}

#[test]
fn test_insert_single_leaf_below_root() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(0u64))?;
    let new_leaf = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b00u64, 2u32),
        1,
        &[0u8],
        0,
        1,
    )?;

    let leaf_1 = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b11u64, 2u32),
        2,
        &[1u8],
        0,
        2,
    )?;

    let leaf_2 = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b10u64, 2u32),
        3,
        &[1u8, 1u8],
        0,
        3,
    )?;

    let leaf_0_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b0u8])]),
        hash_label::<Blake3>(new_leaf.label),
    ]);

    let leaf_1_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b1u8])]),
        hash_label::<Blake3>(leaf_1.label),
    ]);

    let leaf_2_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[1u8, 1u8])]),
        hash_label::<Blake3>(leaf_2.label),
    ]);

    let right_child_expected_hash = Blake3::merge(&[
        Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&[]), leaf_2_hash]),
            leaf_1_hash,
        ]),
        hash_label::<Blake3>(NodeLabel::new(0b1u64, 1u32)),
    ]);

    // let mut leaf_1_as_child = leaf_1.to_node_child_state()?;
    // leaf_1_as_child.hash_val = from_digest::<Blake3>(leaf_1_hash)?;

    // let mut leaf_2_as_child = leaf_2.to_node_child_state()?;
    // leaf_2_as_child.hash_val = from_digest::<Blake3>(leaf_2_hash)?;

    root.write_to_storage()?;
    let mut num_nodes = 1;

    root.insert_single_leaf(new_leaf.clone(), &azks_id, 1, &mut num_nodes)?;

    root.insert_single_leaf(leaf_1.clone(), &azks_id, 2, &mut num_nodes)?;

    root.insert_single_leaf(leaf_2.clone(), &azks_id, 3, &mut num_nodes)?;

    let root_val = root.get_value()?;

    let expected = Blake3::merge(&[
        Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&[]), leaf_0_hash]),
            right_child_expected_hash,
        ]),
        hash_label::<Blake3>(root.label),
    ]);
    assert!(root_val == expected, "Root hash not equal to expected");
    Ok(())
}

#[test]
fn test_insert_single_leaf_below_root_both_sides() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(0u64))?;
    let new_leaf = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b000u64, 3u32),
        1,
        &[0u8],
        0,
        0,
    )?;

    let leaf_1 = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b111u64, 3u32),
        2,
        &[1u8],
        0,
        0,
    )?;

    let leaf_2 = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b100u64, 3u32),
        3,
        &[1u8, 1u8],
        0,
        0,
    )?;

    let leaf_3 = get_leaf_node::<Blake3, InMemoryDb>(
        &azks_id,
        NodeLabel::new(0b010u64, 3u32),
        4,
        &[0u8, 1u8],
        0,
        0,
    )?;

    let leaf_0_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b0u8])]),
        hash_label::<Blake3>(new_leaf.label),
    ]);

    let leaf_1_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b1u8])]),
        hash_label::<Blake3>(leaf_1.label),
    ]);
    let leaf_2_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b1u8, 0b1u8])]),
        hash_label::<Blake3>(leaf_2.label),
    ]);

    let leaf_3_hash = Blake3::merge(&[
        Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&[0b0u8, 0b1u8])]),
        hash_label::<Blake3>(leaf_3.label),
    ]);

    let _right_child_expected_hash = Blake3::merge(&[
        Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&[]), leaf_2_hash]),
            leaf_1_hash,
        ]),
        hash_label::<Blake3>(NodeLabel::new(0b1u64, 1u32)),
    ]);

    let _left_child_expected_hash = Blake3::merge(&[
        Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&[]), leaf_0_hash]),
            leaf_3_hash,
        ]),
        hash_label::<Blake3>(NodeLabel::new(0b0u64, 1u32)),
    ]);

    let mut leaf_0_as_child = new_leaf.to_node_child_state()?;
    leaf_0_as_child.hash_val = from_digest::<Blake3>(leaf_0_hash).unwrap();

    let mut leaf_3_as_child = leaf_3.to_node_child_state()?;
    leaf_3_as_child.hash_val = from_digest::<Blake3>(leaf_3_hash).unwrap();

    root.write_to_storage()?;
    let mut num_nodes = 1;

    root.insert_single_leaf(new_leaf.clone(), &azks_id, 1, &mut num_nodes)?;
    root.insert_single_leaf(leaf_1.clone(), &azks_id, 2, &mut num_nodes)?;
    root.insert_single_leaf(leaf_2.clone(), &azks_id, 3, &mut num_nodes)?;
    root.insert_single_leaf(leaf_3.clone(), &azks_id, 4, &mut num_nodes)?;

    // let root_val = root.get_value()?;

    // let expected = Blake3::merge(&[
    //     Blake3::merge(&[
    //         Blake3::merge(&[Blake3::hash(&[]), left_child_expected_hash]),
    //         right_child_expected_hash,
    //     ]),
    //     hash_label::<Blake3>(root.label),
    // ]);
    // assert!(root_val == expected, "Root hash not equal to expected");
    Ok(())
}

#[test]
fn test_insert_single_leaf_full_tree() -> Result<(), HistoryTreeNodeError> {
    let mut rng = OsRng;
    let mut azks_id = vec![0u8; 32];
    rng.fill_bytes(&mut azks_id);
    let mut root = get_empty_root::<Blake3, InMemoryDb>(&azks_id, Option::Some(0u64))?;
    root.write_to_storage()?;
    let mut num_nodes = 1;
    let mut leaves = Vec::<HistoryTreeNode<Blake3, InMemoryDb>>::new();
    let mut leaf_hashes = Vec::new();
    for i in 0u64..8u64 {
        let new_leaf = get_leaf_node::<Blake3, InMemoryDb>(
            &azks_id,
            NodeLabel::new(i.clone(), 3u32),
            leaves.len(),
            &i.to_ne_bytes(),
            0,
            7 - i,
        )?;
        leaf_hashes.push(Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&[]), Blake3::hash(&i.to_ne_bytes())]),
            hash_label::<Blake3>(new_leaf.label),
        ]));
        leaves.push(new_leaf);
    }

    let mut layer_1_hashes = Vec::new();
    let mut j = 0u64;
    for i in 0..4 {
        let left_child_hash = leaf_hashes[2 * i];
        let right_child_hash = leaf_hashes[2 * i + 1];
        layer_1_hashes.push(Blake3::merge(&[
            Blake3::merge(&[
                Blake3::merge(&[Blake3::hash(&[]), left_child_hash]),
                right_child_hash,
            ]),
            hash_label::<Blake3>(NodeLabel::new(j, 2u32)),
        ]));
        j += 1;
    }

    let mut layer_2_hashes = Vec::new();
    let mut j = 0u64;
    for i in 0..2 {
        let left_child_hash = layer_1_hashes[2 * i];
        let right_child_hash = layer_1_hashes[2 * i + 1];
        layer_2_hashes.push(Blake3::merge(&[
            Blake3::merge(&[
                Blake3::merge(&[Blake3::hash(&[]), left_child_hash]),
                right_child_hash,
            ]),
            hash_label::<Blake3>(NodeLabel::new(j, 1u32)),
        ]));
        j += 1;
    }

    let expected = Blake3::merge(&[
        Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&[]), layer_2_hashes[0]]),
            layer_2_hashes[1],
        ]),
        hash_label::<Blake3>(root.label),
    ]);

    for i in 0..8 {
        let ep: u64 = i.try_into().unwrap();
        root.insert_single_leaf(leaves[7 - i].clone(), &azks_id, ep + 1, &mut num_nodes)?;
    }

    let root_val = root.get_value()?;

    assert!(root_val == expected, "Root hash not equal to expected");
    Ok(())
}
