#![cfg(test)]
// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::convert::TryInto;

use winter_crypto::{hashers::Blake3_256, Hasher};
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;

use crate::serialization::from_digest;
use crate::{
    errors::*,
    history_tree_node::get_empty_root,
    history_tree_node::get_leaf_node,
    history_tree_node::HistoryTreeNode,
    node_state::HistoryChildState,
    node_state::{hash_label, NodeLabel},
    *,
};

type InMemoryDb = storage::memory::AsyncInMemoryDatabase;

////////// history_tree_node tests //////
//  Test set_child_without_hash and get_child_at_existing_epoch

#[tokio::test]
async fn test_set_child_without_hash_at_root() -> Result<(), HistoryTreeNodeError> {
    let ep = 1;
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    let child_hist_node_1 =
        HistoryChildState::new::<Blake3>(NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep).unwrap();
    root.write_to_storage(&db).await?;
    root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_1.clone()))
        .await?;

    let set_child = root
        .get_child_at_existing_epoch::<_, Blake3>(&db, ep, Direction::Some(1))
        .await
        .map_err(|_| panic!("Child not set in test_set_child_without_hash_at_root"))
        .unwrap();
    assert!(
        set_child == Some(child_hist_node_1),
        "Child in direction is not equal to the set value"
    );
    assert!(
        root.get_latest_epoch().unwrap_or(0) == 1,
        "Latest epochs don't match!"
    );
    assert!(
        root.birth_epoch == root.last_epoch,
        "How would the last epoch be different from the birth epoch without an update?"
    );

    Ok(())
}

#[tokio::test]
async fn test_set_children_without_hash_at_root() -> Result<(), HistoryTreeNodeError> {
    let ep = 1;
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    let child_hist_node_1 =
        HistoryChildState::new::<Blake3>(NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep).unwrap();
    let child_hist_node_2: HistoryChildState =
        HistoryChildState::new::<Blake3>(NodeLabel::new(0, 1), Blake3::hash(&[0u8]), ep).unwrap();
    root.write_to_storage(&db).await?;
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_1.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_2.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root
        .get_child_at_existing_epoch::<_, Blake3>(&db, ep, Direction::Some(1))
        .await;
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_1),
            "Child in 1 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root
        .get_child_at_existing_epoch::<_, Blake3>(&db, ep, Direction::Some(0))
        .await;
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_2),
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 1, "Latest epochs don't match!");
    assert!(
        root.birth_epoch == root.last_epoch,
        "How would the last epoch be different from the birth epoch without an update?"
    );

    Ok(())
}

#[tokio::test]
async fn test_set_children_without_hash_multiple_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut ep = 1;
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    let child_hist_node_1 =
        HistoryChildState::new::<Blake3>(NodeLabel::new(11, 2), Blake3::hash(&[0u8]), ep).unwrap();
    let child_hist_node_2: HistoryChildState =
        HistoryChildState::new::<Blake3>(NodeLabel::new(00, 2), Blake3::hash(&[0u8]), ep).unwrap();
    root.write_to_storage(&db).await?;
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_1))
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_2))
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );

    ep = 2;

    let child_hist_node_3: HistoryChildState =
        HistoryChildState::new::<Blake3>(NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep).unwrap();
    let child_hist_node_4: HistoryChildState =
        HistoryChildState::new::<Blake3>(NodeLabel::new(0, 1), Blake3::hash(&[0u8]), ep).unwrap();
    root.write_to_storage(&db).await?;
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_3.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_4.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root
        .get_child_at_existing_epoch::<_, Blake3>(&db, ep, Direction::Some(1))
        .await;
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_3),
            "Child in 1 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root
        .get_child_at_existing_epoch::<_, Blake3>(&db, ep, Direction::Some(0))
        .await;
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_4),
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 2, "Latest epochs don't match!");
    assert!(
        root.birth_epoch < root.last_epoch,
        "How is the last epoch not higher than the birth epoch after an udpate?"
    );

    Ok(())
}

#[tokio::test]
async fn test_get_child_at_existing_epoch_multiple_at_root() -> Result<(), HistoryTreeNodeError> {
    let mut ep = 1;
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    let child_hist_node_1 =
        HistoryChildState::new::<Blake3>(NodeLabel::new(11, 2), Blake3::hash(&[0u8]), ep).unwrap();
    let child_hist_node_2: HistoryChildState =
        HistoryChildState::new::<Blake3>(NodeLabel::new(00, 2), Blake3::hash(&[0u8]), ep).unwrap();
    root.write_to_storage(&db).await?;
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_1.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_2.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );

    ep = 2;

    let child_hist_node_3: HistoryChildState =
        HistoryChildState::new::<Blake3>(NodeLabel::new(1, 1), Blake3::hash(&[0u8]), ep).unwrap();
    let child_hist_node_4: HistoryChildState =
        HistoryChildState::new::<Blake3>(NodeLabel::new(0, 1), Blake3::hash(&[0u8]), ep).unwrap();
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_3.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    assert!(
        root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_4.clone()),)
            .await
            .is_ok(),
        "Setting the child without hash threw an error"
    );
    let set_child_1 = root
        .get_child_at_existing_epoch::<_, Blake3>(&db, 1, Direction::Some(1))
        .await;
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_1),
            "Child in 1 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root
        .get_child_at_existing_epoch::<_, Blake3>(&db, 1, Direction::Some(0))
        .await;
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_2),
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 2, "Latest epochs don't match!");
    assert!(
        root.birth_epoch < root.last_epoch,
        "How is the last epoch not higher than the birth epoch after an udpate?"
    );

    Ok(())
}

//  Test get_child_at_epoch
#[tokio::test]
pub async fn test_get_child_at_epoch_at_root() -> Result<(), HistoryTreeNodeError> {
    let init_ep = 0;
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(init_ep)).await?;

    for ep in 0..3 {
        let child_hist_node_1 = HistoryChildState::new::<Blake3>(
            NodeLabel::new(0b1u64 << ep, ep.try_into().unwrap()),
            Blake3::hash(&[0u8]),
            2 * ep,
        )
        .unwrap();
        let child_hist_node_2: HistoryChildState = HistoryChildState::new::<Blake3>(
            NodeLabel::new(0, ep.try_into().unwrap()),
            Blake3::hash(&[0u8]),
            2 * ep,
        )
        .unwrap();
        root.write_to_storage(&db).await?;
        root.set_child::<_, Blake3>(&db, 2 * ep, &(Direction::Some(1), child_hist_node_1))
            .await?;
        root.set_child::<_, Blake3>(&db, 2 * ep, &(Direction::Some(0), child_hist_node_2))
            .await?;
    }

    let ep_existing = 0u64;

    let child_hist_node_1 = HistoryChildState::new::<Blake3>(
        NodeLabel::new(0b1u64 << ep_existing, ep_existing.try_into().unwrap()),
        Blake3::hash(&[0u8]),
        2 * ep_existing,
    )
    .unwrap();
    let child_hist_node_2: HistoryChildState = HistoryChildState::new::<Blake3>(
        NodeLabel::new(0, ep_existing.try_into().unwrap()),
        Blake3::hash(&[0u8]),
        2 * ep_existing,
    )
    .unwrap();

    let set_child_1 = root
        .get_child_at_epoch::<_, Blake3>(&db, 1, Direction::Some(1))
        .await;
    match set_child_1 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_1),
            "Child in 1 is not equal to the set value = {:?}",
            child_st
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }

    let set_child_2 = root
        .get_child_at_epoch::<_, Blake3>(&db, 1, Direction::Some(0))
        .await;
    match set_child_2 {
        Ok(child_st) => assert!(
            child_st == Some(child_hist_node_2),
            "Child in 0 is not equal to the set value"
        ),
        Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    }
    let latest_ep = root.get_latest_epoch();
    assert!(latest_ep.unwrap_or(0) == 4, "Latest epochs don't match!");
    assert!(
        root.birth_epoch < root.last_epoch,
        "How is the last epoch not higher than the birth epoch after an udpate?"
    );

    Ok(())
}

// insert_single_leaf tests

#[tokio::test]
async fn test_insert_single_leaf_root() -> Result<(), HistoryTreeNodeError> {
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
    let new_leaf = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b0u64, 1u32),
        &[0u8],
        NodeLabel::root(),
        0,
    )
    .await?;

    let leaf_1 = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b1u64, 1u32),
        &[1u8],
        NodeLabel::root(),
        0,
    )
    .await?;
    root.write_to_storage(&db).await?;

    let mut num_nodes = 1;
    root.insert_single_leaf::<_, Blake3>(&db, new_leaf.clone(), 0, &mut num_nodes)
        .await?;

    println!("X1.5");
    root.insert_single_leaf::<_, Blake3>(&db, leaf_1.clone(), 0, &mut num_nodes)
        .await?;
    println!("X2");

    let root_val = root.get_value::<_, Blake3>(&db).await?;

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
    assert_eq!(root_val, expected, "Root hash not equal to expected");

    Ok(())
}

#[tokio::test]
async fn test_insert_single_leaf_below_root() -> Result<(), HistoryTreeNodeError> {
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
    let new_leaf = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b00u64, 2u32),
        &[0u8],
        NodeLabel::root(),
        1,
    )
    .await?;

    let leaf_1 = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b11u64, 2u32),
        &[1u8],
        NodeLabel::root(),
        2,
    )
    .await?;

    let leaf_2 = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b10u64, 2u32),
        &[1u8, 1u8],
        NodeLabel::root(),
        3,
    )
    .await?;

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

    root.write_to_storage(&db).await?;
    let mut num_nodes = 1;

    root.insert_single_leaf::<_, Blake3>(&db, new_leaf.clone(), 1, &mut num_nodes)
        .await?;

    root.insert_single_leaf::<_, Blake3>(&db, leaf_1.clone(), 2, &mut num_nodes)
        .await?;

    root.insert_single_leaf::<_, Blake3>(&db, leaf_2.clone(), 3, &mut num_nodes)
        .await?;

    let root_val = root.get_value::<_, Blake3>(&db).await?;

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

#[tokio::test]
async fn test_insert_single_leaf_below_root_both_sides() -> Result<(), HistoryTreeNodeError> {
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
    let new_leaf = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b000u64, 3u32),
        &[0u8],
        NodeLabel::root(),
        0,
    )
    .await?;

    let leaf_1 = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b111u64, 3u32),
        &[1u8],
        NodeLabel::root(),
        0,
    )
    .await?;

    let leaf_2 = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b100u64, 3u32),
        &[1u8, 1u8],
        NodeLabel::root(),
        0,
    )
    .await?;

    let leaf_3 = get_leaf_node::<Blake3, _>(
        &db,
        NodeLabel::new(0b010u64, 3u32),
        &[0u8, 1u8],
        NodeLabel::root(),
        0,
    )
    .await?;

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

    let mut leaf_0_as_child = new_leaf.to_node_child_state::<_, Blake3>(&db).await?;
    leaf_0_as_child.hash_val = from_digest::<Blake3>(leaf_0_hash).unwrap();

    let mut leaf_3_as_child = leaf_3.to_node_child_state::<_, Blake3>(&db).await?;
    leaf_3_as_child.hash_val = from_digest::<Blake3>(leaf_3_hash).unwrap();

    root.write_to_storage(&db).await?;
    let mut num_nodes = 1;

    root.insert_single_leaf::<_, Blake3>(&db, new_leaf.clone(), 1, &mut num_nodes)
        .await?;
    root.insert_single_leaf::<_, Blake3>(&db, leaf_1.clone(), 2, &mut num_nodes)
        .await?;
    root.insert_single_leaf::<_, Blake3>(&db, leaf_2.clone(), 3, &mut num_nodes)
        .await?;
    root.insert_single_leaf::<_, Blake3>(&db, leaf_3.clone(), 4, &mut num_nodes)
        .await?;

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

#[tokio::test]
async fn test_insert_single_leaf_full_tree() -> Result<(), HistoryTreeNodeError> {
    let db = InMemoryDb::new();
    let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
    root.write_to_storage(&db).await?;
    let mut num_nodes = 1;
    let mut leaves = Vec::<HistoryTreeNode>::new();
    let mut leaf_hashes = Vec::new();
    for i in 0u64..8u64 {
        let new_leaf = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(i, 3u32),
            &i.to_ne_bytes(),
            NodeLabel::root(),
            7 - i,
        )
        .await?;
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
        root.insert_single_leaf::<_, Blake3>(&db, leaves[7 - i].clone(), ep + 1, &mut num_nodes)
            .await?;
    }

    let root_val = root.get_value::<_, Blake3>(&db).await?;

    assert!(root_val == expected, "Root hash not equal to expected");
    Ok(())
}
