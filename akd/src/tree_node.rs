// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The implementation of a node for a history patricia tree

use crate::errors::{AkdError, StorageError, TreeNodeError};
use crate::storage::manager::StorageManager;
use crate::storage::types::{DbRecord, StorageType};
use crate::storage::{Database, Storable};
use crate::Digest;
use crate::{node_label::*, Direction, EMPTY_LABEL};
use akd_core::hash::EMPTY_DIGEST;
#[cfg(feature = "serde_serialization")]
use akd_core::utils::serde_helpers::{bytes_deserialize_hex, bytes_serialize_hex};
use std::cmp::{max, min};
use std::convert::TryInto;
use std::marker::Sync;

/// There are three types of nodes: root, leaf and interior.
/// This enum is used to mark the type of a [TreeNode].
#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub enum NodeType {
    /// Nodes with this type only have dummy children. Their value is
    /// an input when they're created and the hash is H(value, creation_epoch)
    Leaf = 1,
    /// Nodes with this type do not have parents and their value,
    /// like Interior, is a hash of their children's
    /// hash along with their respective labels.
    Root = 2,
    /// Nodes of this type must have non-dummy children
    /// and their value is a hash of their children, along with the labels of the children.
    Interior = 3,
}

impl akd_core::SizeOf for NodeType {
    fn size_of(&self) -> usize {
        1
    }
}

impl NodeType {
    pub(crate) fn from_u8(code: u8) -> Self {
        match code {
            1 => Self::Leaf,
            2 => Self::Root,
            3 => Self::Interior,
            _ => Self::Leaf,
        }
    }
}

/// Represents a [TreeNode] with its current state and potential future state.
/// Depending on the `epoch` which the Directory believes is the "most current"
/// version, we may need to load a slightly older version of the tree node. This is because
/// we can't guarantee that a "publish" operation is globally atomic at the storage layer,
/// however we do assume record-level atomicity. This means that some records may be updated
/// to "future" values, and therefore we might need to temporarily read their previous values.
///
/// The Directory publishes the AZKS after all other records are successfully written.
/// This single record is where the "current" epoch is determined, so any instances with read-only
/// access (example: Directory instances service proof generation, but not publishing) will be notified
/// that a new epoch is available, flush their caches, and retrieve data from storage directly again.
///
/// This structure holds the label along with the current value & epoch - 1
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct TreeNodeWithPreviousValue {
    /// The label of the node
    pub label: NodeLabel,
    /// The "latest" node, either future or current
    pub latest_node: TreeNode,
    /// The "previous" node, either current or past
    pub previous_node: Option<TreeNode>,
}

impl akd_core::SizeOf for TreeNodeWithPreviousValue {
    fn size_of(&self) -> usize {
        self.label.size_of()
            + self.latest_node.size_of()
            + self.previous_node.as_ref().map_or(8, |v| v.size_of() + 8)
    }
}

impl Storable for TreeNodeWithPreviousValue {
    type StorageKey = NodeKey;

    fn data_type() -> StorageType {
        StorageType::TreeNode
    }

    fn get_id(&self) -> NodeKey {
        NodeKey(self.label)
    }

    fn get_full_binary_key_id(key: &NodeKey) -> Vec<u8> {
        let mut result = vec![StorageType::TreeNode as u8];
        result.extend_from_slice(&key.0.label_len.to_be_bytes());
        result.extend_from_slice(&key.0.label_val);
        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<NodeKey, String> {
        if bin.len() < 37 {
            return Err("Not enough bytes to form a proper key".to_string());
        }

        if bin[0] != StorageType::TreeNode as u8 {
            return Err("Not a tree node key".to_string());
        }

        let len_bytes: [u8; 4] = bin[1..=4].try_into().expect("Slice with incorrect length");
        let val_bytes: [u8; 32] = bin[5..=36].try_into().expect("Slice with incorrect length");
        let len = u32::from_be_bytes(len_bytes);

        Ok(NodeKey(NodeLabel::new(val_bytes, len)))
    }
}

impl TreeNodeWithPreviousValue {
    /// Determine which of the previous + latest nodes to retrieve based on the
    /// target epoch. If it should be older than the latest node, and there is no
    /// previous node, it returns Not Found
    fn determine_node_to_get(&self, target_epoch: u64) -> Result<TreeNode, StorageError> {
        // If a publish is currently underway, and "some" nodes have been updated to future values
        // our "target_epoch" may point to some older data. Therefore we may need to load a previous
        // version of this node.
        if self.latest_node.last_epoch > target_epoch {
            if let Some(previous_node) = &self.previous_node {
                Ok(previous_node.clone())
            } else {
                // no previous, return not found
                Err(StorageError::NotFound(format!(
                    "TreeNode {:?} at epoch {}",
                    NodeKey(self.label),
                    target_epoch
                )))
            }
        } else {
            // Otherwise the currently targeted epoch just points to the most up-to-date value, retrieve that
            Ok(self.latest_node.clone())
        }
    }

    /// Construct a TreeNode with "previous" value where the
    /// previous value is None. This is useful for the first
    /// time a node appears in the directory data layer.
    #[cfg(feature = "public-tests")]
    pub(crate) fn from_tree_node(node: TreeNode) -> Self {
        Self {
            label: node.label,
            latest_node: node,
            previous_node: None,
        }
    }

    pub(crate) async fn write_to_storage<S: Database>(
        &self,
        storage: &StorageManager<S>,
    ) -> Result<(), StorageError> {
        storage.set(DbRecord::TreeNode(self.clone())).await
    }

    pub(crate) async fn get_appropriate_tree_node_from_storage<S: Database>(
        storage: &StorageManager<S>,
        key: &NodeKey,
        target_epoch: u64,
    ) -> Result<TreeNode, StorageError> {
        match storage.get::<Self>(key).await? {
            DbRecord::TreeNode(node) => node.determine_node_to_get(target_epoch),
            _ => Err(StorageError::NotFound(format!(
                "TreeNodeWithPreviousValue {:?}",
                key
            ))),
        }
    }

    pub(crate) async fn batch_get_appropriate_tree_node_from_storage<S: Database>(
        storage: &StorageManager<S>,
        keys: &[NodeKey],
        target_epoch: u64,
    ) -> Result<Vec<TreeNode>, StorageError> {
        let node_records: Vec<DbRecord> = storage.batch_get::<Self>(keys).await?;
        let mut nodes = Vec::<TreeNode>::new();
        for node in node_records.into_iter() {
            if let DbRecord::TreeNode(node) = node {
                let correct_node = node.determine_node_to_get(target_epoch)?;
                nodes.push(correct_node);
            } else {
                return Err(StorageError::NotFound(
                    "Batch retrieve returned types <> TreeNodeWithPreviousValue".to_string(),
                ));
            }
        }
        Ok(nodes)
    }
}

/// FIXME(@klewi): update this documentation
/// A TreeNode represents a generic node of a Merkle Patricia Trie with ordering.
/// The main idea here is that the tree is changing at every epoch and that we do not need
/// to touch the state of a node, unless it changes.
/// The leaves of the tree represented by these nodes is supposed to allow for a user
/// to monitor the state of a key-value pair in the past.
/// We achieve this by including the epoch a leaf was added as part of the hash stored in it.
/// At a later time, we may need to access older sub-trees of the tree built with these nodes.
/// To facilitate this, we require this struct to include the last time a node was updated
/// as well as the oldest descendant it holds.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct TreeNode {
    /// The binary label for this node.
    pub label: NodeLabel,
    /// The last epoch this node was updated in.
    pub last_epoch: u64,
    /// The minimum last_epoch across all descendants of this node.
    pub min_descendant_epoch: u64,
    /// The label of this node's parent. where the root node is marked its own parent.
    pub parent: NodeLabel,
    /// The type of node: Leaf, Root, or Interior.
    pub node_type: NodeType,
    /// Label of the left child, None if there is none.
    pub left_child: Option<NodeLabel>,
    /// Label of the right child, None if there is none.
    pub right_child: Option<NodeLabel>,
    /// Hash (aka state) of the node.
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "bytes_serialize_hex")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "bytes_deserialize_hex")
    )]
    pub hash: [u8; crate::hash::DIGEST_BYTES],
}

impl akd_core::SizeOf for TreeNode {
    fn size_of(&self) -> usize {
        self.label.size_of()
            + std::mem::size_of::<u64>() * 2
            + self.parent.size_of()
            + self.node_type.size_of()
            + self.left_child.as_ref().map_or(8, |v| v.size_of() + 8)
            + self.right_child.as_ref().map_or(8, |v| v.size_of() + 8)
            + 32
    }
}

impl TreeNode {
    pub(crate) async fn write_to_storage<S: Database>(
        &self,
        storage: &StorageManager<S>,
    ) -> Result<(), StorageError> {
        // MOTIVATION:
        // We want to retrieve the previous latest_node value, so we want to investigate where (epoch - 1).
        // When a request comes in to write the node with a future epoch, (epoch - 1) will be the latest node in storage
        // and we'll do a shift-left. The get call should ideally utilize a cached value, so this should be safe to
        // call repeatedly. If the node retrieved from storage has the same epoch as the incoming changes, we don't shift
        // since the assumption is either (1) there's no changes or (2) a shift already occurred previously where the
        // epoch changed.

        // retrieve the highest node properties, at a previous epoch than this one. If we're modifying "this" epoch, simply take it as no need for a rotation.
        // When we write the node, with an updated epoch value, we'll rotate the stored value and capture the previous
        let target_epoch = match self.last_epoch {
            e if e > 0 => e - 1,
            other => other,
        };
        // Previous value of a new node are None.
        let previous = match TreeNodeWithPreviousValue::get_appropriate_tree_node_from_storage(
            storage,
            &NodeKey(self.label),
            target_epoch,
        )
        .await
        {
            Ok(p) => Some(p),
            Err(StorageError::NotFound(_)) => None,
            Err(other) => return Err(other),
        };
        // construct the "new" record, shifting the most recent stored value into the "previous" field
        let left_shifted = TreeNodeWithPreviousValue {
            label: self.label,
            latest_node: self.clone(),
            previous_node: previous,
        };
        // write this updated tuple record back to storage
        left_shifted.write_to_storage(storage).await
    }

    pub(crate) async fn get_from_storage<S: Database>(
        storage: &StorageManager<S>,
        key: &NodeKey,
        target_epoch: u64,
    ) -> Result<TreeNode, StorageError> {
        TreeNodeWithPreviousValue::get_appropriate_tree_node_from_storage(
            storage,
            key,
            target_epoch,
        )
        .await
    }

    pub(crate) async fn batch_get_from_storage<S: Database>(
        storage: &StorageManager<S>,
        keys: &[NodeKey],
        target_epoch: u64,
    ) -> Result<Vec<TreeNode>, StorageError> {
        TreeNodeWithPreviousValue::batch_get_appropriate_tree_node_from_storage(
            storage,
            keys,
            target_epoch,
        )
        .await
    }
}

/// Wraps the label with which to find a node in storage.
#[derive(Clone, PartialEq, Eq, Hash, std::fmt::Debug)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct NodeKey(pub NodeLabel);

unsafe impl Sync for TreeNode {}

impl TreeNode {
    // FIXME: Figure out how to better group arguments.
    #[allow(clippy::too_many_arguments)]
    /// Creates a new TreeNode and writes it to the storage.
    fn new(
        label: NodeLabel,
        parent: NodeLabel,
        node_type: NodeType,
        birth_epoch: u64,
        min_descendant_epoch: u64,
        hash: crate::Digest,
    ) -> Self {
        TreeNode {
            label,
            last_epoch: birth_epoch,
            min_descendant_epoch,
            parent, // Root node is its own parent
            node_type,
            left_child: None,
            right_child: None,
            hash,
        }
    }

    /// Updates the node hash and saves it in storage.
    pub(crate) async fn update_node_hash<S: Database>(
        &mut self,
        storage: &StorageManager<S>,
        hash_mode: NodeHashingMode,
    ) -> Result<(), AkdError> {
        match self.node_type {
            // For leaf nodes, updates the hash of the node by using the `hash` field (hash of the public key) and the hashed label.
            NodeType::Leaf => {
                // The leaf is initialized with its value.
                // When it's used later, it'll be hashed with the epoch.
            }
            // For non-leaf nodes, the hash is updated by merging the hashes of the node's children.
            // It is assumed that the children already updated their hashes.
            _ => {
                // Get children states.
                let left_child_state = self
                    .get_child_node(storage, Direction::Left, self.last_epoch)
                    .await?;
                let right_child_state = self
                    .get_child_node(storage, Direction::Right, self.last_epoch)
                    .await?;

                // Get merged hashes for the children.
                let child_hashes = crate::hash::merge(&[
                    optional_child_state_label_hash(&left_child_state, hash_mode),
                    optional_child_state_label_hash(&right_child_state, hash_mode),
                ]);
                // Store the hash
                self.hash = child_hashes;
            }
        }

        Ok(())
    }

    /// Inserts a child into this node, adding the state to the state at this epoch,
    /// without updating its own hash.
    pub(crate) fn set_child(&mut self, child_node: &mut TreeNode) -> Result<(), TreeNodeError> {
        // Set child according to given direction.
        match self.label.get_dir(child_node.label) {
            Direction::None => return Err(TreeNodeError::InvalidDirection(Direction::None)),
            Direction::Left => {
                self.left_child = Some(child_node.label);
            }
            Direction::Right => {
                self.right_child = Some(child_node.label);
            }
        }
        // Uparent of the child.
        child_node.parent = self.label;

        // Update last updated epoch.
        self.last_epoch = max(self.last_epoch, child_node.last_epoch);

        // Update the smallest descencent epoch
        if self.min_descendant_epoch == 0u64 {
            self.min_descendant_epoch = child_node.min_descendant_epoch;
        } else {
            self.min_descendant_epoch =
                min(self.min_descendant_epoch, child_node.min_descendant_epoch);
        };

        Ok(())
    }

    ///// getrs for child nodes ////

    /// Loads (from storage) the left or right child of a node using given direction and epoch
    pub(crate) async fn get_child_node<S: Database>(
        &self,
        storage: &StorageManager<S>,
        direction: Direction,
        epoch: u64,
    ) -> Result<Option<TreeNode>, AkdError> {
        match direction {
            Direction::None => Err(AkdError::TreeNode(TreeNodeError::NoDirection(
                self.label, None,
            ))),
            _ => {
                if let Some(child_label) = self.get_child_label(direction)? {
                    let child_key = NodeKey(child_label);
                    let get_result = Self::get_from_storage(storage, &child_key, epoch).await;
                    match get_result {
                        Ok(node) => Ok(Some(node)),
                        Err(StorageError::NotFound(_)) => Ok(None),
                        _ => Err(AkdError::Storage(StorageError::NotFound(format!(
                            "TreeNode {:?}",
                            child_key
                        )))),
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub(crate) fn get_child_label(
        &self,
        direction: Direction,
    ) -> Result<Option<NodeLabel>, AkdError> {
        match direction {
            Direction::None => Err(AkdError::TreeNode(TreeNodeError::NoDirection(
                self.label, None,
            ))),
            Direction::Left => Ok(self.left_child),
            Direction::Right => Ok(self.right_child),
        }
    }

    /* Functions for compression-related operations */

    pub(crate) fn get_latest_epoch(&self) -> u64 {
        self.last_epoch
    }
}

/////// Helpers //////

#[derive(Debug, Clone, Copy)]
pub(crate) enum NodeHashingMode {
    // Mixes the last epoch into the hashes of any child leaves
    WithLeafEpoch,
    // Does not mix the last epoch into the hashes of child leaves
    NoLeafEpoch,
}

pub(crate) fn merge_digest_with_label_hash(digest: &Digest, label: NodeLabel) -> Digest {
    crate::hash::merge(&[*digest, label.hash()])
}

pub(crate) fn optional_child_state_to_label(input: &Option<TreeNode>) -> NodeLabel {
    match input {
        Some(child_state) => child_state.label,
        None => EMPTY_LABEL,
    }
}

fn optional_child_state_label_hash(input: &Option<TreeNode>, hash_mode: NodeHashingMode) -> Digest {
    match input {
        Some(child_state) => {
            let mut hash = child_state.hash;
            if let (NodeType::Leaf, NodeHashingMode::WithLeafEpoch) =
                (child_state.node_type, hash_mode)
            {
                hash = crate::hash::merge_with_int(hash, child_state.last_epoch);
            }
            merge_digest_with_label_hash(&hash, child_state.label)
        }
        None => merge_digest_with_label_hash(&crate::utils::empty_node_hash(), EMPTY_LABEL),
    }
}

pub(crate) fn optional_child_state_hash(input: &Option<TreeNode>) -> Digest {
    match input {
        Some(child_state) => {
            if child_state.node_type == NodeType::Leaf {
                crate::hash::merge_with_int(child_state.hash, child_state.last_epoch)
            } else {
                child_state.hash
            }
        }
        None => crate::utils::empty_node_hash(),
    }
}

/// Create an empty root node.
pub(crate) fn new_root_node() -> TreeNode {
    // Empty root hash is the same as empty node hash with no label
    let empty_root_hash = crate::hash::hash(&crate::EMPTY_VALUE);
    TreeNode::new(
        NodeLabel::root(),
        NodeLabel::root(),
        NodeType::Root,
        0u64,
        0u64,
        empty_root_hash,
    )
}

/// Create an interior node with an empty hash.
pub(crate) fn new_interior_node(label: NodeLabel, birth_epoch: u64) -> TreeNode {
    TreeNode::new(
        label,
        EMPTY_LABEL,
        NodeType::Interior,
        birth_epoch,
        birth_epoch,
        EMPTY_DIGEST,
    )
}

/// Create a specific leaf node.
pub(crate) fn new_leaf_node(label: NodeLabel, value: &Digest, birth_epoch: u64) -> TreeNode {
    TreeNode::new(
        label,
        EMPTY_LABEL,
        NodeType::Leaf,
        birth_epoch,
        birth_epoch,
        *value,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::byte_arr_from_u64;
    use crate::{NodeLabel, EMPTY_VALUE};
    type InMemoryDb = crate::storage::memory::AsyncInMemoryDatabase;
    use crate::storage::manager::StorageManager;

    fn hash_label(label: NodeLabel) -> Digest {
        label.hash()
    }

    #[tokio::test]
    async fn test_smallest_descendant_ep() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node();

        let mut right_child =
            new_interior_node(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32), 3);

        let mut new_leaf = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b00u64), 2u32),
            &crate::hash::hash(&EMPTY_VALUE),
            1,
        );

        let mut leaf_1 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b11u64 << 62), 2u32),
            &crate::hash::hash(&[1u8]),
            2,
        );

        let mut leaf_2 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b10u64 << 62), 2u32),
            &crate::hash::hash(&[1u8, 1u8]),
            3,
        );

        right_child.set_child(&mut leaf_2)?;
        right_child.set_child(&mut leaf_1)?;
        right_child
            .update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        leaf_2.write_to_storage(&db).await?;
        leaf_1.write_to_storage(&db).await?;
        right_child.write_to_storage(&db).await?;

        root.set_child(&mut new_leaf)?;
        root.set_child(&mut right_child)?;
        root.update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        new_leaf.write_to_storage(&db).await?;
        right_child.write_to_storage(&db).await?;
        root.write_to_storage(&db).await?;

        let stored_root = db
            .get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root()))
            .await?;

        let root_smallest_descendant_ep = match stored_root {
            DbRecord::TreeNode(node) => node.latest_node.min_descendant_epoch,
            _ => panic!("Root not found in storage."),
        };

        let stored_right_child = db
            .get::<TreeNodeWithPreviousValue>(&NodeKey(root.right_child.unwrap()))
            .await?;

        let right_child_smallest_descendant_ep = match stored_right_child {
            DbRecord::TreeNode(node) => node.latest_node.min_descendant_epoch,
            _ => panic!("Root not found in storage."),
        };

        let stored_left_child = db
            .get::<TreeNodeWithPreviousValue>(&NodeKey(root.left_child.unwrap()))
            .await?;

        let left_child_smallest_descendant_ep = match stored_left_child {
            DbRecord::TreeNode(node) => node.latest_node.min_descendant_epoch,
            _ => panic!("Root not found in storage."),
        };

        let root_expected_min_dec = 1u64;
        assert_eq!(
            root_expected_min_dec, root_smallest_descendant_ep,
            "Minimum descendant epoch not equal to expected: root, expected: {:?}, got: {:?}",
            root_expected_min_dec, root_smallest_descendant_ep
        );

        let right_child_expected_min_dec = 2u64;
        assert_eq!(
            right_child_expected_min_dec, right_child_smallest_descendant_ep,
            "Minimum descendant epoch not equal to expected: right child"
        );

        let left_child_expected_min_dec = 1u64;
        assert_eq!(
            left_child_expected_min_dec, left_child_smallest_descendant_ep,
            "Minimum descendant epoch not equal to expected: left child"
        );

        Ok(())
    }

    // insert_single_leaf tests
    #[tokio::test]
    async fn test_insert_single_leaf_root() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);

        let mut root = new_root_node();

        // Prepare the leaf to be inserted with label 0.
        let mut leaf_0 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32),
            &crate::hash::hash(&EMPTY_VALUE),
            0,
        );

        // Prepare another leaf to insert with label 1.
        let mut leaf_1 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32),
            &crate::hash::hash(&[1u8]),
            0,
        );

        // Insert leaves.
        root.set_child(&mut leaf_0)?;
        root.set_child(&mut leaf_1)?;
        leaf_0.write_to_storage(&db).await?;
        leaf_1.write_to_storage(&db).await?;

        root.update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        root.write_to_storage(&db).await?;

        // Calculate expected root hash.
        let leaf_0_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&EMPTY_VALUE), 0),
            hash_label(leaf_0.label),
        ]);

        let leaf_1_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&[1u8]), 0),
            hash_label(leaf_1.label),
        ]);

        // Merge leaves hash along with the root label.
        let leaves_hash = crate::hash::merge(&[leaf_0_hash, leaf_1_hash]);
        let expected = crate::hash::merge(&[leaves_hash, hash_label(root.label)]);

        // Get root hash
        let stored_root = db
            .get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root()))
            .await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => {
                merge_digest_with_label_hash(&node.latest_node.hash, node.label)
            }
            _ => panic!("Root not found in storage."),
        };

        assert_eq!(root_digest, expected, "Root hash not equal to expected");

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_below_root() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node();

        let mut right_child =
            new_interior_node(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32), 3);

        let mut leaf_0 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b00u64), 2u32),
            &crate::hash::hash(&EMPTY_VALUE),
            1,
        );

        let mut leaf_1 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b11u64 << 62), 2u32),
            &crate::hash::hash(&[1u8]),
            2,
        );

        let mut leaf_2 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b10u64 << 62), 2u32),
            &crate::hash::hash(&[1u8, 1u8]),
            3,
        );

        right_child.set_child(&mut leaf_2)?;
        right_child.set_child(&mut leaf_1)?;
        leaf_2.write_to_storage(&db).await?;
        leaf_1.write_to_storage(&db).await?;

        right_child
            .update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        right_child.write_to_storage(&db).await?;

        root.set_child(&mut leaf_0)?;
        root.set_child(&mut right_child)?;
        leaf_0.write_to_storage(&db).await?;
        right_child.write_to_storage(&db).await?;

        root.update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        root.write_to_storage(&db).await?;

        let leaf_0_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&EMPTY_VALUE), 1),
            hash_label(leaf_0.label),
        ]);

        let leaf_1_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&[0b1u8]), 2),
            hash_label(leaf_1.label),
        ]);

        let leaf_2_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&[1u8, 1u8]), 3),
            hash_label(leaf_2.label),
        ]);

        let right_child_expected_hash = crate::hash::merge(&[
            crate::hash::merge(&[leaf_2_hash, leaf_1_hash]),
            hash_label(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32)),
        ]);

        let stored_root = db
            .get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root()))
            .await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => {
                merge_digest_with_label_hash(&node.latest_node.hash, node.label)
            }
            _ => panic!("Root not found in storage."),
        };

        let expected = crate::hash::merge(&[
            crate::hash::merge(&[leaf_0_hash, right_child_expected_hash]),
            hash_label(root.label),
        ]);
        assert!(root_digest == expected, "Root hash not equal to expected");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_below_root_both_sides() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node();

        let mut left_child = new_interior_node(NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32), 4);

        let mut right_child =
            new_interior_node(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32), 3);

        let mut leaf_0 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b000u64), 3u32),
            &crate::hash::hash(&EMPTY_VALUE),
            1,
        );

        let mut leaf_1 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b111u64 << 61), 3u32),
            &crate::hash::hash(&[1u8]),
            2,
        );

        let mut leaf_2 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b100u64 << 61), 3u32),
            &crate::hash::hash(&[1u8, 1u8]),
            3,
        );

        let mut leaf_3 = new_leaf_node(
            NodeLabel::new(byte_arr_from_u64(0b010u64 << 61), 3u32),
            &crate::hash::hash(&[0u8, 1u8]),
            4,
        );

        // Insert nodes.
        left_child.set_child(&mut leaf_0)?;
        left_child.set_child(&mut leaf_3)?;
        leaf_0.write_to_storage(&db).await?;
        leaf_3.write_to_storage(&db).await?;

        left_child
            .update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        left_child.write_to_storage(&db).await?;

        right_child.set_child(&mut leaf_2)?;
        right_child.set_child(&mut leaf_1)?;
        leaf_2.write_to_storage(&db).await?;
        leaf_1.write_to_storage(&db).await?;

        right_child
            .update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        right_child.write_to_storage(&db).await?;

        root.set_child(&mut left_child)?;
        root.set_child(&mut right_child)?;
        left_child.write_to_storage(&db).await?;
        right_child.write_to_storage(&db).await?;

        root.update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        root.write_to_storage(&db).await?;

        let leaf_0_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&EMPTY_VALUE), 1),
            hash_label(leaf_0.label),
        ]);

        let leaf_1_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&[1u8]), 2),
            hash_label(leaf_1.label),
        ]);
        let leaf_2_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&[1u8, 1u8]), 3),
            hash_label(leaf_2.label),
        ]);

        let leaf_3_hash = crate::hash::merge(&[
            crate::hash::merge_with_int(crate::hash::hash(&[0u8, 1u8]), 4),
            hash_label(leaf_3.label),
        ]);

        // Children: left: leaf2, right: leaf1, label: 1
        let right_child_expected_hash = crate::hash::merge(&[
            crate::hash::merge(&[leaf_2_hash, leaf_1_hash]),
            hash_label(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32)),
        ]);

        // Children: left: new_leaf, right: leaf3, label: 0
        let left_child_expected_hash = crate::hash::merge(&[
            crate::hash::merge(&[leaf_0_hash, leaf_3_hash]),
            hash_label(NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32)),
        ]);

        let stored_root = db
            .get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root()))
            .await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => {
                merge_digest_with_label_hash(&node.latest_node.hash, node.label)
            }
            _ => panic!("Root not found in storage."),
        };

        let expected = crate::hash::merge(&[
            crate::hash::merge(&[left_child_expected_hash, right_child_expected_hash]),
            hash_label(root.label),
        ]);
        assert_eq!(root_digest, expected, "Root hash not equal to expected");

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_full_tree() -> Result<(), AkdError> {
        let database = InMemoryDb::new();
        let db = StorageManager::new_no_cache(database);
        let mut root = new_root_node();

        let mut leaves = Vec::<TreeNode>::new();
        let mut leaf_hashes = Vec::new();
        for i in 0u64..8u64 {
            let leaf_u64 = i << 61;
            let new_leaf = new_leaf_node(
                NodeLabel::new(byte_arr_from_u64(leaf_u64), 3u32),
                &crate::hash::hash(&leaf_u64.to_be_bytes()),
                7 - i,
            );
            leaf_hashes.push(crate::hash::merge(&[
                crate::hash::merge_with_int(crate::hash::hash(&leaf_u64.to_be_bytes()), 7 - i),
                hash_label(new_leaf.label),
            ]));
            leaves.push(new_leaf);
        }

        let mut layer_1_interior = Vec::new();
        let mut layer_1_hashes = Vec::new();
        for (i, j) in (0u64..4).enumerate() {
            let interior_u64 = j << 62;
            layer_1_interior.push(new_interior_node(
                NodeLabel::new(byte_arr_from_u64(interior_u64), 2u32),
                7 - (2 * j),
            ));

            let left_child_hash = leaf_hashes[2 * i];
            let right_child_hash = leaf_hashes[2 * i + 1];
            layer_1_hashes.push(crate::hash::merge(&[
                crate::hash::merge(&[left_child_hash, right_child_hash]),
                hash_label(NodeLabel::new(byte_arr_from_u64(j << 62), 2u32)),
            ]));
        }

        let mut layer_2_interior = Vec::new();
        let mut layer_2_hashes = Vec::new();
        for (i, j) in (0u64..2).enumerate() {
            let interior_u64 = j << 63;
            layer_2_interior.push(new_interior_node(
                NodeLabel::new(byte_arr_from_u64(interior_u64), 1u32),
                7 - (4 * j),
            ));

            let left_child_hash = layer_1_hashes[2 * i];
            let right_child_hash = layer_1_hashes[2 * i + 1];
            layer_2_hashes.push(crate::hash::merge(&[
                crate::hash::merge(&[left_child_hash, right_child_hash]),
                hash_label(NodeLabel::new(byte_arr_from_u64(j << 63), 1u32)),
            ]));
        }

        let expected = crate::hash::merge(&[
            crate::hash::merge(&[layer_2_hashes[0], layer_2_hashes[1]]),
            hash_label(root.label),
        ]);

        for node in layer_1_interior.iter_mut() {
            let mut left_child = leaves.remove(0);
            let mut right_child = leaves.remove(0);

            node.set_child(&mut left_child)?;
            node.set_child(&mut right_child)?;
            left_child.write_to_storage(&db).await?;
            right_child.write_to_storage(&db).await?;

            node.update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
                .await?;
            node.write_to_storage(&db).await?;
        }

        for node in layer_2_interior.iter_mut() {
            let mut left_child = layer_1_interior.remove(0);
            let mut right_child = layer_1_interior.remove(0);

            node.set_child(&mut left_child)?;
            node.set_child(&mut right_child)?;
            left_child.write_to_storage(&db).await?;
            right_child.write_to_storage(&db).await?;

            node.update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
                .await?;
            node.write_to_storage(&db).await?;
        }

        let mut left_child = layer_2_interior.remove(0);
        let mut right_child = layer_2_interior.remove(0);

        root.set_child(&mut left_child)?;
        root.set_child(&mut right_child)?;
        left_child.write_to_storage(&db).await?;
        right_child.write_to_storage(&db).await?;

        root.update_node_hash(&db, NodeHashingMode::WithLeafEpoch)
            .await?;
        root.write_to_storage(&db).await?;

        let stored_root = db
            .get::<TreeNodeWithPreviousValue>(&NodeKey(NodeLabel::root()))
            .await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => {
                merge_digest_with_label_hash(&node.latest_node.hash, node.label)
            }
            _ => panic!("Root not found in storage."),
        };

        assert_eq!(root_digest, expected, "Root hash not equal to expected");
        Ok(())
    }
}
