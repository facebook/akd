// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The implementation of a node for a history patricia tree

use crate::errors::{AkdError, StorageError, TreeNodeError};
use crate::serialization::{from_digest, to_digest};
use crate::storage::types::{DbRecord, StorageType};
use crate::storage::{Storable, Storage};
use crate::{node_label::*, Direction, EMPTY_LABEL};
use async_recursion::async_recursion;
use log::debug;
use std::cmp::min;
use std::convert::TryInto;
use std::marker::{Send, Sync};
use winter_crypto::Hasher;

/// There are three types of nodes: root, leaf and interior.
/// This enum is used to mark nodes using the node_type variable
/// of a TreeNode.
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum NodeType {
    /// Nodes with this type only have dummy children. Their value is
    /// input when they're created and the hash is H(value, creation_epoch)
    Leaf = 1,
    /// Nodes with this type do not have parents and their value,
    /// like Interior below, is a hash of their children's
    /// hash along with their respective labels.
    Root = 2,
    /// Nodes of this type must have non-dummy children
    /// and their value is a hash of their children, along with the labels of the children.
    Interior = 3,
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

pub(crate) type InsertionNode<'a> = (Direction, &'a mut TreeNode);

/// A TreeNode represents a generic node of a Merkle Patricia Trei with ordering.
/// The main idea here is that the tree is changing at every epoch and that we do not need
/// to touch the state of a node, unless it changes.
/// The leaves of the tree represented by these nodes is supposed to allow for a user
/// to monitor the state of a key-value pair in the past.
/// We achieve this by including the epoch a leaf was added as part of the hash stored in it.
/// At a later time, we may need to access older sub-trees of the tree built with these nodes.
/// To facilitate this, we require this struct to include the last time a node was updated
/// as well as the oldest descendant it holds.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct TreeNode {
    /// The binary label for this node
    pub label: NodeLabel,
    /// The last epoch this node was updated in
    pub last_epoch: u64,
    /// The least epoch of any descendant of this node
    pub least_descendant_ep: u64,
    /// The label of this node's parent
    pub parent: NodeLabel, // The root node is marked its own parent.
    /// The type of node: leaf, root or interior.
    pub node_type: NodeType, // Leaf, Root or Interior
    /// Label of the left child, None if there is none.
    pub left_child: Option<NodeLabel>,
    /// Label of the right child, None if there is none.
    pub right_child: Option<NodeLabel>,
    /// Hash (aka state) of the node.
    pub hash: [u8; 32],
}

/// Wraps the label with which to find a node in storage.
#[derive(Clone, PartialEq, Eq, Hash, std::fmt::Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NodeKey(pub NodeLabel);

impl Storable for TreeNode {
    type StorageKey = NodeKey;

    fn data_type() -> StorageType {
        StorageType::TreeNode
    }

    fn get_id(&self) -> NodeKey {
        NodeKey(self.label)
    }

    // The key is computed using the node_label and to make sure this
    // is unique, use both the label's val [`NodeLabel::label_val`] and
    // its len [`NodeLabel::label_len`].
    // The label_len originally is a u32, so it takes 4 bytes to write it.
    // The label_val, which is a [u8; 32] occupies the remaining 32 bytes,
    // so a total of 36 bytes are written.
    fn get_full_binary_key_id(key: &NodeKey) -> Vec<u8> {
        let mut result = vec![StorageType::TreeNode as u8];
        result.extend_from_slice(&key.0.label_len.to_le_bytes());
        result.extend_from_slice(&key.0.label_val);
        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<NodeKey, String> {
        // When the key is originally written down, it includes
        // [1 byte]: the type of the data structure represented by this key.
        // [4 bytes]: the length of the NodeLabel represented by this binary
        // [32 bytes]: the value of the NodeLabel
        // Totalling to 37 bytes.
        if bin.len() < 37 {
            return Err("Not enough bytes to form a proper key".to_string());
        }

        if bin[0] != StorageType::TreeNode as u8 {
            return Err("Not a history tree node key".to_string());
        }

        // The len is a u32, so read the first 4 bytes to get the len in bytes.
        let len_bytes: [u8; 4] = bin[1..=4].try_into().expect("Slice with incorrect length");
        // The val is of type [u8; 32], hence the rest of the 32 bytes are the value.
        let val_bytes: [u8; 32] = bin[5..=36].try_into().expect("Slice with incorrect length");
        // Get the length as a u32 from the bytes.
        let len = u32::from_le_bytes(len_bytes);

        Ok(NodeKey(NodeLabel::new(val_bytes, len)))
    }
}

unsafe impl Sync for TreeNode {}

impl Clone for TreeNode {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            last_epoch: self.last_epoch,
            least_descendant_ep: self.least_descendant_ep,
            parent: self.parent,
            node_type: self.node_type,
            left_child: self.left_child,
            right_child: self.right_child,
            hash: self.hash,
        }
    }
}

impl TreeNode {
    // FIXME: Figure out how to better group arguments.
    #[allow(clippy::too_many_arguments)]
    fn new(
        label: NodeLabel,
        parent: NodeLabel,
        node_type: NodeType,
        birth_epoch: u64,
        least_descendant_ep: u64,
        left_child: Option<NodeLabel>,
        right_child: Option<NodeLabel>,
        hash: [u8; 32],
    ) -> Self {
        TreeNode {
            label,
            last_epoch: birth_epoch,
            least_descendant_ep,
            parent, // Root node is its own parent
            node_type,
            left_child,
            right_child,
            hash,
        }
    }

    pub(crate) async fn write_to_storage<S: Storage + Send + Sync>(
        &self,
        storage: &S,
    ) -> Result<(), StorageError> {
        storage.set(DbRecord::TreeNode(self.clone())).await
    }

    pub(crate) async fn get_from_storage<S: Storage + Send + Sync>(
        storage: &S,
        key: &NodeKey,
        _current_epoch: u64,
    ) -> Result<TreeNode, StorageError> {
        match storage.get::<TreeNode>(key).await? {
            DbRecord::TreeNode(node) => Ok(node),
            _ => Err(StorageError::NotFound(format!("TreeNode {:?}", key))),
        }
    }

    pub(crate) async fn batch_get_from_storage<S: Storage + Send + Sync>(
        storage: &S,
        keys: &[NodeKey],
        _current_epoch: u64,
    ) -> Result<Vec<TreeNode>, StorageError> {
        let node_records: Vec<DbRecord> = storage.batch_get::<TreeNode>(keys).await?;
        let mut nodes = Vec::<TreeNode>::new();
        for node in node_records.into_iter() {
            if let DbRecord::TreeNode(node) = node {
                nodes.push(node);
            } else {
                return Err(StorageError::NotFound(
                    "Batch retrieve returned types <> TreeNode".to_string(),
                ));
            }
        }
        Ok(nodes)
    }

    /// Inserts a single leaf node and updates the required hashes, creating new nodes where needed.
    /// This function is only used in testing, since in general, we want to update the hashes of nodes
    /// in a batch to prevent repeated work.
    pub(crate) async fn insert_single_leaf_and_hash<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
        include_ep: Option<bool>,
    ) -> Result<(), AkdError> {
        self.insert_single_leaf_helper::<_, H>(
            storage, new_leaf, epoch, num_nodes, true, include_ep,
        )
        .await
    }

    /// Inserts a single leaf node without hashing, creates new nodes where needed
    /// Essentially, this function updates the structure of the Patricia Trei for which
    /// TreeNode is used but not the hash stored in updated parts of this Trei.
    /// This is used for batch inserting leaves, so that hashes can be updated
    /// in an amortized way, at a later time.
    pub(crate) async fn insert_leaf<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
        include_ep: Option<bool>,
    ) -> Result<(), AkdError> {
        self.insert_single_leaf_helper::<_, H>(
            storage, new_leaf, epoch, num_nodes, false, include_ep,
        )
        .await
    }

    /// Inserts a single leaf node and updates the required hashes,
    /// if hashing is true. Creates new nodes where neded.
    /// This is used to both batch insert leaves in a Patricia Trei as well as
    /// for the single leaf insertions for testing.
    #[async_recursion]
    pub(crate) async fn insert_single_leaf_helper<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
        hashing: bool,
        exclude_ep: Option<bool>,
    ) -> Result<(), AkdError> {
        let (lcs_label, dir_leaf, dir_self) = self
            .label
            .get_longest_common_prefix_and_dirs(new_leaf.label);

        if self.is_root() {
            // Account for the new leaf in the tree. We want to account for it only once, so let's do it on the root.
            *num_nodes += 1;
            let child_state = self.get_child_state(storage, dir_leaf).await?;
            if child_state == None {
                // This case is not entered very often, in fact it only happens
                // when you are actually instantiating the tree. Initially the tree only
                // consists of the root node. Then, a left child and a right child are inserted relatively soon.
                return self
                    .insert_single_leaf_helper_root_handler::<S, H>(
                        storage, new_leaf, epoch, hashing, exclude_ep, dir_leaf,
                    )
                    .await;
            }
        }

        // if a node is the longest common prefix of itself and the leaf, dir_self will be None
        match dir_self {
            Some(_) => {
                // This is the case where the calling node and the leaf have a longest common prefix
                // not equal to the label of the calling node.
                // This means that the current node needs to be pushed down one level (away from root)
                // in the tree and replaced with a new node whose label is equal to the longest common prefix.
                return self
                    .insert_single_leaf_helper_base_case_handler::<S, H>(
                        storage, new_leaf, epoch, num_nodes, hashing, exclude_ep, lcs_label,
                        dir_leaf, dir_self,
                    )
                    .await;
            }
            // Case where the current node is equal to the lcs
            // Recurse!
            None => {
                // This is the case where the calling node is the longest common prefix of itself
                // and the inserted leaf, so we just need to modify the tree structure further down the tree.
                return self
                    .insert_single_leaf_helper_recursive_case_handler::<S, H>(
                        storage, new_leaf, epoch, num_nodes, hashing, exclude_ep, dir_leaf,
                    )
                    .await;
            }
        }
    }

    /// This handler is used to handle the case when the tree is just starting out and
    /// at least one of the root's (left or right) children is None.
    pub(crate) async fn insert_single_leaf_helper_root_handler<
        S: Storage + Sync + Send,
        H: Hasher,
    >(
        &mut self,
        storage: &S,
        mut new_leaf: Self,
        epoch: u64,
        hashing: bool,
        exclude_ep: Option<bool>,
        dir_leaf: Option<usize>,
    ) -> Result<(), AkdError> {
        // If the root does not have a child at the direction the new leaf should be at, we add it.

        // Set up parent-child connection.
        self.set_child(storage, &mut (dir_leaf, &mut new_leaf), epoch)
            .await?;

        if hashing {
            // Update the hash of the leaf first since the parent hash will rely on the fact.
            new_leaf
                .update_node_hash::<_, H>(storage, epoch, exclude_ep)
                .await?;

            self.update_node_hash::<_, H>(storage, epoch, exclude_ep)
                .await?;
        } else {
            // If no hashing, we need to manually save the nodes.
            new_leaf.write_to_storage(storage).await?;
            self.write_to_storage(storage).await?;
        }

        Ok(())
    }

    /// This handler is used for insert_single_leaf_helper,
    /// is the case where the calling node and the leaf have a longest common prefix
    /// not equal to the label of the calling node.
    /// This means that the current node needs to be pushed down one level (away from root)
    /// in the tree and replaced with a new node whose label is equal to the longest common prefix.
    #[async_recursion]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn insert_single_leaf_helper_base_case_handler<
        S: Storage + Sync + Send,
        H: Hasher,
    >(
        &mut self,
        storage: &S,
        mut new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
        hashing: bool,
        exclude_ep: Option<bool>,
        lcs_label: NodeLabel,
        dir_leaf: Option<usize>,
        dir_self: Option<usize>,
    ) -> Result<(), AkdError> {
        // We will be creating a new node, so let's account for it.
        *num_nodes += 1;
        let mut parent = TreeNode::get_from_storage(storage, &NodeKey(self.parent), epoch).await?;
        let self_dir_in_parent = parent.get_direction(self);

        debug!("BEGIN create new node");
        let mut new_node = TreeNode::new(
            lcs_label,
            parent.label,
            NodeType::Interior,
            epoch,
            // if self is in the tree already, then its value should be moved up
            min(self.least_descendant_ep, epoch),
            None,
            None,
            [0u8; 32],
        );
        // Set up child-parent connections from top to bottom
        // (set child sets both child for the parent and parent for the child)
        // 1. Replace the self with the new node.
        debug!("BEGIN set node child parent(new_node)");
        parent
            .set_child(storage, &mut (self_dir_in_parent, &mut new_node), epoch)
            .await?;

        // 2. Set children of the new node (new leaf and self)
        debug!("BEGIN set node child new_node(new_leaf)");
        new_node
            .set_child(storage, &mut (dir_leaf, &mut new_leaf), epoch)
            .await?;

        debug!("BEGIN set node child new_node(self)");
        new_node
            .set_child(storage, &mut (dir_self, self), epoch)
            .await?;

        if hashing {
            // Update hashes from bottom to top.
            // Note that we don't need to hash the
            // node itself, since it's not changing.
            debug!("BEGIN update hashes");
            new_leaf
                .update_node_hash::<_, H>(storage, epoch, exclude_ep)
                .await?;
            new_node
                .update_node_hash::<_, H>(storage, epoch, exclude_ep)
                .await?;
            parent
                .update_node_hash::<_, H>(storage, epoch, exclude_ep)
                .await?;
        } else {
            // If no hashing, we need to manually save the nodes.
            new_leaf.write_to_storage(storage).await?;
            new_node.write_to_storage(storage).await?;
            parent.write_to_storage(storage).await?;
        }
        debug!("END insert single leaf (dir_self = Some)");
        Ok(())
    }

    // This is the handler for the case where the calling node is the longest common prefix of itself
    // and the inserted leaf, so we just need to modify the tree structure further down the tree.
    #[allow(clippy::too_many_arguments)]
    #[async_recursion]
    pub(crate) async fn insert_single_leaf_helper_recursive_case_handler<
        S: Storage + Sync + Send,
        H: Hasher,
    >(
        &mut self,
        storage: &S,
        new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
        hashing: bool,
        exclude_ep: Option<bool>,
        dir_leaf: Option<usize>,
    ) -> Result<(), AkdError> {
        debug!("BEGIN get child node from storage");
        let child_node = self.get_child_state(storage, dir_leaf).await?;
        debug!("BEGIN insert single leaf helper");
        match child_node {
            Some(mut child_node) => {
                child_node
                    .insert_single_leaf_helper::<_, H>(
                        storage, new_leaf, epoch, num_nodes, hashing, exclude_ep,
                    )
                    .await?;
                if hashing {
                    debug!("BEGIN update hashes");
                    *self =
                        TreeNode::get_from_storage(storage, &NodeKey(self.label), epoch).await?;
                    if self.node_type != NodeType::Leaf {
                        self.update_node_hash::<_, H>(storage, epoch, exclude_ep)
                            .await?;
                    }
                } else {
                    debug!("BEGIN retrieve self");
                    *self =
                        TreeNode::get_from_storage(storage, &NodeKey(self.label), epoch).await?;
                }
                debug!("END insert single leaf (dir_self = None)");
                Ok(())
            }
            None => Err(AkdError::TreeNode(TreeNodeError::NoChildAtEpoch(
                epoch,
                dir_leaf.unwrap(),
            ))),
        }
    }

    /// Updates the node hash and saves it in storage.
    pub(crate) async fn update_node_hash<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        epoch: u64,
        exclude_ep: Option<bool>,
    ) -> Result<(), AkdError> {
        // Mark the node as updated in this epoch.
        self.last_epoch = epoch;
        let exclude_ep_val = exclude_ep.unwrap_or(false);
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
                let left_child_state = self.get_child_state(storage, Some(0)).await?;
                let right_child_state = self.get_child_state(storage, Some(1)).await?;

                // Get merged hashes for the children.
                let child_hashes = H::merge(&[
                    optional_child_state_label_hash::<H>(&left_child_state, exclude_ep_val)?,
                    optional_child_state_label_hash::<H>(&right_child_state, exclude_ep_val)?,
                ]);
                // Store the hash
                self.hash = from_digest::<H>(child_hashes);
            }
        }

        // Update the node in storage.
        self.write_to_storage(storage).await?;

        Ok(())
    }

    /// Inserts a child into this node, adding the state to the state at this epoch,
    /// without updating its own hash.
    pub(crate) async fn set_child<S: Storage + Sync + Send>(
        &mut self,
        storage: &S,
        child: &mut InsertionNode<'_>,
        epoch: u64,
    ) -> Result<(), StorageError> {
        let (direction, child_node) = child;
        // Set child according to given direction.
        if let Some(direction) = direction {
            if *direction == 0_usize {
                self.left_child = Some(child_node.label);
            }
            if *direction == 1_usize {
                self.right_child = Some(child_node.label);
            }
        } else {
            return Err(StorageError::Other(format!(
                "Unexpected child index: {:?}",
                direction
            )));
        }
        // Update parent of the child.
        child_node.parent = self.label;

        // Update last updated epoch.
        self.last_epoch = epoch;

        // Update the least descencent epoch
        if self.least_descendant_ep == 0u64 {
            self.least_descendant_ep = child_node.least_descendant_ep;
        } else {
            self.least_descendant_ep =
                min(self.least_descendant_ep, child_node.least_descendant_ep);
        }

        self.write_to_storage(storage).await?;
        child_node.write_to_storage(storage).await?;

        Ok(())
    }

    pub(crate) fn get_child_label(&self, dir: Direction) -> Option<NodeLabel> {
        if dir == Some(0) {
            self.left_child
        } else if dir == Some(1) {
            self.right_child
        } else {
            None
        }
    }

    // gets the direction of node, i.e. if it's a left
    // child or right. If not found, return None
    fn get_direction(&self, node: &Self) -> Direction {
        if let Some(label) = self.left_child {
            if label == node.label {
                return Some(0);
            }
        }

        if let Some(label) = self.right_child {
            if label == node.label {
                return Some(1);
            }
        }
        None
    }

    pub(crate) fn is_root(&self) -> bool {
        matches!(self.node_type, NodeType::Root)
    }

    pub(crate) fn is_leaf(&self) -> bool {
        matches!(self.node_type, NodeType::Leaf)
    }

    ///// getrs for child nodes ////

    /// Loads (from storage) the left or right child of a node using given direction
    pub(crate) async fn get_child_state<S: Storage + Sync + Send>(
        &self,
        storage: &S,
        direction: Direction,
    ) -> Result<Option<TreeNode>, AkdError> {
        match direction {
            Direction::None => Err(AkdError::TreeNode(TreeNodeError::NoDirection(
                self.label, None,
            ))),
            Direction::Some(_dir) => {
                if let Some(child_label) = self.get_child_label(direction) {
                    let child_key = NodeKey(child_label);
                    let get_result = storage.get::<TreeNode>(&child_key).await;
                    match get_result {
                        Ok(DbRecord::TreeNode(ht_node)) => Ok(Some(ht_node)),
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

    pub(crate) fn get_child(&self, direction: Direction) -> Result<Option<NodeLabel>, AkdError> {
        match direction {
            Direction::None => Err(AkdError::TreeNode(TreeNodeError::NoDirection(
                self.label, None,
            ))),
            Direction::Some(dir) => {
                // TODO(eoz): Use Direction:Left and Direction:Right instead
                if dir == 0 {
                    Ok(self.left_child)
                } else if dir == 1 {
                    Ok(self.right_child)
                } else {
                    Err(AkdError::TreeNode(TreeNodeError::InvalidDirection(dir)))
                }
            }
        }
    }

    /* Functions for compression-related operations */

    pub(crate) fn get_latest_epoch(&self) -> u64 {
        self.last_epoch
    }

    #[allow(unused)]
    pub(crate) fn get_least_descendant_epoch(&self) -> u64 {
        self.least_descendant_ep
    }
}

/////// Helpers //////

pub(crate) fn hash_u8_with_label<H: Hasher>(
    digest: &[u8],
    label: NodeLabel,
) -> Result<H::Digest, AkdError> {
    Ok(H::merge(&[to_digest::<H>(digest)?, hash_label::<H>(label)]))
}

pub(crate) fn optional_child_state_to_label(input: &Option<TreeNode>) -> NodeLabel {
    match input {
        Some(child_state) => child_state.label,
        None => EMPTY_LABEL,
    }
}

pub(crate) fn optional_child_state_label_hash<H: Hasher>(
    input: &Option<TreeNode>,
    exclude_ep_val: bool,
) -> Result<H::Digest, AkdError> {
    match input {
        Some(child_state) => {
            let mut hash = to_digest::<H>(&child_state.hash)?;
            if child_state.is_leaf() && !exclude_ep_val {
                hash = H::merge_with_int(hash, child_state.last_epoch);
            }
            Ok(H::merge(&[hash, hash_label::<H>(child_state.label)]))
        }
        None => Ok(H::merge(&[
            crate::utils::empty_node_hash::<H>(),
            hash_label::<H>(EMPTY_LABEL),
        ])),
    }
}

pub(crate) fn optional_child_state_hash<H: Hasher>(
    input: &Option<TreeNode>,
) -> Result<H::Digest, AkdError> {
    match input {
        Some(child_state) => {
            if child_state.is_leaf() {
                Ok(H::merge_with_int(
                    to_digest::<H>(&child_state.hash)?,
                    child_state.last_epoch,
                ))
            } else {
                to_digest::<H>(&child_state.hash)
            }
        }
        None => Ok(crate::utils::empty_node_hash::<H>()),
    }
}

/// Retrieve an empty root node
pub fn get_empty_root<H: Hasher>(ep: Option<u64>, least_descendant_ep: Option<u64>) -> TreeNode {
    // Empty root hash is the same as empty node hash
    let empty_root_hash = from_digest::<H>(crate::utils::empty_node_hash_no_label::<H>());
    let mut node = TreeNode::new(
        NodeLabel::root(),
        NodeLabel::root(),
        NodeType::Root,
        0u64,
        0u64,
        // Empty root has no children.
        None,
        None,
        empty_root_hash,
    );
    if let Some(epoch) = ep {
        node.last_epoch = epoch;
    }
    if let Some(least_ep) = least_descendant_ep {
        node.least_descendant_ep = least_ep;
    }
    node
}

/// Get a specific leaf node
pub fn get_leaf_node<H: Hasher>(
    label: NodeLabel,
    value: &H::Digest,
    parent: NodeLabel,
    birth_epoch: u64,
) -> TreeNode {
    TreeNode {
        label,
        last_epoch: birth_epoch,
        least_descendant_ep: birth_epoch,
        parent,
        node_type: NodeType::Leaf,
        // Leaf has no children.
        left_child: None,
        right_child: None,
        hash: from_digest::<H>(*value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        node_label::{byte_arr_from_u64, hash_label, NodeLabel},
        EMPTY_VALUE,
    };
    use std::convert::TryInto;
    use winter_crypto::{hashers::Blake3_256, Hasher};
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type InMemoryDb = crate::storage::memory::AsyncInMemoryDatabase;

    #[tokio::test]
    async fn test_least_descendant_ep() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3>(Option::Some(0u64), Option::Some(0u64));
        let new_leaf = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b00u64), 2u32),
            &Blake3::hash(&EMPTY_VALUE),
            NodeLabel::root(),
            1,
        );

        let leaf_1 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b11u64 << 62), 2u32),
            &Blake3::hash(&[1u8]),
            NodeLabel::root(),
            2,
        );

        let leaf_2 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b10u64 << 62), 2u32),
            &Blake3::hash(&[1u8, 1u8]),
            NodeLabel::root(),
            3,
        );

        root.write_to_storage(&db).await?;
        let mut num_nodes = 1;

        root.insert_single_leaf_and_hash::<_, Blake3>(
            &db,
            new_leaf.clone(),
            1,
            &mut num_nodes,
            None,
        )
        .await?;

        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_1.clone(), 2, &mut num_nodes, None)
            .await?;

        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_2.clone(), 3, &mut num_nodes, None)
            .await?;

        let stored_root = db.get::<TreeNode>(&NodeKey(NodeLabel::root())).await?;

        let root_least_descendant_ep = match stored_root {
            DbRecord::TreeNode(node) => node.least_descendant_ep,
            _ => panic!("Root not found in storage."),
        };

        let stored_right_child = db
            .get::<TreeNode>(&NodeKey(root.right_child.unwrap()))
            .await?;

        let right_child_least_descendant_ep = match stored_right_child {
            DbRecord::TreeNode(node) => node.least_descendant_ep,
            _ => panic!("Root not found in storage."),
        };

        let stored_left_child = db
            .get::<TreeNode>(&NodeKey(root.left_child.unwrap()))
            .await?;

        let left_child_least_descendant_ep = match stored_left_child {
            DbRecord::TreeNode(node) => node.least_descendant_ep,
            _ => panic!("Root not found in storage."),
        };

        let root_expected_least_dec = 1u64;
        assert!(
            root_expected_least_dec == root_least_descendant_ep,
            "Least decendent epoch not equal to expected: root, expected: {:?}, got: {:?}",
            root_expected_least_dec,
            root_least_descendant_ep
        );

        let right_child_expected_least_dec = 2u64;
        assert!(
            right_child_expected_least_dec == right_child_least_descendant_ep,
            "Least decendent epoch not equal to expected: right child"
        );

        let left_child_expected_least_dec = 1u64;
        assert!(
            left_child_expected_least_dec == left_child_least_descendant_ep,
            "Least decendent epoch not equal to expected: left child"
        );

        Ok(())
    }

    // insert_single_leaf tests
    #[tokio::test]
    async fn test_insert_single_leaf_root() -> Result<(), AkdError> {
        let db = InMemoryDb::new();

        let mut root = get_empty_root::<Blake3>(Option::Some(0u64), Option::Some(0u64));
        root.write_to_storage(&db).await?;

        // Num nodes in total (currently only the root).
        let mut num_nodes = 1;

        // Prepare the leaf to be inserted with label 0.
        let leaf_0 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32),
            &Blake3::hash(&EMPTY_VALUE),
            NodeLabel::root(),
            0,
        );

        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_0.clone(), 0, &mut num_nodes, None)
            .await?;
        assert_eq!(num_nodes, 2);

        // Prepare another leaf to insert with label 1.
        let leaf_1 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32),
            &Blake3::hash(&[1u8]),
            NodeLabel::root(),
            0,
        );

        // Insert leaf 1.
        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_1.clone(), 0, &mut num_nodes, None)
            .await?;

        // Calculate expected root hash.
        let leaf_0_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&EMPTY_VALUE), 0),
            hash_label::<Blake3>(leaf_0.label),
        ]);

        let leaf_1_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&[1u8]), 0),
            hash_label::<Blake3>(leaf_1.label),
        ]);

        // Merge leaves hash along with the root label.
        let leaves_hash = Blake3::merge(&[leaf_0_hash, leaf_1_hash]);
        let expected = Blake3::merge(&[leaves_hash, hash_label::<Blake3>(root.label)]);

        // Get root hash
        let stored_root = db.get::<TreeNode>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => hash_u8_with_label::<Blake3>(&node.hash, node.label)?,
            _ => panic!("Root not found in storage."),
        };

        assert_eq!(root_digest, expected, "Root hash not equal to expected");

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_below_root() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3>(Option::Some(0u64), Option::Some(0u64));
        let leaf_0 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b00u64), 2u32),
            &Blake3::hash(&EMPTY_VALUE),
            NodeLabel::root(),
            1,
        );

        let leaf_1 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b11u64 << 62), 2u32),
            &Blake3::hash(&[1u8]),
            NodeLabel::root(),
            2,
        );

        let leaf_2 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b10u64 << 62), 2u32),
            &Blake3::hash(&[1u8, 1u8]),
            NodeLabel::root(),
            3,
        );

        let leaf_0_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&EMPTY_VALUE), 1),
            hash_label::<Blake3>(leaf_0.label),
        ]);

        let leaf_1_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&[0b1u8]), 2),
            hash_label::<Blake3>(leaf_1.label),
        ]);

        let leaf_2_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&[1u8, 1u8]), 3),
            hash_label::<Blake3>(leaf_2.label),
        ]);

        let right_child_expected_hash = Blake3::merge(&[
            Blake3::merge(&[leaf_2_hash, leaf_1_hash]),
            hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32)),
        ]);

        root.write_to_storage(&db).await?;
        let mut num_nodes = 1;

        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_0.clone(), 1, &mut num_nodes, None)
            .await?;

        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_1.clone(), 2, &mut num_nodes, None)
            .await?;

        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_2.clone(), 3, &mut num_nodes, None)
            .await?;

        let stored_root = db.get::<TreeNode>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => hash_u8_with_label::<Blake3>(&node.hash, node.label)?,
            _ => panic!("Root not found in storage."),
        };

        let expected = Blake3::merge(&[
            Blake3::merge(&[leaf_0_hash, right_child_expected_hash]),
            hash_label::<Blake3>(root.label),
        ]);
        assert!(root_digest == expected, "Root hash not equal to expected");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_below_root_both_sides() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3>(Option::Some(0u64), Option::Some(0u64));

        let leaf_0 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b000u64), 3u32),
            &Blake3::hash(&EMPTY_VALUE),
            NodeLabel::root(),
            0,
        );

        let leaf_1 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b111u64 << 61), 3u32),
            &Blake3::hash(&[1u8]),
            NodeLabel::root(),
            0,
        );

        let leaf_2 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b100u64 << 61), 3u32),
            &Blake3::hash(&[1u8, 1u8]),
            NodeLabel::root(),
            0,
        );

        let leaf_3 = get_leaf_node::<Blake3>(
            NodeLabel::new(byte_arr_from_u64(0b010u64 << 61), 3u32),
            &Blake3::hash(&[0u8, 1u8]),
            NodeLabel::root(),
            0,
        );

        let leaf_0_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&EMPTY_VALUE), 1),
            hash_label::<Blake3>(leaf_0.label),
        ]);

        let leaf_1_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&[1u8]), 2),
            hash_label::<Blake3>(leaf_1.label),
        ]);
        let leaf_2_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&[1u8, 1u8]), 3),
            hash_label::<Blake3>(leaf_2.label),
        ]);

        let leaf_3_hash = Blake3::merge(&[
            Blake3::merge_with_int(Blake3::hash(&[0u8, 1u8]), 4),
            hash_label::<Blake3>(leaf_3.label),
        ]);

        // Children: left: leaf2, right: leaf1, label: 1
        let right_child_expected_hash = Blake3::merge(&[
            Blake3::merge(&[leaf_2_hash, leaf_1_hash]),
            hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32)),
        ]);

        // Children: left: new_leaf, right: leaf3, label: 0
        let left_child_expected_hash = Blake3::merge(&[
            Blake3::merge(&[leaf_0_hash, leaf_3_hash]),
            hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32)),
        ]);

        // Insert nodes.
        root.write_to_storage(&db).await?;
        let mut num_nodes = 1;

        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_0.clone(), 1, &mut num_nodes, None)
            .await?;
        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_1.clone(), 2, &mut num_nodes, None)
            .await?;
        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_2.clone(), 3, &mut num_nodes, None)
            .await?;
        root.insert_single_leaf_and_hash::<_, Blake3>(&db, leaf_3.clone(), 4, &mut num_nodes, None)
            .await?;

        let stored_root = db.get::<TreeNode>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => hash_u8_with_label::<Blake3>(&node.hash, node.label)?,
            _ => panic!("Root not found in storage."),
        };

        let expected = Blake3::merge(&[
            Blake3::merge(&[left_child_expected_hash, right_child_expected_hash]),
            hash_label::<Blake3>(root.label),
        ]);
        assert!(root_digest == expected, "Root hash not equal to expected");

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_full_tree() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3>(Option::Some(0u64), Option::Some(0u64));
        root.write_to_storage(&db).await?;
        let mut num_nodes = 1;
        let mut leaves = Vec::<TreeNode>::new();
        let mut leaf_hashes = Vec::new();
        for i in 0u64..8u64 {
            let leaf_u64 = i.clone() << 61;
            let new_leaf = get_leaf_node::<Blake3>(
                NodeLabel::new(byte_arr_from_u64(leaf_u64), 3u32),
                &Blake3::hash(&leaf_u64.to_be_bytes()),
                NodeLabel::root(),
                7 - i,
            );
            leaf_hashes.push(Blake3::merge(&[
                Blake3::merge_with_int(Blake3::hash(&leaf_u64.to_be_bytes()), 8 - i),
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
                Blake3::merge(&[left_child_hash, right_child_hash]),
                hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(j << 62), 2u32)),
            ]));
            j += 1;
        }

        let mut layer_2_hashes = Vec::new();
        let mut j = 0u64;
        for i in 0..2 {
            let left_child_hash = layer_1_hashes[2 * i];
            let right_child_hash = layer_1_hashes[2 * i + 1];
            layer_2_hashes.push(Blake3::merge(&[
                Blake3::merge(&[left_child_hash, right_child_hash]),
                hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(j << 63), 1u32)),
            ]));
            j += 1;
        }

        let expected = Blake3::merge(&[
            Blake3::merge(&[layer_2_hashes[0], layer_2_hashes[1]]),
            hash_label::<Blake3>(root.label),
        ]);

        for i in 0..8 {
            let ep: u64 = i.try_into().unwrap();
            root.insert_single_leaf_and_hash::<_, Blake3>(
                &db,
                leaves[7 - i].clone(),
                ep + 1,
                &mut num_nodes,
                None,
            )
            .await?;
        }

        let stored_root = db.get::<TreeNode>(&NodeKey(NodeLabel::root())).await?;
        let root_digest = match stored_root {
            DbRecord::TreeNode(node) => hash_u8_with_label::<Blake3>(&node.hash, node.label)?,
            _ => panic!("Root not found in storage."),
        };

        assert!(root_digest == expected, "Root hash not equal to expected");
        Ok(())
    }
}
