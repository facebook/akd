// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The implementation of a node for a history patricia tree

use crate::errors::{AkdError, HistoryTreeNodeError, StorageError};
use crate::serialization::{from_digest, to_digest};
use crate::storage::types::{DbRecord, StorageType};
use crate::storage::{Storable, Storage};
use crate::{node_state::*, Direction, EMPTY_LABEL, EMPTY_VALUE};
use async_recursion::async_recursion;
use log::debug;
use std::convert::TryInto;
use std::marker::{Send, Sync};
use winter_crypto::{Hasher};

/// There are three types of nodes: root, leaf and interior.
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum NodeType {
    /// Nodes with this type only have dummy children.
    Leaf = 1,
    /// Nodes with this type do not have parents and their value includes a hash of their label.
    Root = 2,
    /// Nodes of this type must have non-dummy children and their value is a hash of their children, along with the labels of the children.
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

pub(crate) type HistoryInsertionNode<'a> = (Direction, &'a mut HistoryTreeNode);

/// A HistoryNode represents a generic interior node of a compressed history tree.
/// The main idea here is that the tree is changing at every epoch and that we do not need
/// to replicate the state of a node, unless it changes.
/// However, in order to allow for a user to monitor the state of a key-value pair in
/// the past, the older states also need to be stored.
/// While the states themselves can be stored elsewhere,
/// we need a list of epochs when this node was updated, and that is what this data structure is meant to do.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct HistoryTreeNode {
    /// The binary label for this node
    pub label: NodeLabel,
    /// The last epoch this node was updated in
    pub last_epoch: u64,
    /// The epoch that this node was birthed in
    pub birth_epoch: u64,
    /// The label of this node's parent
    pub parent: NodeLabel, // The root node is marked its own parent.
    /// The type of node: leaf root or interior.
    pub node_type: NodeType, // Leaf, Root or Interior

    // TODO(eoz): Use EMPTY_LABEL instead?
    pub left_child: Option<NodeLabel>,
    pub right_child: Option<NodeLabel>,

    pub hash: [u8; 32],
}

/// Wraps the label with which to find a node in storage.
#[derive(Clone, PartialEq, Eq, Hash, std::fmt::Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NodeKey(pub NodeLabel);

impl Storable for HistoryTreeNode {
    type Key = NodeKey;

    fn data_type() -> StorageType {
        StorageType::HistoryTreeNode
    }

    fn get_id(&self) -> NodeKey {
        NodeKey(self.label)
    }

    fn get_full_binary_key_id(key: &NodeKey) -> Vec<u8> {
        let mut result = vec![StorageType::HistoryTreeNode as u8];
        result.extend_from_slice(&key.0.len.to_le_bytes());
        result.extend_from_slice(&key.0.val);
        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<NodeKey, String> {
        if bin.len() < 37 {
            return Err("Not enough bytes to form a proper key".to_string());
        }

        if bin[0] != StorageType::HistoryTreeNode as u8 {
            return Err("Not a history tree node key".to_string());
        }

        let len_bytes: [u8; 4] = bin[1..=4].try_into().expect("Slice with incorrect length");
        let val_bytes: [u8; 32] = bin[5..=36].try_into().expect("Slice with incorrect length");
        let len = u32::from_le_bytes(len_bytes);

        Ok(NodeKey(NodeLabel::new(val_bytes, len)))
    }
}

unsafe impl Sync for HistoryTreeNode {}

impl Clone for HistoryTreeNode {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            last_epoch: self.last_epoch,
            birth_epoch: self.birth_epoch,
            parent: self.parent,
            node_type: self.node_type,
            left_child: self.left_child,
            right_child: self.right_child,
            hash: self.hash,
        }
    }
}

impl HistoryTreeNode {
    fn new(
        label: NodeLabel,
        parent: NodeLabel,
        node_type: NodeType,
        birth_epoch: u64,
        left_child: Option<NodeLabel>,
        right_child: Option<NodeLabel>,
        hash: [u8; 32],
    ) -> Self {
        HistoryTreeNode {
            label,
            birth_epoch,
            last_epoch: birth_epoch,
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
        storage.set(DbRecord::HistoryTreeNode(self.clone())).await
    }

    pub(crate) async fn get_from_storage<S: Storage + Send + Sync>(
        storage: &S,
        key: &NodeKey,
        current_epoch: u64,
    ) -> Result<HistoryTreeNode, StorageError> {
        match storage.get::<HistoryTreeNode>(key).await? {
            DbRecord::HistoryTreeNode(node) => {
                // Resets a node's last_epoch value if the node in storage is ahead of the current
                // directory epoch. This could happen when a separate AKD process is in the middle
                // of performing a publish
                if node.last_epoch > current_epoch {
                    let prev_last_epoch = storage.get_epoch_lte_epoch(key.0, current_epoch).await?;
                    Ok(Self {
                        last_epoch: prev_last_epoch,
                        ..node
                    })
                } else {
                    Ok(node)
                }
            }
            _ => Err(StorageError::NotFound(format!("HistoryTreeNode {:?}", key))),
        }
    }

    pub(crate) async fn batch_get_from_storage<S: Storage + Send + Sync>(
        storage: &S,
        keys: &[NodeKey],
        current_epoch: u64,
    ) -> Result<Vec<HistoryTreeNode>, StorageError> {
        let node_records: Vec<DbRecord> = storage.batch_get::<HistoryTreeNode>(keys).await?;
        let mut nodes = Vec::<HistoryTreeNode>::new();
        for (i, node) in node_records.into_iter().enumerate() {
            if let DbRecord::HistoryTreeNode(node) = node {
                // Resets a node's last_epoch value if the node in storage is ahead of the current
                // directory epoch. This could happen when a separate AKD process is in the middle
                // of performing a publish
                if node.last_epoch > current_epoch {
                    let prev_last_epoch = storage
                        .get_epoch_lte_epoch(keys[i].0, current_epoch)
                        .await?;
                    nodes.push(Self {
                        last_epoch: prev_last_epoch,
                        ..node
                    });
                } else {
                    nodes.push(node);
                }
            } else {
                return Err(StorageError::NotFound(
                    "Batch retrieve returned types <> HistoryTreeNode".to_string(),
                ));
            }
        }
        Ok(nodes)
    }

    /// Inserts a single leaf node and updates the required hashes, creating new nodes where needed
    pub(crate) async fn insert_single_leaf<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
    ) -> Result<(), AkdError> {
        self.insert_single_leaf_helper::<_, H>(storage, new_leaf, epoch, num_nodes, true)
            .await
    }

    /// Inserts a single leaf node without hashing, creates new nodes where needed
    pub(crate) async fn insert_leaf<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
    ) -> Result<(), AkdError> {
        self.insert_single_leaf_helper::<_, H>(storage, new_leaf, epoch, num_nodes, false)
            .await
    }

    /// Inserts a single leaf node and updates the required hashes,
    /// if hashing is true. Creates new nodes where neded.
    #[async_recursion]
    pub(crate) async fn insert_single_leaf_helper<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        mut new_leaf: Self,
        epoch: u64,
        num_nodes: &mut u64,
        hashing: bool,
    ) -> Result<(), AkdError> {
        let (lcs_label, dir_leaf, dir_self) = self
            .label
            .get_longest_common_prefix_and_dirs(new_leaf.label);

        if self.is_root() {
            *num_nodes += 1;
            let child_state = self.get_child_state(storage, dir_leaf).await?;
            // If the root does not have a child at the direction the new leaf should be at, we add it.
            if child_state == None {
                // Set up parent-child connection
                self.set_child(&mut(dir_leaf, &mut new_leaf), epoch);

                if hashing {
                    // Update the hash of the leaf first since the parent hash will rely on the fact.
                    new_leaf.update_node_hash::<_, H>(storage, epoch).await?;

                    self.update_node_hash::<_, H>(storage, epoch).await?;
                }

                // Save the new states of the child and the parent
                self.write_to_storage(storage).await?;
                new_leaf.write_to_storage(storage).await?;

                return Ok(());
            }
        }

        // if a node is the longest common prefix of itself and the leaf, dir_self will be None
        match dir_self {
            Some(_) => {
                *num_nodes += 1;
                // This is the case where the calling node and the leaf have a longest common prefix
                // not equal to the label of the calling node.
                // This means that the current node needs to be pushed down one level (away from root)
                // in the tree and replaced with a new node whose label is equal to the longest common prefix.
                debug!("BEGIN get parent");
                let mut parent =
                    HistoryTreeNode::get_from_storage(storage, &NodeKey(self.parent), epoch)
                        .await?;
                debug!("BEGIN get direction at epoch {}", epoch);
                let self_dir_in_parent = parent.get_direction(self);

                debug!("BEGIN create new node");
                let mut new_node = HistoryTreeNode::new(
                    lcs_label,
                    parent.label,
                    NodeType::Interior,
                    epoch,
                    None,
                    None,
                    [0u8; 32],
                );
                // Set up child-parent connections from top to bottom
                // (set child sets both child for the parent and parent for the child)
                // 1. Replace the self with the new node.
                debug!("BEGIN set node child parent(new_node)");
                parent
                    .set_child(&mut (self_dir_in_parent, &mut new_node), epoch);

                // 2. Set children of the new node (new leaf and self)
                debug!("BEGIN set node child new_node(new_leaf)");
                new_node
                    .set_child(&mut (dir_leaf, &mut new_leaf), epoch);

                debug!("BEGIN set node child new_node(self)");
                new_node
                    .set_child(&mut (dir_self, self), epoch);


                if hashing {
                    // Update hashes from bottom to top.
                    debug!("BEGIN update hashes");
                    new_leaf.update_node_hash::<_, H>(storage, epoch).await?;
                    self.update_node_hash::<_, H>(storage, epoch).await?;
                    new_node.update_node_hash::<_, H>(storage, epoch).await?;
                    parent.update_node_hash::<_, H>(storage, epoch).await?;
                }

                // Write the updates node to the storage.
                new_leaf.write_to_storage(storage).await?;
                self.write_to_storage(storage).await?;
                new_node.write_to_storage(storage).await?;
                parent.write_to_storage(storage).await?;
                debug!("END insert single leaf (dir_self = Some)");
                Ok(())
            }
            // Case where the current node is equal to the lcs
            // Recurse!
            None => {
                debug!("BEGIN get child node from storage");
                let child_node = self.get_child_state(storage, dir_leaf).await?;
                debug!("BEGIN insert single leaf helper");
                let result = match child_node {
                    Some(mut child_node) => {
                        child_node
                            .insert_single_leaf_helper::<_, H>(storage, new_leaf, epoch, num_nodes, hashing)
                            .await?;
                        if hashing {
                            debug!("BEGIN update hashes");
                            *self = HistoryTreeNode::get_from_storage(storage, &NodeKey(self.label), epoch)
                                .await?;
                            self.update_node_hash::<_, H>(storage, epoch).await?;
                            self.write_to_storage(storage).await?;
                        } else {
                            debug!("BEGIN retrieve self");
                            *self = HistoryTreeNode::get_from_storage(storage, &NodeKey(self.label), epoch)
                                .await?;
                        }
                        debug!("END insert single leaf (dir_self = None)");
                        Ok(())

                    },
                    None => {
                        Err(AkdError::HistoryTreeNode(HistoryTreeNodeError::NoChildAtEpoch(epoch, dir_leaf.unwrap())))
                    }
                };
                result
           }
        }
    }

    /// Updates the hash of this node as stored in its parent,
    /// provided the children of this node have already updated their own versions
    /// in this node and epoch is contained in the state_map
    /// Also assumes that `set_child_without_hash` has already been called
    // pub(crate) async fn update_hash<S: Storage + Sync + Send, H: Hasher>(
    //     &mut self,
    //     storage: &S,
    //     epoch: u64,
    // ) -> Result<(), AkdError> {
    //     match self.node_type {
    //         NodeType::Leaf => {
    //             // the hash of this is just the value, simply place in parent
    //             let leaf_hash_val = H::merge(&[
    //                 self.get_value::<_, H>(storage).await?,
    //                 hash_label::<H>(self.label),
    //             ]);
    //         }
    //         _ => {
    //             let mut hash_digest = self.hash_node::<_, H>(storage, epoch).await?;
    //             // The root has no parent, so the hash must only be stored within the value.
    //             if self.is_root() {
    //                 hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
    //             }
    //             self.hash = from_digest::<H>(hash_digest);

    //             self.write_to_storage(storage).await?;
    //             let hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
    //             self.update_hash_at_parent::<_, H>(storage, epoch, hash_digest)
    //                 .await
    //         }
    //     }
    // }

    pub(crate) async fn update_node_hash<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        epoch: u64,
    ) -> Result<(), AkdError> {
        // Mark the node as updated in this epoch.
        self.last_epoch = epoch;
        match self.node_type {
            // For leaf nodes, updates the hash of the node by hashing the VRF of public key stored in the `hash` field and the label.
            NodeType::Leaf => {
                let mut leaf_hash = H::hash(&self.hash);
                leaf_hash = H::merge(&[
                    leaf_hash,
                    hash_label::<H>(self.label),
                ]);

                // Update the node hash.
                self.hash = from_digest::<H>(leaf_hash);

                Ok(())
            }
            // For non-leaf nodes, the hash is updated by merging the hashes of the node's children.
            // It is assumed that the children already updated their hashes.
            _ => {
                // Get children states.
                let left_child_state = self.get_child_state(storage, Some(0)).await?;
                let right_child_state = self.get_child_state(storage, Some(1)).await?;

                // Calculate a hash over the children
                let mut new_hash = H::hash(&EMPTY_VALUE);
                new_hash = H::merge(&[new_hash, to_digest::<H>(&optional_child_state_to_hash::<H>(&left_child_state,))?]);
                new_hash = H::merge(&[new_hash, to_digest::<H>(&optional_child_state_to_hash::<H>(&right_child_state,))?]);

                // Update the node hash.
                self.hash = from_digest::<H>(new_hash);

                Ok(())
            }
        }
    }

    /// Writes the new_hash_val into the parent's state for this epoch.
    /// Accounts for the case when considering a root node, which has no parent.
    // async fn update_hash_at_parent<S: Storage + Sync + Send, H: Hasher>(
    //     &mut self,
    //     storage: &S,
    //     epoch: u64,
    //     new_hash_val: H::Digest,
    // ) -> Result<(), AkdError> {
    //     if self.is_root() {
    //         return Ok(());
    //     }

    //     let parent =
    //         &mut HistoryTreeNode::get_from_storage(storage, &NodeKey(self.parent), epoch).await?;

    //     // Update the parent's hash and save it.
    //     parent.hash = parent.hash_node::<_, H>(storage, epoch).await?.as_bytes();
    //     parent.write_to_storage(storage).await?;
    //     Ok(())
    // }

    /// Inserts a child into this node, adding the state to the state at this epoch,
    /// without updating its own hash.
    // #[async_recursion]
    pub(crate) fn set_child(
        &mut self,
        child: &mut HistoryInsertionNode<'_>,
        epoch: u64,
    ) {
        let (direction, child_node) = child;
        // Set child according to given direction.
        if let Some(direction) = direction {
            if *direction == 0 as usize {
                self.left_child = Some(child_node.label);
            }
            if *direction == 1 as usize {
                self.right_child = Some(child_node.label);
            }
        } else {
            panic!("Unknown child index or None.");
        }
        // Update parent of the child.
        child_node.parent = self.label;

        // Update last updated epoch.
        self.last_epoch = epoch;
        child_node.last_epoch = epoch;
    }

    /// This function is just a wrapper: given a [`HistoryTreeNode`], sets this node's latest value using
    /// set_child_without_hash. Just used for type conversion.
    // pub(crate) async fn set_node_child<S: Storage + Sync + Send, H: Hasher>(
    //     &mut self,
    //     storage: &S,
    //     dir: Direction,
    //     child: &Self,
    // ) -> Result<(), AkdError> {
    //     // TODO(eoz): Do we need to convert?
    //     // let node_as_child_state = child.to_node_unhashed_child_state::<_, H>(storage).await?;
    //     // let insertion_node = (dir, node_as_child_state);
    //     // TODO(eoz): Does clone work here?
    //     let insertion_node = (dir, child.clone());
    //     self.set_child::<_, H>(storage, &insertion_node).await
    //     child.parent = self.label
    // }

    ////// getrs for this node ////

    pub(crate) async fn get_value_at_epoch<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<H::Digest, AkdError> {
        Ok(to_digest::<H>(
            &self.hash,
        )?)
    }

    // pub(crate) async fn get_value_without_label_at_epoch<S: Storage + Sync + Send, H: Hasher>(
    //     &self,
    //     storage: &S,
    //     epoch: u64,
    // ) -> Result<H::Digest, AkdError> {
    //     if self.is_leaf() {
    //         return self.get_value_at_epoch::<_, H>(storage, epoch).await;
    //     }
    //     let children = self.get_state_at_epoch(storage, epoch).await?.child_states;
    //     let mut new_hash = H::hash(&EMPTY_VALUE);
    //     for child in children.iter().take(ARITY) {
    //         let hash_val = optional_history_child_state_to_hash::<H>(child);
    //         new_hash = H::merge(&[new_hash, to_digest::<H>(&hash_val)?]);
    //     }
    //     Ok(new_hash)
    // }

    pub(crate) fn get_child_label(&self, dir: Direction) -> Option<NodeLabel> {
        let mut child_label_to_ret = None;
        // TODO(eoz): Replace usize dirs with a Direction enum.
        if dir == Some(0) {
            child_label_to_ret = self.left_child;
        } else if dir == Some(1) {
            child_label_to_ret = self.right_child;
        } else {
            panic!("No child with that index!");
        }
        child_label_to_ret
    }

    // gets value at current epoch
    pub(crate) async fn get_value<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
    ) -> Result<H::Digest, AkdError> {
        match get_state_map(storage, self, self.get_latest_epoch()).await {
            Ok(state_map) => Ok(to_digest::<H>(&state_map.value)?),
            Err(er) => Err(er.into()),
        }
    }

    pub(crate) fn get_birth_epoch(&self) -> u64 {
        self.birth_epoch
    }

    // gets the direction of node, i.e. if it's a left
    // child or right. If not found, return None
    fn get_direction(&self, node: &Self) -> Direction {
        // TODO(eoz): Return direction instead of int.
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
    ) -> Result<Option<HistoryTreeNode>, AkdError> {
        match direction {
            Direction::None => Err(AkdError::HistoryTreeNode(
                HistoryTreeNodeError::NoDirection(self.label, None),
            )),
            Direction::Some(dir) => {
                if let Some(child_label) = self.get_child_label(direction) {
                    let child_key = NodeKey(child_label);
                    let get_result = storage.get::<HistoryTreeNode>(&child_key).await?;
                    match get_result {
                        DbRecord::HistoryTreeNode(ht_node) => Ok(Some(ht_node)),
                        _ => Err(AkdError::Storage(StorageError::NotFound(format!(
                            "HistoryTreeNode {:?}",
                            child_key
                        )))),
                    }
                } else {
                    return Ok(None);
                }
            }
        }
    }

    pub(crate) fn get_child<S: Storage + Sync + Send>(
        &self,
        storage: &S,
        direction: Direction,
    ) -> Result<Option<NodeLabel>, AkdError> {
        match direction {
            Direction::None => Err(AkdError::HistoryTreeNode(
                HistoryTreeNodeError::NoDirection(self.label, None),
            )),
            Direction::Some(dir) => {
                // TODO(eoz): Use Direction:Left and Direction:Right instead
                if dir == 0 {
                    Ok(self.left_child)
                } else if dir == 1 {
                    Ok(self.right_child)
                } else {
                    panic!(
                        "AKD is based on a binary tree. No child with a given index: {}",
                        dir
                    );
                }
            }
        }
    }

    // pub(crate) async fn get_state_at_epoch<S: Storage + Sync + Send>(
    //     &self,
    //     storage: &S,
    //     epoch: u64,
    // ) -> Result<HistoryNodeState, AkdError> {
    //     if self.get_birth_epoch() > epoch {
    //         Err(AkdError::HistoryTreeNode(
    //             HistoryTreeNodeError::NonexistentAtEpoch(self.label, epoch),
    //         ))
    //     } else {
    //         let chosen_ep = {
    //             if self.last_epoch <= epoch {
    //                 // the "last" updated epoch is <= epoch, so it is
    //                 // the last valid state at this epoch
    //                 Some(self.last_epoch)
    //             } else if self.birth_epoch == epoch {
    //                 // we're looking at the state at the birth epoch
    //                 Some(self.birth_epoch)
    //             } else {
    //                 // Indeterminate, we are somewhere above the
    //                 // birth epoch but we're less than the "last" epoch.
    //                 // db query is necessary
    //                 None
    //             }
    //         };
    //         if let Some(ep) = chosen_ep {
    //             self.get_state_at_existing_epoch(storage, ep).await
    //         } else {
    //             let target_ep = storage.get_epoch_lte_epoch(self.label, epoch).await?;
    //             // DB query for the state <= this epoch value
    //             self.get_state_at_existing_epoch(storage, target_ep).await
    //         }
    //     }
    // }

    // async fn get_state_at_existing_epoch<S: Storage + Sync + Send>(
    //     &self,
    //     storage: &S,
    //     epoch: u64,
    // ) -> Result<HistoryNodeState, AkdError> {
    //     Ok(get_state_map(storage, self, epoch)
    //         .await
    //         .map_err(|_| HistoryTreeNodeError::NoStateAtEpoch(self.label, epoch))?)
    // }

    /* Functions for compression-related operations */

    pub(crate) fn get_latest_epoch(&self) -> u64 {
        self.last_epoch
    }

    /////// Helpers /////////

    async fn to_node_unhashed_child_state<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
    ) -> Result<HistoryChildState, AkdError> {
        Ok(HistoryChildState {
            label: self.label,
            hash_val: from_digest::<H>(H::merge(&[
                self.get_value::<_, H>(storage).await?,
                hash_label::<H>(self.label),
            ])),
            epoch_version: self.get_latest_epoch(),
        })
    }

    #[cfg(test)]
    pub(crate) async fn to_node_child_state<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
    ) -> Result<HistoryChildState, AkdError> {
        Ok(HistoryChildState {
            label: self.label,
            hash_val: from_digest::<H>(H::merge(&[
                self.get_value::<_, H>(storage).await?,
                hash_label::<H>(self.label),
            ])),
            epoch_version: self.get_latest_epoch(),
        })
    }
}

/////// Helpers //////

pub(crate) fn optional_child_state_to_hash<H: Hasher>(
    input: &Option<HistoryTreeNode>,
) -> [u8; 32] {
    match input {
        Some(child_state) => child_state.hash,
        None => from_digest::<H>(crate::utils::empty_node_hash::<H>()),
    }
}

pub(crate) fn optional_child_state_to_label(
    input: &Option<NodeLabel>,
) -> NodeLabel {
    match input {
        Some(label) => *label,
        None => EMPTY_LABEL,
    }
}

/// Retrieve an empty root node
pub async fn get_empty_root<H: Hasher, S: Storage + Send + Sync>(
    storage: &S,
    ep: Option<u64>,
) -> Result<HistoryTreeNode, AkdError> {
    // Since empty root has no children and has no value, its
    let empty_root_hash = from_digest::<H>(H::hash(&EMPTY_VALUE));
    let mut node = HistoryTreeNode::new(
        NodeLabel::root(),
        NodeLabel::root(),
        NodeType::Root,
        0u64,
        None,
        None,
        empty_root_hash,
    );
    if let Some(epoch) = ep {
        node.birth_epoch = epoch;
        node.last_epoch = epoch;
    }

    Ok(node)
}

/// Get a specific leaf node
pub async fn get_leaf_node<H: Hasher, S: Storage + Sync + Send>(
    storage: &S,
    label: NodeLabel,
    value: &H::Digest,
    parent: NodeLabel,
    birth_epoch: u64,
) -> Result<HistoryTreeNode, AkdError> {
    // Leaf hash is the hash of its value (no children are hashed).
    let leaf_hash = from_digest::<H>(H::merge(&[H::hash(&EMPTY_VALUE), *value]));

    let node = HistoryTreeNode {
        label,
        birth_epoch,
        last_epoch: birth_epoch,
        parent,
        node_type: NodeType::Leaf,
        // Leaf has no children
        left_child: None,
        right_child: None,
        hash: leaf_hash,
    };

    Ok(node)
}

pub(crate) async fn get_leaf_node_without_hashing<H: Hasher, S: Storage + Sync + Send>(
    storage: &S,
    node: Node<H>,
    parent: NodeLabel,
    birth_epoch: u64,
) -> Result<HistoryTreeNode, AkdError> {
    let leaf_hash = from_digest::<H>(node.hash);
    let history_node = HistoryTreeNode {
        label: node.label,
        birth_epoch,
        last_epoch: birth_epoch,
        parent,
        node_type: NodeType::Leaf,
        left_child: None,
        right_child: None,
        hash: leaf_hash,
    };

    Ok(history_node)
}

pub(crate) async fn set_state_map<S: Storage + Sync + Send>(
    storage: &S,
    val: HistoryNodeState,
) -> Result<(), StorageError> {
    storage.set(DbRecord::HistoryNodeState(val)).await
}

pub(crate) async fn get_state_map<S: Storage + Sync + Send>(
    storage: &S,
    node: &HistoryTreeNode,
    key: u64,
) -> Result<HistoryNodeState, StorageError> {
    let state_key = get_state_map_key(node, key);
    if let Ok(DbRecord::HistoryNodeState(state)) = storage.get::<HistoryNodeState>(&state_key).await
    {
        Ok(state)
    } else {
        Err(StorageError::NotFound(format!(
            "HistoryNodeState {:?}",
            state_key
        )))
    }
}

pub(crate) fn get_state_map_key(node: &HistoryTreeNode, key: u64) -> NodeStateKey {
    NodeStateKey(node.label, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        node_state::{byte_arr_from_u64, hash_label, HistoryChildState, NodeLabel},
        serialization::from_digest,
    };
    use std::convert::TryInto;
    use winter_crypto::{hashers::Blake3_256, Hasher};
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type InMemoryDb = crate::storage::memory::AsyncInMemoryDatabase;

    ////////// history_tree_node tests //////
    //  Test set_child_without_hash and get_child_state

    // #[tokio::test]
    // async fn test_set_child_without_hash_at_root() -> Result<(), AkdError> {
    //     let ep = 1;
    //     let db = InMemoryDb::new();
    //     let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    //     let child_hist_node_1 = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(1), 1),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     root.write_to_storage(&db).await?;
    //     root.set_child::<_, Blake3>(&(Direction::Some(1), &child_hist_node_1.clone()), ep);

    //     let set_child = root
    //         .get_child_state::<_, Blake3>(&db, ep, Direction::Some(1))
    //         .await
    //         .map_err(|_| panic!("Child not set in test_set_child_without_hash_at_root"))
    //         .unwrap();
    //     assert!(
    //         set_child == Some(child_hist_node_1),
    //         "Child in direction is not equal to the set value"
    //     );
    //     assert!(root.get_latest_epoch() == 1, "Latest epochs don't match!");
    //     assert!(
    //         root.birth_epoch == root.last_epoch,
    //         "How would the last epoch be different from the birth epoch without an update?"
    //     );

    //     Ok(())
    // }

    // #[tokio::test]
    // async fn test_set_children_without_hash_at_root() -> Result<(), AkdError> {
    //     let ep = 1;
    //     let db = InMemoryDb::new();
    //     let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    //     let child_hist_node_1 = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(1), 1),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     let child_hist_node_2: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(0), 1),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     root.write_to_storage(&db).await?;
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_1.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_2.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     let set_child_1 = root
    //         .get_child_state::<_, Blake3>(&db, ep, Direction::Some(1))
    //         .await;
    //     match set_child_1 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_1),
    //             "Child in 1 is not equal to the set value"
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }

    //     let set_child_2 = root
    //         .get_child_state::<_, Blake3>(&db, ep, Direction::Some(0))
    //         .await;
    //     match set_child_2 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_2),
    //             "Child in 0 is not equal to the set value"
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }
    //     let latest_ep = root.get_latest_epoch();
    //     assert!(latest_ep == 1, "Latest epochs don't match!");
    //     assert!(
    //         root.birth_epoch == root.last_epoch,
    //         "How would the last epoch be different from the birth epoch without an update?"
    //     );

    //     Ok(())
    // }

    // #[tokio::test]
    // async fn test_set_children_without_hash_multiple_at_root() -> Result<(), AkdError> {
    //     let mut ep = 1;
    //     let db = InMemoryDb::new();
    //     let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    //     let child_hist_node_1 = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(11), 2),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     let child_hist_node_2: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(00), 2),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     root.write_to_storage(&db).await?;
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_1))
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_2))
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );

    //     ep = 2;

    //     let child_hist_node_3: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(1), 1),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     let child_hist_node_4: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(0), 1),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     root.write_to_storage(&db).await?;
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_3.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_4.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     let set_child_1 = root
    //         .get_child_state::<_, Blake3>(&db, ep, Direction::Some(1))
    //         .await;
    //     match set_child_1 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_3),
    //             "Child in 1 is not equal to the set value"
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }

    //     let set_child_2 = root
    //         .get_child_state::<_, Blake3>(&db, ep, Direction::Some(0))
    //         .await;
    //     match set_child_2 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_4),
    //             "Child in 0 is not equal to the set value"
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }
    //     let latest_ep = root.get_latest_epoch();
    //     assert!(latest_ep == 2, "Latest epochs don't match!");
    //     assert!(
    //         root.birth_epoch < root.last_epoch,
    //         "How is the last epoch not higher than the birth epoch after an udpate?"
    //     );

    //     Ok(())
    // }

    // #[tokio::test]
    // async fn test_get_child_state_multiple_at_root() -> Result<(), AkdError> {
    //     let mut ep = 1;
    //     let db = InMemoryDb::new();
    //     let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(ep)).await?;
    //     let child_hist_node_1 = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(11), 2),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     let child_hist_node_2: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(00), 2),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     root.write_to_storage(&db).await?;
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_1.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_2.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );

    //     ep = 2;

    //     let child_hist_node_3: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(1), 1),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     let child_hist_node_4: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(byte_arr_from_u64(0), 1),
    //         Blake3::hash(&EMPTY_VALUE),
    //         ep,
    //     );
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(1), child_hist_node_3.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     assert!(
    //         root.set_child::<_, Blake3>(&db, ep, &(Direction::Some(0), child_hist_node_4.clone()),)
    //             .await
    //             .is_ok(),
    //         "Setting the child without hash threw an error"
    //     );
    //     let set_child_1 = root
    //         .get_child_state::<_, Blake3>(&db, 1, Direction::Some(1))
    //         .await;
    //     match set_child_1 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_1),
    //             "Child in 1 is not equal to the set value"
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }

    //     let set_child_2 = root
    //         .get_child_state::<_, Blake3>(&db, 1, Direction::Some(0))
    //         .await;
    //     match set_child_2 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_2),
    //             "Child in 0 is not equal to the set value"
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }
    //     let latest_ep = root.get_latest_epoch();
    //     assert!(latest_ep == 2, "Latest epochs don't match!");
    //     assert!(
    //         root.birth_epoch < root.last_epoch,
    //         "How is the last epoch not higher than the birth epoch after an udpate?"
    //     );

    //     Ok(())
    // }

    // //  Test get_child_at_epoch
    // #[tokio::test]
    // pub async fn test_get_child_at_epoch_at_root() -> Result<(), AkdError> {
    //     let init_ep = 0;
    //     let db = InMemoryDb::new();
    //     let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(init_ep)).await?;

    //     for ep in 0..3 {
    //         let child_hist_node_1 = HistoryChildState::new::<Blake3>(
    //             NodeLabel::new(
    //                 byte_arr_from_u64(0b1u64 << ep.clone()),
    //                 ep.try_into().unwrap(),
    //             ),
    //             Blake3::hash(&EMPTY_VALUE),
    //             2 * ep,
    //         );
    //         let child_hist_node_2: HistoryChildState = HistoryChildState::new::<Blake3>(
    //             NodeLabel::new(byte_arr_from_u64(0), ep.clone().try_into().unwrap()),
    //             Blake3::hash(&EMPTY_VALUE),
    //             2 * ep,
    //         );
    //         root.write_to_storage(&db).await?;
    //         root.set_child::<_, Blake3>(&db, 2 * ep, &(Direction::Some(1), child_hist_node_1))
    //             .await?;
    //         root.set_child::<_, Blake3>(&db, 2 * ep, &(Direction::Some(0), child_hist_node_2))
    //             .await?;
    //     }

    //     let ep_existing = 0u64;

    //     let child_hist_node_1 = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(
    //             byte_arr_from_u64(0b1u64 << ep_existing.clone()),
    //             ep_existing.try_into().unwrap(),
    //         ),
    //         Blake3::hash(&EMPTY_VALUE),
    //         2 * ep_existing,
    //     );
    //     let child_hist_node_2: HistoryChildState = HistoryChildState::new::<Blake3>(
    //         NodeLabel::new(
    //             byte_arr_from_u64(0),
    //             ep_existing.clone().try_into().unwrap(),
    //         ),
    //         Blake3::hash(&EMPTY_VALUE),
    //         2 * ep_existing,
    //     );

    //     let set_child_1 = root.get_child_state(&db, Direction::Some(1));
    //     match set_child_1 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_1),
    //             "Child in 1 is not equal to the set value = {:?}",
    //             child_st
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }

    //     let set_child_2 = root.get_child_state(&db, Direction::Some(0));
    //     match set_child_2 {
    //         Ok(child_st) => assert!(
    //             child_st == Some(child_hist_node_2),
    //             "Child in 0 is not equal to the set value"
    //         ),
    //         Err(_) => panic!("Child not set in test_set_children_without_hash_at_root"),
    //     }
    //     let latest_ep = root.get_latest_epoch();
    //     assert!(latest_ep == 4, "Latest epochs don't match!");
    //     assert!(
    //         root.birth_epoch < root.last_epoch,
    //         "How is the last epoch not higher than the birth epoch after an udpate?"
    //     );

    //     Ok(())
    // }

    // insert_single_leaf tests

    #[tokio::test]
    async fn test_insert_single_leaf_root() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
        let new_leaf = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32),
            &Blake3::hash(&EMPTY_VALUE),
            NodeLabel::root(),
            0,
        )
        .await?;

        let leaf_1 = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32),
            &Blake3::hash(&[1u8]),
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
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b0u8])]),
            hash_label::<Blake3>(new_leaf.label),
        ]);

        let leaf_1_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b1u8])]),
            hash_label::<Blake3>(leaf_1.label),
        ]);

        let expected = Blake3::merge(&[
            Blake3::merge(&[
                Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), leaf_0_hash]),
                leaf_1_hash,
            ]),
            hash_label::<Blake3>(root.label),
        ]);
        assert_eq!(root_val, expected, "Root hash not equal to expected");

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_below_root() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
        let new_leaf = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b00u64), 2u32),
            &Blake3::hash(&EMPTY_VALUE),
            NodeLabel::root(),
            1,
        )
        .await?;

        let leaf_1 = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b11u64 << 62), 2u32),
            &Blake3::hash(&[1u8]),
            NodeLabel::root(),
            2,
        )
        .await?;

        let leaf_2 = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b10u64 << 62), 2u32),
            &Blake3::hash(&[1u8, 1u8]),
            NodeLabel::root(),
            3,
        )
        .await?;

        let leaf_0_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b0u8])]),
            hash_label::<Blake3>(new_leaf.label),
        ]);

        let leaf_1_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b1u8])]),
            hash_label::<Blake3>(leaf_1.label),
        ]);

        let leaf_2_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[1u8, 1u8])]),
            hash_label::<Blake3>(leaf_2.label),
        ]);

        let right_child_expected_hash = Blake3::merge(&[
            Blake3::merge(&[
                Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), leaf_2_hash]),
                leaf_1_hash,
            ]),
            hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32)),
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
                Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), leaf_0_hash]),
                right_child_expected_hash,
            ]),
            hash_label::<Blake3>(root.label),
        ]);
        assert!(root_val == expected, "Root hash not equal to expected");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_below_root_both_sides() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
        let new_leaf = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b000u64), 3u32),
            &Blake3::hash(&EMPTY_VALUE),
            NodeLabel::root(),
            0,
        )
        .await?;

        let leaf_1 = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b111u64 << 61), 3u32),
            &Blake3::hash(&[1u8]),
            NodeLabel::root(),
            0,
        )
        .await?;

        let leaf_2 = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b100u64 << 61), 3u32),
            &Blake3::hash(&[1u8, 1u8]),
            NodeLabel::root(),
            0,
        )
        .await?;

        let leaf_3 = get_leaf_node::<Blake3, _>(
            &db,
            NodeLabel::new(byte_arr_from_u64(0b010u64 << 61), 3u32),
            &Blake3::hash(&[0u8, 1u8]),
            NodeLabel::root(),
            0,
        )
        .await?;

        let leaf_0_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b0u8])]),
            hash_label::<Blake3>(new_leaf.label),
        ]);

        let leaf_1_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b1u8])]),
            hash_label::<Blake3>(leaf_1.label),
        ]);
        let leaf_2_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b1u8, 0b1u8])]),
            hash_label::<Blake3>(leaf_2.label),
        ]);

        let leaf_3_hash = Blake3::merge(&[
            Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), Blake3::hash(&[0b0u8, 0b1u8])]),
            hash_label::<Blake3>(leaf_3.label),
        ]);

        let _right_child_expected_hash = Blake3::merge(&[
            Blake3::merge(&[
                Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), leaf_2_hash]),
                leaf_1_hash,
            ]),
            hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32)),
        ]);

        let _left_child_expected_hash = Blake3::merge(&[
            Blake3::merge(&[
                Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), leaf_0_hash]),
                leaf_3_hash,
            ]),
            hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(0b0u64), 1u32)),
        ]);

        let mut leaf_0_as_child = new_leaf.to_node_child_state::<_, Blake3>(&db).await?;
        leaf_0_as_child.hash_val = from_digest::<Blake3>(leaf_0_hash);

        let mut leaf_3_as_child = leaf_3.to_node_child_state::<_, Blake3>(&db).await?;
        leaf_3_as_child.hash_val = from_digest::<Blake3>(leaf_3_hash);

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
        //         Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), left_child_expected_hash]),
        //         right_child_expected_hash,
        //     ]),
        //     hash_label::<Blake3>(root.label),
        // ]);
        // assert!(root_val == expected, "Root hash not equal to expected");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_single_leaf_full_tree() -> Result<(), AkdError> {
        let db = InMemoryDb::new();
        let mut root = get_empty_root::<Blake3, _>(&db, Option::Some(0u64)).await?;
        root.write_to_storage(&db).await?;
        let mut num_nodes = 1;
        let mut leaves = Vec::<HistoryTreeNode>::new();
        let mut leaf_hashes = Vec::new();
        for i in 0u64..8u64 {
            let leaf_u64 = i.clone() << 61;
            let new_leaf = get_leaf_node::<Blake3, _>(
                &db,
                NodeLabel::new(byte_arr_from_u64(leaf_u64), 3u32),
                &Blake3::hash(&leaf_u64.to_be_bytes()),
                NodeLabel::root(),
                7 - i,
            )
            .await?;
            leaf_hashes.push(Blake3::merge(&[
                Blake3::merge(&[
                    Blake3::hash(&EMPTY_VALUE),
                    Blake3::hash(&leaf_u64.to_be_bytes()),
                ]),
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
                    Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), left_child_hash]),
                    right_child_hash,
                ]),
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
                Blake3::merge(&[
                    Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), left_child_hash]),
                    right_child_hash,
                ]),
                hash_label::<Blake3>(NodeLabel::new(byte_arr_from_u64(j << 63), 1u32)),
            ]));
            j += 1;
        }

        let expected = Blake3::merge(&[
            Blake3::merge(&[
                Blake3::merge(&[Blake3::hash(&EMPTY_VALUE), layer_2_hashes[0]]),
                layer_2_hashes[1],
            ]),
            hash_label::<Blake3>(root.label),
        ]);

        for i in 0..8 {
            let ep: u64 = i.try_into().unwrap();
            root.insert_single_leaf::<_, Blake3>(
                &db,
                leaves[7 - i].clone(),
                ep + 1,
                &mut num_nodes,
            )
            .await?;
        }

        let root_val = root.get_value::<_, Blake3>(&db).await?;

        assert!(root_val == expected, "Root hash not equal to expected");
        Ok(())
    }
}
