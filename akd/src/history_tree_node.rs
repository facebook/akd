// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The implementation of a node for a history patricia tree

use crate::errors::{HistoryTreeNodeError, StorageError};
use crate::serialization::{from_digest, to_digest};
use crate::storage::types::{DbRecord, StorageType};
use crate::storage::{Storable, Storage};
use crate::{node_state::*, Direction, ARITY, EMPTY_LABEL, EMPTY_VALUE};
use async_recursion::async_recursion;
use log::debug;
use std::convert::TryInto;
use std::marker::{Send, Sync};
use winter_crypto::Hasher;

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

pub(crate) type HistoryInsertionNode = (Direction, HistoryChildState);

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
        }
    }
}

impl HistoryTreeNode {
    fn new(label: NodeLabel, parent: NodeLabel, node_type: NodeType, birth_epoch: u64) -> Self {
        HistoryTreeNode {
            label,
            birth_epoch,
            last_epoch: birth_epoch,
            parent, // Root node is its own parent
            node_type,
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
            _ => Err(StorageError::GetData(String::from("Not found"))),
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
                return Err(StorageError::GetData(String::from(
                    "Batch retrieve returned types <> HistoryTreeNode",
                )));
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
    ) -> Result<(), HistoryTreeNodeError> {
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
    ) -> Result<(), HistoryTreeNodeError> {
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
    ) -> Result<(), HistoryTreeNodeError> {
        let (lcs_label, dir_leaf, dir_self) = self
            .label
            .get_longest_common_prefix_and_dirs(new_leaf.label);

        if self.is_root() {
            new_leaf.write_to_storage(storage).await?;
            *num_nodes += 1;
            // the root should always be instantiated with dummy children in the beginning
            let child_state = self
                .get_child_at_epoch::<_, H>(storage, self.get_latest_epoch()?, dir_leaf)
                .await?;
            if child_state == None {
                new_leaf.parent = self.label;
                self.set_node_child::<_, H>(storage, epoch, dir_leaf, &new_leaf)
                    .await?;
                self.write_to_storage(storage).await?;
                new_leaf.write_to_storage(storage).await?;

                if hashing {
                    new_leaf.update_hash::<_, H>(storage, epoch).await?;
                    let mut new_self: HistoryTreeNode =
                        HistoryTreeNode::get_from_storage(storage, &NodeKey(self.label), epoch)
                            .await?;
                    new_self.update_hash::<_, H>(storage, epoch).await?;
                    *self = new_self;
                } else {
                    *self = HistoryTreeNode::get_from_storage(storage, &NodeKey(self.label), epoch)
                        .await?;
                }

                return Ok(());
            }
        }

        // if a node is the longest common prefix of itself and the leaf, dir_self will be None
        match dir_self {
            Some(_) => {
                // This is the case where the calling node and the leaf have a longest common prefix
                // not equal to the label of the calling node.
                // This means that the current node needs to be pushed down one level (away from root)
                // in the tree and replaced with a new node whose label is equal to the longest common prefix.
                debug!("BEGIN get parent");
                let mut parent =
                    HistoryTreeNode::get_from_storage(storage, &NodeKey(self.parent), epoch)
                        .await?;
                debug!("BEGIN get direction at epoch {}", epoch);
                let self_dir_in_parent = parent.get_direction_at_ep(storage, self, epoch).await?;

                debug!("BEGIN create new node");
                let mut new_node =
                    HistoryTreeNode::new(lcs_label, parent.label, NodeType::Interior, epoch);
                new_node.write_to_storage(storage).await?;
                set_state_map(
                    storage,
                    HistoryNodeState::new::<H>(NodeStateKey(new_node.label, epoch))?,
                )
                .await?;
                *num_nodes += 1;
                // Add this node in the correct dir and child node in the other direction
                debug!("BEGIN update leaf label");
                new_leaf.parent = new_node.label;
                new_leaf.write_to_storage(storage).await?;

                debug!("BEGIN update self");
                self.parent = new_node.label;
                self.write_to_storage(storage).await?;

                debug!("BEGIN set node child new_node(new_leaf)");
                new_node
                    .set_node_child::<_, H>(storage, epoch, dir_leaf, &new_leaf)
                    .await?;
                debug!("BEGIN set node child new_node(self)");
                new_node
                    .set_node_child::<_, H>(storage, epoch, dir_self, self)
                    .await?;

                debug!("BEGIN set node child parent(new_node)");
                parent
                    .set_node_child::<_, H>(storage, epoch, self_dir_in_parent, &new_node)
                    .await?;
                if hashing {
                    debug!("BEGIN update hashes");
                    new_leaf.update_hash::<_, H>(storage, epoch).await?;
                    self.update_hash::<_, H>(storage, epoch).await?;
                    new_node =
                        HistoryTreeNode::get_from_storage(storage, &NodeKey(new_node.label), epoch)
                            .await?;
                    new_node.update_hash::<_, H>(storage, epoch).await?;
                }
                debug!("BEGIN save new_node");
                new_node.write_to_storage(storage).await?;
                debug!("BEGIN save parent");
                parent.write_to_storage(storage).await?;
                debug!("BEGIN retrieve new self");
                *self =
                    HistoryTreeNode::get_from_storage(storage, &NodeKey(self.label), epoch).await?;
                debug!("END insert single leaf (dir_self = Some)");
                Ok(())
            }
            None => {
                // case where the current node is equal to the lcs
                debug!("BEGIN get child at epoch");
                let child_st = self
                    .get_child_at_epoch::<_, H>(storage, self.get_latest_epoch()?, dir_leaf)
                    .await?
                    .ok_or(HistoryTreeNodeError::NoChildAtEpoch(
                        self.get_latest_epoch()?,
                        dir_leaf.unwrap_or(0),
                    ))?;

                debug!("BEGIN get child node from storage");
                let mut child_node =
                    HistoryTreeNode::get_from_storage(storage, &NodeKey(child_st.label), epoch)
                        .await?;
                debug!("BEGIN insert single leaf helper");
                child_node
                    .insert_single_leaf_helper::<_, H>(storage, new_leaf, epoch, num_nodes, hashing)
                    .await?;
                if hashing {
                    debug!("BEGIN update hashes");
                    *self = HistoryTreeNode::get_from_storage(storage, &NodeKey(self.label), epoch)
                        .await?;
                    self.update_hash::<_, H>(storage, epoch).await?;
                    self.write_to_storage(storage).await?;
                } else {
                    debug!("BEGIN retrieve self");
                    *self = HistoryTreeNode::get_from_storage(storage, &NodeKey(self.label), epoch)
                        .await?;
                }
                debug!("END insert single leaf (dir_self = None)");
                Ok(())
            }
        }
    }

    /// Updates the hash of this node as stored in its parent,
    /// provided the children of this node have already updated their own versions
    /// in this node and epoch is contained in the state_map
    /// Also assumes that `set_child_without_hash` has already been called
    pub(crate) async fn update_hash<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        epoch: u64,
    ) -> Result<(), HistoryTreeNodeError> {
        match self.node_type {
            NodeType::Leaf => {
                // the hash of this is just the value, simply place in parent
                let leaf_hash_val = H::merge(&[
                    self.get_value::<_, H>(storage).await?,
                    hash_label::<H>(self.label),
                ]);
                self.update_hash_at_parent::<_, H>(storage, epoch, leaf_hash_val)
                    .await
            }
            _ => {
                // the root has no parent, so the hash must only be stored within the value
                let mut hash_digest = self.hash_node::<_, H>(storage, epoch).await?;
                if self.is_root() {
                    hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
                }
                let mut updated_state = self.get_state_at_epoch(storage, epoch).await?;
                updated_state.value = from_digest::<H>(hash_digest)?;
                updated_state.key = NodeStateKey(self.label, epoch);
                set_state_map(storage, updated_state).await?;

                self.write_to_storage(storage).await?;
                let hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
                self.update_hash_at_parent::<_, H>(storage, epoch, hash_digest)
                    .await
            }
        }
    }

    /// Hashes a node by merging the hashes and labels of its children.
    async fn hash_node<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        let epoch_node_state = self.get_state_at_epoch(storage, epoch).await?;
        let mut new_hash = H::hash(&EMPTY_VALUE);
        for child_index in 0..ARITY {
            new_hash = H::merge(&[
                new_hash,
                to_digest::<H>(&optional_history_child_state_to_hash::<H>(
                    &epoch_node_state.get_child_state_in_dir(child_index),
                )?)?,
            ]);
        }
        Ok(new_hash)
    }

    /// Writes the new_hash_val into the parent's state for this epoch.
    /// Accounts for the case when considering a root node, which has no parent.
    async fn update_hash_at_parent<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        epoch: u64,
        new_hash_val: H::Digest,
    ) -> Result<(), HistoryTreeNodeError> {
        if self.is_root() {
            return Ok(());
        }

        let parent =
            &mut HistoryTreeNode::get_from_storage(storage, &NodeKey(self.parent), epoch).await?;
        if parent.get_latest_epoch()? < epoch {
            let (_, dir_self, _) = parent.label.get_longest_common_prefix_and_dirs(self.label);
            parent
                .set_node_child::<_, H>(storage, epoch, dir_self, self)
                .await?;
            parent.write_to_storage(storage).await?;
            *parent =
                HistoryTreeNode::get_from_storage(storage, &NodeKey(self.parent), epoch).await?;
        }

        match get_state_map(storage, parent, epoch).await {
            Err(_) => Err(HistoryTreeNodeError::ParentNextEpochInvalid(epoch)),
            Ok(parent_state) => match parent.get_direction_at_ep(storage, self, epoch).await? {
                None => Err(HistoryTreeNodeError::HashUpdateOrderInconsistent),
                Some(s_dir) => {
                    let mut parent_updated_state = parent_state;
                    let mut self_child_state =
                        parent_updated_state
                            .get_child_state_in_dir(s_dir)
                            .ok_or(HistoryTreeNodeError::NoChildAtEpoch(epoch, s_dir))?;
                    self_child_state.hash_val = from_digest::<H>(new_hash_val)?;
                    parent_updated_state.child_states[s_dir] = Some(self_child_state);
                    parent_updated_state.key = NodeStateKey(parent.label, epoch);
                    set_state_map(storage, parent_updated_state).await?;
                    parent.write_to_storage(storage).await?;

                    Ok(())
                }
            },
        }
    }

    /// Inserts a child into this node, adding the state to the state at this epoch,
    /// without updating its own hash.
    #[async_recursion]
    pub(crate) async fn set_child<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        epoch: u64,
        child: &HistoryInsertionNode,
    ) -> Result<(), HistoryTreeNodeError> {
        let (direction, child_node) = child.clone();
        // It's possible that this node's latest epoch is not the same as
        // epoch, in which case, you should set the state to include the latest epoch.
        // We also make sure here, to update the list of epochs.
        // If you're here, you can be sure that get_state_at_epoch should return a value.
        // If it doesn't, then you must not have called set_state_map when you created this node.
        // That is, make sure after every call to HistoryTreeNode::new, there is a call to
        // set_state_map.
        if self.get_latest_epoch()? != epoch {
            set_state_map(
                storage,
                match self
                    .get_state_at_epoch(storage, self.get_latest_epoch()?)
                    .await
                {
                    Ok(mut latest_st) => {
                        latest_st.key = NodeStateKey(self.label, epoch);
                        latest_st
                    }
                    Err(_) => HistoryNodeState::new::<H>(NodeStateKey(self.label, epoch))?,
                },
            )
            .await?;

            match self.get_latest_epoch() {
                Ok(latest) => {
                    if latest != epoch {
                        self.last_epoch = epoch;
                    }
                }
                Err(_) => {
                    self.last_epoch = epoch;
                }
            }
            self.write_to_storage(storage).await?;
            self.set_child::<_, H>(storage, epoch, child).await?;
            return Ok(());
        }

        let dir = direction.map_or(
            Err(HistoryTreeNodeError::NoDirection(
                self.label,
                Some(child_node.label),
            )),
            Ok,
        )?;

        match get_state_map(storage, self, epoch).await {
            Ok(HistoryNodeState {
                value,
                mut child_states,
                key: _,
            }) => {
                child_states[dir] = Some(child_node.clone());
                set_state_map(
                    storage,
                    HistoryNodeState {
                        value,
                        child_states,
                        key: NodeStateKey(self.label, epoch),
                    },
                )
                .await?;
                Ok(())
            }
            Err(e) => Err(HistoryTreeNodeError::from(e)),
        }
    }

    /// This function is just a wrapper: given a [`HistoryTreeNode`], sets this node's latest value using
    /// set_child_without_hash. Just used for type conversion.
    pub(crate) async fn set_node_child<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        epoch: u64,
        dir: Direction,
        child: &Self,
    ) -> Result<(), HistoryTreeNodeError> {
        let node_as_child_state = child.to_node_unhashed_child_state::<_, H>(storage).await?;
        let insertion_node = (dir, node_as_child_state);
        self.set_child::<_, H>(storage, epoch, &insertion_node)
            .await
    }

    ////// getrs for this node ////

    pub(crate) async fn get_value_at_epoch<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        to_digest::<H>(&self.get_state_at_epoch(storage, epoch).await?.value)
    }

    pub(crate) async fn get_value_without_label_at_epoch<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        if self.is_leaf() {
            return self.get_value_at_epoch::<_, H>(storage, epoch).await;
        }
        let children = self.get_state_at_epoch(storage, epoch).await?.child_states;
        let mut new_hash = H::hash(&EMPTY_VALUE);
        for child in children.iter().take(ARITY) {
            let hash_val = optional_history_child_state_to_hash::<H>(child)?;
            new_hash = H::merge(&[new_hash, to_digest::<H>(&hash_val)?]);
        }
        Ok(new_hash)
    }

    pub(crate) async fn get_child_label_at_epoch<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
        dir: Direction,
    ) -> Result<NodeLabel, HistoryTreeNodeError> {
        Ok(self
            .get_child_at_epoch::<_, H>(storage, epoch, dir)
            .await?
            .ok_or_else(|| HistoryTreeNodeError::NoChildAtEpoch(epoch, dir.unwrap_or(0)))?
            .label)
    }

    // gets value at current epoch
    pub(crate) async fn get_value<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        match get_state_map(storage, self, self.get_latest_epoch()?).await {
            Ok(state_map) => Ok(to_digest::<H>(&state_map.value)?),
            Err(er) => Err(er.into()),
        }
    }

    pub(crate) fn get_birth_epoch(&self) -> u64 {
        self.birth_epoch
    }

    // gets the direction of node, i.e. if it's a left
    // child or right. If not found, return None
    async fn get_direction_at_ep<S: Storage + Sync + Send>(
        &self,
        storage: &S,
        node: &Self,
        ep: u64,
    ) -> Result<Direction, HistoryTreeNodeError> {
        let state_at_ep = self.get_state_at_epoch(storage, ep).await?;
        for node_index in 0..ARITY {
            let node_val = state_at_ep.get_child_state_in_dir(node_index);
            if let Some(node_val) = node_val {
                if node_val.label == node.label {
                    return Ok(Some(node_index));
                }
            };
        }
        Ok(None)
    }

    pub(crate) fn is_root(&self) -> bool {
        matches!(self.node_type, NodeType::Root)
    }

    pub(crate) fn is_leaf(&self) -> bool {
        matches!(self.node_type, NodeType::Leaf)
    }

    ///// getrs for child nodes ////

    pub(crate) async fn get_child_at_epoch<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
        direction: Direction,
    ) -> Result<Option<HistoryChildState>, HistoryTreeNodeError> {
        match direction {
            Direction::None => Err(HistoryTreeNodeError::NoDirection(self.label, None)),
            Direction::Some(dir) => {
                if self.get_birth_epoch() > epoch {
                    Err(HistoryTreeNodeError::NoChildAtEpoch(epoch, dir))
                } else {
                    let chosen_ep = {
                        if self.last_epoch <= epoch {
                            // the "last" updated epoch is <= epoch, so it is
                            // the last valid state at this epoch
                            Some(self.last_epoch)
                        } else if self.birth_epoch == epoch {
                            // we're looking at the state at the birth epoch
                            Some(self.birth_epoch)
                        } else {
                            // Indeterminate, we are somewhere above the
                            // birth epoch but we're less than the "last" epoch.
                            // db query is necessary
                            None
                        }
                    };

                    if let Some(ep) = chosen_ep {
                        self.get_child_at_existing_epoch::<_, H>(storage, ep, direction)
                            .await
                    } else {
                        let target_ep = storage.get_epoch_lte_epoch(self.label, epoch).await?;
                        // DB query for the state <= this epoch value
                        self.get_child_at_existing_epoch::<_, H>(storage, target_ep, direction)
                            .await
                    }
                }
            }
        }
    }

    pub(crate) async fn get_child_at_existing_epoch<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
        direction: Direction,
    ) -> Result<Option<HistoryChildState>, HistoryTreeNodeError> {
        match direction {
            Direction::None => Err(HistoryTreeNodeError::NoDirection(self.label, None)),
            Direction::Some(dir) => Ok(get_state_map(storage, self, epoch)
                .await
                .map(|curr| curr.get_child_state_in_dir(dir))?),
        }
    }

    pub(crate) async fn get_state_at_epoch<S: Storage + Sync + Send>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<HistoryNodeState, HistoryTreeNodeError> {
        if self.get_birth_epoch() > epoch {
            Err(HistoryTreeNodeError::NonexistentAtEpoch(self.label, epoch))
        } else {
            let chosen_ep = {
                if self.last_epoch <= epoch {
                    // the "last" updated epoch is <= epoch, so it is
                    // the last valid state at this epoch
                    Some(self.last_epoch)
                } else if self.birth_epoch == epoch {
                    // we're looking at the state at the birth epoch
                    Some(self.birth_epoch)
                } else {
                    // Indeterminate, we are somewhere above the
                    // birth epoch but we're less than the "last" epoch.
                    // db query is necessary
                    None
                }
            };
            if let Some(ep) = chosen_ep {
                self.get_state_at_existing_epoch(storage, ep).await
            } else {
                let target_ep = storage.get_epoch_lte_epoch(self.label, epoch).await?;
                // DB query for the state <= this epoch value
                self.get_state_at_existing_epoch(storage, target_ep).await
            }
        }
    }

    async fn get_state_at_existing_epoch<S: Storage + Sync + Send>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<HistoryNodeState, HistoryTreeNodeError> {
        get_state_map(storage, self, epoch)
            .await
            .map_err(|_| HistoryTreeNodeError::NoStateAtEpoch(self.label, epoch))
    }

    /* Functions for compression-related operations */

    pub(crate) fn get_latest_epoch(&self) -> Result<u64, HistoryTreeNodeError> {
        Ok(self.last_epoch)
    }

    /////// Helpers /////////

    async fn to_node_unhashed_child_state<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
    ) -> Result<HistoryChildState, HistoryTreeNodeError> {
        Ok(HistoryChildState {
            label: self.label,
            hash_val: from_digest::<H>(H::merge(&[
                self.get_value::<_, H>(storage).await?,
                hash_label::<H>(self.label),
            ]))?,
            epoch_version: self.get_latest_epoch()?,
        })
    }

    #[cfg(test)]
    pub(crate) async fn to_node_child_state<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
    ) -> Result<HistoryChildState, HistoryTreeNodeError> {
        Ok(HistoryChildState {
            label: self.label,
            hash_val: from_digest::<H>(H::merge(&[
                self.get_value::<_, H>(storage).await?,
                hash_label::<H>(self.label),
            ]))?,
            epoch_version: self.get_latest_epoch()?,
        })
    }
}

/////// Helpers //////

pub(crate) fn optional_history_child_state_to_hash<H: Hasher>(
    input: &Option<HistoryChildState>,
) -> Result<Vec<u8>, HistoryTreeNodeError> {
    match input {
        Some(child_state) => Ok(child_state.hash_val.clone()),
        None => Ok(from_digest::<H>(crate::utils::empty_node_hash::<H>())?),
    }
}

pub(crate) fn optional_history_child_state_to_label(
    input: &Option<HistoryChildState>,
) -> NodeLabel {
    match input {
        Some(child_state) => child_state.label,
        None => EMPTY_LABEL,
    }
}

/// Retrieve an empty root node
pub async fn get_empty_root<H: Hasher, S: Storage + Send + Sync>(
    storage: &S,
    ep: Option<u64>,
) -> Result<HistoryTreeNode, HistoryTreeNodeError> {
    let mut node = HistoryTreeNode::new(NodeLabel::root(), NodeLabel::root(), NodeType::Root, 0u64);
    if let Some(epoch) = ep {
        node.birth_epoch = epoch;
        node.last_epoch = epoch;
        let new_state: HistoryNodeState =
            HistoryNodeState::new::<H>(NodeStateKey(node.label, epoch))?;
        set_state_map(storage, new_state).await?;
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
) -> Result<HistoryTreeNode, HistoryTreeNodeError> {
    let node = HistoryTreeNode {
        label,
        birth_epoch,
        last_epoch: birth_epoch,
        parent,
        node_type: NodeType::Leaf,
    };

    let mut new_state: HistoryNodeState =
        HistoryNodeState::new::<H>(NodeStateKey(node.label, birth_epoch))?;
    new_state.value = from_digest::<H>(H::merge(&[H::hash(&EMPTY_VALUE), value.clone()]))?;

    set_state_map(storage, new_state).await?;

    Ok(node)
}

pub(crate) async fn get_leaf_node_without_hashing<H: Hasher, S: Storage + Sync + Send>(
    storage: &S,
    node: Node<H>,
    parent: NodeLabel,
    birth_epoch: u64,
) -> Result<HistoryTreeNode, HistoryTreeNodeError> {
    let history_node = HistoryTreeNode {
        label: node.label,
        birth_epoch,
        last_epoch: birth_epoch,
        parent,
        node_type: NodeType::Leaf,
    };

    let mut new_state: HistoryNodeState =
        HistoryNodeState::new::<H>(NodeStateKey(history_node.label, birth_epoch))?;
    new_state.value = from_digest::<H>(node.hash)?;

    set_state_map(storage, new_state).await?;

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
    if let Ok(DbRecord::HistoryNodeState(state)) = storage
        .get::<HistoryNodeState>(&get_state_map_key(node, key))
        .await
    {
        Ok(state)
    } else {
        Err(StorageError::GetData(String::from("Not found")))
    }
}

pub(crate) fn get_state_map_key(node: &HistoryTreeNode, key: u64) -> NodeStateKey {
    NodeStateKey(node.label, key)
}
