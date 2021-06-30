// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::collections::HashMap;

use crate::{node_state::*, Direction, ARITY};
use crypto::hash::Hasher;

use crate::errors::HistoryTreeNodeError;

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum NodeType {
    Leaf,
    Root,
    Interior,
}

pub type HistoryInsertionNode<H> = (Direction, HistoryChildState<H>);
pub type HistoryNodeHash<H> = Option<H>;

/**
 * HistoryNode will represent a generic interior node of a compressed history tree
 **/
#[derive(Debug)]
pub struct HistoryTreeNode<H: Hasher> {
    pub label: NodeLabel,
    pub location: usize,
    pub epochs: Vec<u64>,
    pub state_map: HashMap<u64, HistoryNodeState<H>>,
    pub parent: usize,
    // Just use usize and have the 0th position be empty and that can be the parent of root. This makes things simpler.
    pub node_type: NodeType,
    // Note that the NodeType along with the parent/children being options
    // allows us to use this struct to represent child and parent nodes as well.
}

impl<H: Hasher> Clone for HistoryTreeNode<H> {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            location: self.location,
            epochs: self.epochs.clone(),
            state_map: self.state_map.clone(),
            parent: self.parent,
            node_type: self.node_type,
        }
    }
}

impl<H: Hasher> HistoryTreeNode<H> {
    pub fn new(label: NodeLabel, location: usize, parent: usize, node_type: NodeType) -> Self {
        let ep: Vec<u64> = Vec::new();
        let s_map: HashMap<u64, HistoryNodeState<H>> = HashMap::new();
        HistoryTreeNode {
            label,
            location,
            epochs: ep,
            state_map: s_map,
            parent, // Root node is its own parent
            node_type,
        }
    }

    // Inserts a single leaf node and updates the required hashes
    pub fn insert_single_leaf(
        &mut self,
        mut new_leaf: HistoryTreeNode<H>,
        epoch: u64,
        tree_repr_original: Vec<Self>,
    ) -> Result<(Self, Vec<Self>), HistoryTreeNodeError> {
        let mut tree_repr = tree_repr_original;
        if self.is_root() {
            new_leaf.location = tree_repr.len();
            tree_repr.push(new_leaf.clone());
            new_leaf = new_leaf.clone();
            tree_repr = tree_repr.clone();
        }
        let (lcs_label, dir_leaf, dir_self) = self
            .label
            .get_longest_common_prefix_and_dirs(new_leaf.get_label());
        match dir_self {
            Some(dir) => {
                let self_dir_in_parent = tree_repr[self.parent].get_direction_at_ep(self, epoch);
                let new_node_location = tree_repr.len();
                let mut new_node = HistoryTreeNode::new(
                    lcs_label,
                    new_node_location,
                    self.parent,
                    NodeType::Interior,
                );
                tree_repr.push(new_node.clone());

                new_node.set_node_child_without_hash(epoch, dir_leaf, new_leaf.clone())?;
                new_node.set_node_child_without_hash(epoch, dir_self, self.clone())?;
                tree_repr[new_node_location] = new_node.clone();
                tree_repr[self.parent].set_node_child_without_hash(
                    epoch,
                    self_dir_in_parent,
                    new_node.clone(),
                )?;
                new_leaf.parent = new_node.location;
                self.parent = new_node.location;
                tree_repr[new_leaf.location] = new_leaf.clone();
                tree_repr[self.location] = self.clone();
                tree_repr = new_leaf.update_hash(epoch, tree_repr)?;
                tree_repr = self.update_hash(epoch, tree_repr)?;

                tree_repr = tree_repr[new_node_location]
                    .clone()
                    .update_hash(epoch, tree_repr)?;

                Ok((tree_repr[new_node_location].clone(), tree_repr))
                // Add this node in the correct dir and child node in the other direction
            }
            None => {
                // case where the current node is equal to the lcs
                let child_state = self.get_child_at_epoch(self.get_latest_epoch()?, dir_leaf);
                match child_state {
                    Ok(child_st) => {
                        match child_st.dummy_marker {
                            DummyChildState::Dummy => {
                                new_leaf.parent = self.location;
                                if self.is_root() {
                                    self.set_node_child_without_hash(
                                        epoch,
                                        dir_leaf,
                                        new_leaf.clone(),
                                    )?;
                                    tree_repr[self.location] = self.clone();
                                    tree_repr = new_leaf.update_hash(epoch, tree_repr)?;
                                    let mut new_self = tree_repr[self.location].clone();
                                    tree_repr = new_self.update_hash(epoch, tree_repr)?;
                                    Ok((tree_repr[self.location].clone(), tree_repr))
                                } else {
                                    Err(HistoryTreeNodeError::CompressionError(self.label))
                                }
                            }
                            DummyChildState::Real => {
                                let mut child_node = tree_repr[child_st.location].clone();
                                let (mut updated_child, mut tree_repr) =
                                    child_node.insert_single_leaf(new_leaf, epoch, tree_repr)?;
                                tree_repr[self.location] = self.set_node_child_without_hash(
                                    epoch,
                                    dir_leaf,
                                    updated_child.clone(),
                                )?;
                                tree_repr = updated_child.update_hash(epoch, tree_repr)?;
                                let mut new_self = tree_repr[self.location].clone();
                                tree_repr = new_self.update_hash(epoch, tree_repr)?;
                                // let out_tree = new_leaf.update_hash(epoch, updated_tree.clone())?;
                                // new_leaf.parent = self.location;
                                Ok((tree_repr[self.location].clone(), tree_repr))
                            }
                        }
                    }
                    Err(e) => {
                        if self.is_root() {
                            tree_repr[self.location] = self.set_node_child_without_hash(
                                epoch,
                                dir_leaf,
                                new_leaf.clone(),
                            )?;
                            tree_repr = new_leaf.update_hash(epoch, tree_repr)?;
                            let mut new_self = tree_repr[self.location].clone();
                            let tree_repr = new_self.update_hash(epoch, tree_repr)?;
                            Ok((tree_repr[self.location].clone(), tree_repr))
                        } else {
                            Err(e)
                        }
                    }
                }
            }
        }
    }

    // Inserts a single leaf node
    pub fn insert_single_leaf_without_hash(
        &mut self,
        mut new_leaf: HistoryTreeNode<H>,
        epoch: u64,
        tree_repr_original: Vec<Self>,
    ) -> Result<(Self, Vec<Self>), HistoryTreeNodeError> {
        let mut tree_repr = tree_repr_original;
        if self.is_root() {
            new_leaf.location = tree_repr.len();
            tree_repr.push(new_leaf.clone());
            new_leaf = new_leaf.clone();
            tree_repr = tree_repr.clone();
        }
        let (lcs_label, dir_leaf, dir_self) = self
            .label
            .get_longest_common_prefix_and_dirs(new_leaf.get_label());
        match dir_self {
            Some(dir) => {
                let self_dir_in_parent = tree_repr[self.parent].get_direction_at_ep(self, epoch);
                let new_node_location = tree_repr.len();
                let mut new_node = HistoryTreeNode::new(
                    lcs_label,
                    new_node_location,
                    self.parent,
                    NodeType::Interior,
                );
                tree_repr.push(new_node.clone());

                new_node.set_node_child_without_hash(epoch, dir_leaf, new_leaf.clone())?;
                new_node.set_node_child_without_hash(epoch, dir_self, self.clone())?;
                tree_repr[new_node_location] = new_node.clone();
                tree_repr[self.parent].set_node_child_without_hash(
                    epoch,
                    self_dir_in_parent,
                    new_node.clone(),
                )?;
                new_leaf.parent = new_node.location;
                self.parent = new_node.location;
                tree_repr[new_leaf.location] = new_leaf.clone();
                tree_repr[self.location] = self.clone();

                Ok((tree_repr[new_node_location].clone(), tree_repr))
                // Add this node in the correct dir and child node in the other direction
            }
            None => {
                // case where the current node is equal to the lcs
                let child_state = self.get_child_at_epoch(self.get_latest_epoch()?, dir_leaf);
                match child_state {
                    Ok(child_st) => {
                        match child_st.dummy_marker {
                            DummyChildState::Dummy => {
                                new_leaf.parent = self.location;
                                if self.is_root() {
                                    self.set_node_child_without_hash(epoch, dir_leaf, new_leaf)?;
                                    tree_repr[self.location] = self.clone();

                                    Ok((tree_repr[self.location].clone(), tree_repr))
                                } else {
                                    Err(HistoryTreeNodeError::CompressionError(self.label))
                                }
                            }
                            DummyChildState::Real => {
                                let mut child_node = tree_repr[child_st.location].clone();
                                let (mut updated_child, mut tree_repr) =
                                    child_node.insert_single_leaf(new_leaf, epoch, tree_repr)?;
                                tree_repr[self.location] = self.set_node_child_without_hash(
                                    epoch,
                                    dir_leaf,
                                    updated_child,
                                )?;

                                // let out_tree = new_leaf.update_hash(epoch, updated_tree.clone())?;
                                // new_leaf.parent = self.location;
                                Ok((tree_repr[self.location].clone(), tree_repr))
                            }
                        }
                    }
                    Err(e) => {
                        if self.is_root() {
                            tree_repr[self.location] =
                                self.set_node_child_without_hash(epoch, dir_leaf, new_leaf)?;
                            Ok((tree_repr[self.location].clone(), tree_repr))
                        } else {
                            Err(e)
                        }
                    }
                }
            }
        }
    }

    /// Updates the hash of this node as stored in its parent,
    /// provided the children of this node have already updated their own versions
    /// in this node and epoch is contained in the state_map
    /// Also assumes that `set_child_without_hash` has already been called
    pub fn update_hash(
        &mut self,
        epoch: u64,
        tree_repr: Vec<Self>,
    ) -> Result<Vec<Self>, HistoryTreeNodeError> {
        match self.node_type {
            NodeType::Leaf => {
                // the hash of this is just the value, simply place in parent
                let leaf_hash_val = H::merge(&[hash_label::<H>(self.label), *self.get_value()?]);
                self.update_hash_at_parent(epoch, leaf_hash_val, tree_repr)
            }
            _ => {
                // the root has no parent, so the hash must only be stored within the value
                let hash_digest = self.hash_node_and_children(epoch)?;
                match self.state_map.get(&epoch) {
                    Some(epoch_state) => {
                        let mut updated_state = epoch_state.clone();
                        updated_state.value = hash_digest;
                        self.state_map.insert(epoch, updated_state);
                        let mut updated_tree = tree_repr;
                        updated_tree[self.location] = self.clone();
                        self.update_hash_at_parent(epoch, hash_digest, updated_tree)
                    }
                    None => Err(HistoryTreeNodeError::NoChildrenInTreeAtEpoch(epoch)),
                }
            }
        }
    }

    pub fn hash_node_and_children(
        &mut self,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        match self.state_map.get(&epoch) {
            None => Err(HistoryTreeNodeError::NoChildrenInTreeAtEpoch(epoch)),
            Some(mut epoch_node_state) => {
                let mut new_hash = hash_label::<H>(self.label);
                for child_index in 0..ARITY {
                    new_hash = H::merge(&[
                        new_hash,
                        epoch_node_state
                            .get_child_state_in_dir(child_index)
                            .hash_val,
                    ]);
                }
                Ok(new_hash)
            }
        }
    }

    pub fn update_hash_at_parent(
        &mut self,
        epoch: u64,
        new_hash_val: H::Digest,
        tree_repr: Vec<Self>,
    ) -> Result<Vec<Self>, HistoryTreeNodeError> {
        let mut tree_repr_copy = tree_repr;
        if self.is_root() {
            Ok(tree_repr_copy)
        } else {
            let mut parent = tree_repr_copy[self.parent].clone();
            println!("parent = {}", self.parent);
            println!("parent_state_epochs = {:?}", parent.state_map.keys());
            println!("self = {}", self.label.val);
            //let mut parent_latest_ep = parent.get_latest_epoch().unwrap_or(0);
            match parent.state_map.get(&epoch) {
                //&parent_latest_ep) {
                None => Err(HistoryTreeNodeError::ParentNextEpochInvalid(epoch)),
                Some(parent_state) => match parent.get_direction_at_ep(self, epoch) {
                    None => Err(HistoryTreeNodeError::HashUpdateOnlyAllowedAfterNodeInsertion),
                    Some(s_dir) => {
                        let mut parent_updated_state = parent_state.clone();
                        let mut self_child_state =
                            parent_updated_state.get_child_state_in_dir(s_dir);
                        self_child_state.hash_val = new_hash_val;
                        parent_updated_state.child_states[s_dir] = self_child_state;
                        parent.state_map.insert(epoch, parent_updated_state);
                        tree_repr_copy[self.parent] = parent.clone();
                        Ok(tree_repr_copy)
                    }
                },
            }
        }
    }

    pub fn set_child_without_hash(
        &mut self,
        epoch: u64,
        child: HistoryInsertionNode<H>,
    ) -> Result<Self, HistoryTreeNodeError> {
        let (direction, child_node) = child;

        match direction {
            Direction::Some(dir) => match self.state_map.get(&epoch) {
                Some(&HistoryNodeState {
                    value,
                    mut child_states,
                }) => {
                    child_states[dir] = child_node;
                    let mut new_state_map = self.state_map.clone();
                    new_state_map.insert(
                        epoch,
                        HistoryNodeState {
                            value,
                            child_states,
                        },
                    );
                    self.state_map = new_state_map;
                    Ok(self.clone())
                }
                None => {
                    self.state_map.insert(
                        epoch,
                        match self.state_map.get(&self.get_latest_epoch().unwrap_or(0)) {
                            Some(latest_st) => latest_st.clone(),

                            None => HistoryNodeState::<H>::new(),
                        },
                    );

                    match self.get_latest_epoch() {
                        Ok(latest) => {
                            if latest != epoch {
                                self.epochs.push(epoch);
                            }
                        }
                        Err(e) => {
                            self.epochs.push(epoch);
                        }
                    }

                    self.set_child_without_hash(epoch, child)
                }
            },
            Direction::None => Err(HistoryTreeNodeError::NoDirectionInSettingChild(
                self.get_label().get_val(),
                child_node.label.get_val(),
            )),
        }
    }

    pub fn set_node_child_without_hash(
        &mut self,
        epoch: u64,
        dir: Direction,
        child: Self,
    ) -> Result<Self, HistoryTreeNodeError> {
        let node_as_child_state = child.to_node_unhashed_child_state()?;
        let insertion_node = (dir, node_as_child_state);
        self.set_child_without_hash(epoch, insertion_node)
    }

    ////// getrs for this node ////

    pub fn get_value_at_epoch(&self, epoch: u64) -> Result<&H::Digest, HistoryTreeNodeError> {
        unimplemented!()
    }

    // gets value at current epoch
    pub fn get_value(&self) -> Result<&H::Digest, HistoryTreeNodeError> {
        //&HistoryNodeHash<H> {
        match self.state_map.get(&self.get_latest_epoch().unwrap_or(0)) {
            Some(node_state) => Ok(&node_state.value),
            None => Err(HistoryTreeNodeError::NodeCreatedWithoutEpochs(
                self.label.get_val(),
            )),
        }
    }

    pub fn get_birth_epoch(&self) -> u64 {
        self.epochs[0]
    }

    pub fn get_label(&self) -> NodeLabel {
        self.label
    }

    pub fn get_location(&self) -> usize {
        self.location
    }

    // gets the direction of node, i.e. if it's a left
    // child or right. If not found, return None
    pub fn get_direction_at_ep(&self, node: &HistoryTreeNode<H>, ep: u64) -> Direction {
        let mut outcome: Direction = None;
        let latest_state = self.state_map.get(&ep).unwrap();
        for node_index in 0..ARITY {
            let node_val = latest_state.get_child_state_in_dir(node_index);
            let node_label = node_val.label;
            if node_label == node.get_label() {
                outcome = Some(node_index)
            }
        }
        outcome
    }

    pub fn is_root(&self) -> bool {
        matches!(self.node_type, NodeType::Root)
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self.node_type, NodeType::Leaf)
    }

    pub fn is_interior(&self) -> bool {
        matches!(self.node_type, NodeType::Interior)
    }

    ///// getrs for child nodes ////

    pub fn get_child_at_existing_epoch(
        &self,
        epoch: u64,
        direction: Direction,
    ) -> Result<HistoryChildState<H>, HistoryTreeNodeError> {
        match direction {
            Direction::None => Err(HistoryTreeNodeError::DirectionIsNone),
            Direction::Some(dir) => {
                let state_map_val = self.state_map.get(&epoch);
                match state_map_val {
                    Some(curr) => Ok(curr.get_child_state_in_dir(dir)),
                    None => Err(HistoryTreeNodeError::NoChildInTreeAtEpoch(epoch, dir)),
                }
            }
        }
    }

    pub fn get_child_at_epoch(
        &self,
        epoch: u64,
        direction: Direction,
    ) -> Result<HistoryChildState<H>, HistoryTreeNodeError> {
        let dir: usize;
        match direction {
            Direction::None => Err(HistoryTreeNodeError::DirectionIsNone),
            Direction::Some(dir_val) => {
                let dir = dir_val;

                if self.get_birth_epoch() > epoch {
                    Err(HistoryTreeNodeError::NoChildInTreeAtEpoch(epoch, dir))
                } else {
                    let mut curr_ep = self.get_birth_epoch();
                    let mut i = 0;
                    while curr_ep <= epoch && i < self.epochs.len() - 1 {
                        i += 1;
                        curr_ep = self.epochs[i];
                    }
                    if (i == 0) {
                        self.get_child_at_existing_epoch(self.epochs[i], direction)
                    } else {
                        self.get_child_at_existing_epoch(self.epochs[i - 1], direction)
                    }
                }
            }
        }
    }

    /// if this node existed at epoch, return label of
    /// appropriate child. Else, return the latest label of
    /// that child.
    pub fn get_child_label(
        &self,
        epoch: u64,
        direction: Direction,
    ) -> Result<NodeLabel, HistoryTreeNodeError> {
        let _child = self.get_child_at_epoch(epoch, direction);
        match _child {
            Ok(child_state) => Ok(child_state.label),
            Err(e) => Err(e),
        }
    }

    /// if this node existed at epoch, return time of
    /// appropriate child. Else, return the latest time of
    /// that child.
    pub fn get_child_epoch_version(
        &self,
        epoch: u64,
        direction: Direction,
    ) -> Result<u64, HistoryTreeNodeError> {
        let _child = self.get_child_at_epoch(epoch, direction);
        match _child {
            Ok(child_state) => Ok(child_state.epoch_version),
            Err(e) => Err(e),
        }
    }

    /// if this node existed at epoch, return hash of
    /// appropriate child. Else, return the latest hash of
    /// that child.
    pub fn get_child_hash(
        &self,
        epoch: u64,
        direction: Direction,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        let _child = self.get_child_at_epoch(epoch, direction);
        match _child {
            Ok(child_state) => Ok(child_state.hash_val),
            Err(e) => Err(e),
        }
    }

    /* Functions for compression-related operations */

    pub fn get_latest_epoch(&self) -> Result<u64, HistoryTreeNodeError> {
        match self.epochs.len() {
            0 => Err(HistoryTreeNodeError::NodeCreatedWithoutEpochs(
                self.label.get_val(),
            )),
            n => Ok(self.epochs[n - 1]),
        }
    }

    /////// Helpers /////////

    pub fn to_node_unhashed_child_state(
        &self,
    ) -> Result<HistoryChildState<H>, HistoryTreeNodeError> {
        let epoch_val = self.get_latest_epoch()?;
        Ok(HistoryChildState {
            dummy_marker: DummyChildState::Real,
            location: self.location,
            label: self.label,
            hash_val: *self.get_value()?,
            epoch_version: epoch_val,
        })
    }

    pub fn to_node_child_state(&self) -> Result<HistoryChildState<H>, HistoryTreeNodeError> {
        let epoch_val = self.get_latest_epoch()?;
        Ok(HistoryChildState {
            dummy_marker: DummyChildState::Real,
            location: self.location,
            label: self.label,
            hash_val: *self.get_value()?,
            epoch_version: epoch_val,
        })
    }
}

/////// Helpers //////

pub fn get_empty_root<H: Hasher>(ep: Option<u64>) -> HistoryTreeNode<H> {
    let label = NodeLabel::new(0u64, 0u32);
    let loc = 0;
    let parent = 0;
    let mut node: HistoryTreeNode<H> = HistoryTreeNode::new(label, loc, parent, NodeType::Root);
    if let Some(epoch) = ep {
        node.epochs.push(epoch);
    }
    node
}

pub fn get_leaf_node<H: Hasher>(
    label: NodeLabel,
    location: usize,
    value: &[u8],
    parent: usize,
    birth_epoch: u64,
) -> HistoryTreeNode<H> {
    HistoryTreeNode {
        label,
        location,
        epochs: vec![birth_epoch],
        state_map: get_state_map_for_leaf::<H>(H::hash(value), birth_epoch),
        parent,
        node_type: NodeType::Leaf,
    }
}

pub fn get_interior_node<H: Hasher>(
    label: NodeLabel,
    location: usize,
    value: H::Digest,
    parent: usize,
    birth_epoch: u64,
    child_states: [HistoryChildState<H>; 2],
) -> HistoryTreeNode<H> {
    HistoryTreeNode {
        label,
        location,
        epochs: vec![birth_epoch],
        state_map: get_state_map_for_interior::<H>(birth_epoch, value, child_states),
        parent,
        node_type: NodeType::Interior,
    }
}

fn get_state_map_for_leaf<H: Hasher>(
    value: H::Digest,
    epoch: u64,
) -> HashMap<u64, HistoryNodeState<H>> {
    let mut state_map: HashMap<u64, HistoryNodeState<H>> = HashMap::new();
    let mut new_state = HistoryNodeState::new();
    new_state.value = value;
    state_map.insert(epoch, new_state);
    state_map
}

fn get_state_map_for_interior<H: Hasher>(
    epoch: u64,
    value: H::Digest,
    child_states: [HistoryChildState<H>; 2],
) -> HashMap<u64, HistoryNodeState<H>> {
    let mut state_map: HashMap<u64, HistoryNodeState<H>> = HashMap::new();
    let mut new_state = HistoryNodeState {
        value,
        child_states,
    };
    state_map.insert(epoch, new_state);
    state_map
}
