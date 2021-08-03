// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::collections::HashMap;

use crate::errors::StorageError;
use crate::storage::{get_state_map, set_state_map, Storage};
use crate::{node_state::*, Direction, ARITY};
use crypto::Hasher;

use crate::errors::HistoryTreeNodeError;

use std::marker::PhantomData;

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
pub struct HistoryTreeNode<H: Hasher, S: Storage<HistoryNodeState<H>>> {
    pub label: NodeLabel,
    pub location: usize,
    pub epochs: Vec<u64>,
    pub parent: usize,
    // Just use usize and have the 0th position be empty and that can be the parent of root. This makes things simpler.
    pub node_type: NodeType,
    #[cfg(test)]
    pub(crate) state_map: HashMap<u64, HistoryNodeState<H>>,
    // Note that the NodeType along with the parent/children being options
    // allows us to use this struct to represent child and parent nodes as well.
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}

impl<H: Hasher, S: Storage<HistoryNodeState<H>>> Clone for HistoryTreeNode<H, S> {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            location: self.location,
            epochs: self.epochs.clone(),
            parent: self.parent,
            node_type: self.node_type,
            #[cfg(test)]
            state_map: self.state_map.clone(),
            _s: PhantomData,
            _h: PhantomData,
        }
    }
}

impl<H: Hasher, S: Storage<HistoryNodeState<H>>> HistoryTreeNode<H, S> {
    pub fn new(label: NodeLabel, location: usize, parent: usize, node_type: NodeType) -> Self {
        let ep: Vec<u64> = Vec::new();
        HistoryTreeNode {
            label,
            location,
            epochs: ep,
            parent, // Root node is its own parent
            node_type,
            #[cfg(test)]
            state_map: HashMap::new(),
            _s: PhantomData,
            _h: PhantomData,
        }
    }

    // Inserts a single leaf node and updates the required hashes
    pub fn insert_single_leaf(
        &mut self,
        mut new_leaf: Self,
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
                tree_repr[new_node.location] = tree_repr[new_node.location]
                    .set_node_child_without_hash(epoch, dir_leaf, new_leaf.clone())?;
                tree_repr[new_node.location] = tree_repr[new_node.location]
                    .set_node_child_without_hash(epoch, dir_self, self.clone())?;
                new_node = tree_repr[new_node.location].clone();
                tree_repr[self.parent] = tree_repr[self.parent].set_node_child_without_hash(
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
                new_node = tree_repr[new_node.location].clone();
                tree_repr = new_node.update_hash(epoch, tree_repr)?;
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
                                    tree_repr[self.location] = self.set_node_child_without_hash(
                                        epoch,
                                        dir_leaf,
                                        new_leaf.clone(),
                                    )?;
                                    // tree_repr[self.location] = self.clone();
                                    let mut new_leaf = tree_repr[new_leaf.location].clone();
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
                                updated_child = tree_repr[updated_child.location].clone();
                                tree_repr = updated_child.update_hash(epoch, tree_repr)?;
                                if self.is_root() {
                                    let mut new_self = tree_repr[self.location].clone();
                                    tree_repr = new_self.update_hash(epoch, tree_repr)?;
                                }
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
        mut new_leaf: Self,
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
                    Ok(child_st) => match child_st.dummy_marker {
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
                            let (mut updated_child, mut tree_repr) = child_node
                                .insert_single_leaf_without_hash(new_leaf, epoch, tree_repr)?;
                            self.set_node_child_without_hash(epoch, dir_leaf, updated_child)?;
                            tree_repr[self.location] = self.clone();
                            let loc_and_behold = tree_repr[self.location]
                                .get_child_at_existing_epoch(epoch, dir_leaf)
                                .unwrap();

                            Ok((tree_repr[self.location].clone(), tree_repr))
                        }
                    },
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
                let leaf_hash_val = H::merge(&[self.get_value()?, hash_label::<H>(self.label)]);
                self.update_hash_at_parent(epoch, leaf_hash_val, tree_repr)
            }
            _ => {
                // the root has no parent, so the hash must only be stored within the value
                let mut hash_digest = self.hash_node(epoch)?;
                if self.is_root() {
                    hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
                }
                let epoch_state = self.get_state_at_epoch(epoch).unwrap();

                let mut updated_state = epoch_state;
                updated_state.value = hash_digest;
                set_state_map(self, &epoch, updated_state);
              
                let mut updated_tree = tree_repr;
                updated_tree[self.location] = self.clone();
                let hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
                self.update_hash_at_parent(epoch, hash_digest, updated_tree)
            }
        }
    }

    pub fn hash_node(&self, epoch: u64) -> Result<H::Digest, HistoryTreeNodeError> {
        let epoch_node_state = self.get_state_at_epoch(epoch).unwrap();
        let mut new_hash = H::hash(&[]); //hash_label::<H>(self.label);
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

    pub fn hash_node_and_children(
        &mut self,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        match get_state_map(self, &epoch) {
            Err(_) => Err(HistoryTreeNodeError::NoChildrenInTreeAtEpoch(epoch)),
            Ok(mut epoch_node_state) => {
                let mut new_hash = H::hash(&[]); //hash_label::<H>(self.label);
                for child_index in 0..ARITY {
                    new_hash = H::merge(&[
                        new_hash,
                        epoch_node_state
                            .get_child_state_in_dir(child_index)
                            .hash_val,
                    ]);
                }
                new_hash = H::merge(&[new_hash, hash_label::<H>(self.label)]);
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
            // let mut new_state = self.state_map.get(&epoch).unwrap().clone();
            // new_state.value = new_hash_val;
            // self.state_map.insert(epoch, new_state);
            // tree_repr_copy[self.location] = self.clone();
            Ok(tree_repr_copy)
        } else {
            let mut parent = tree_repr_copy[self.parent].clone();
            match get_state_map(&parent, &epoch) {
                Err(_) => Err(HistoryTreeNodeError::ParentNextEpochInvalid(epoch)),
                Ok(parent_state) => match parent.get_direction_at_ep(self, epoch) {
                    None => Err(HistoryTreeNodeError::HashUpdateOnlyAllowedAfterNodeInsertion),
                    Some(s_dir) => {
                        let mut parent_updated_state = parent_state;
                        let mut self_child_state =
                            parent_updated_state.get_child_state_in_dir(s_dir);
                        self_child_state.hash_val = new_hash_val;
                        parent_updated_state.child_states[s_dir] = self_child_state;
                        set_state_map(&mut parent, &epoch, parent_updated_state);
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
            Direction::Some(dir) => match get_state_map(self, &epoch) {
                Ok(HistoryNodeState {
                    value,
                    mut child_states,
                }) => {
                    child_states[dir] = child_node;
                    set_state_map(
                        self,
                        &epoch,
                        HistoryNodeState {
                            value,
                            child_states,
                        },
                    );
                    Ok(self.clone())
                }
                Err(_) => {
                    set_state_map(
                        self,
                        &epoch,
                        match get_state_map(self, &self.get_latest_epoch().unwrap_or(0)) {
                            Ok(latest_st) => latest_st,

                            Err(_) => HistoryNodeState::<H>::new(),
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

    pub fn get_value_at_epoch(&self, epoch: u64) -> Result<H::Digest, HistoryTreeNodeError> {
        Ok(self.get_state_at_epoch(epoch).unwrap().value)
    }

    pub fn get_value_without_label_at_epoch(
        &self,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        if self.is_leaf() {
            return Ok(self.get_value_at_epoch(epoch).unwrap());
        }
        let children = self.get_state_at_epoch(epoch).unwrap().child_states;
        let mut new_hash = H::hash(&[]);
        for child in children.iter().take(ARITY) {
            new_hash = H::merge(&[new_hash, child.hash_val]);
        }
        Ok(new_hash)
    }

    pub fn get_child_location_at_epoch(&self, epoch: u64, dir: Direction) -> usize {
        self.get_child_at_epoch(epoch, dir).unwrap().location
    }

    // gets value at current epoch
    pub fn get_value(&self) -> Result<H::Digest, HistoryTreeNodeError> {
        //&HistoryNodeHash<H> {

        match get_state_map(self, &self.get_latest_epoch().unwrap()) {
            Ok(node_state) => Ok(node_state.value),
            Err(_) => Err(HistoryTreeNodeError::NodeCreatedWithoutEpochs(
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
    pub fn get_direction_at_ep(&self, node: &Self, ep: u64) -> Direction {
        let mut outcome: Direction = None;
        let state_at_ep = self.get_state_at_epoch(ep).unwrap();
        for node_index in 0..ARITY {
            let node_val = state_at_ep.get_child_state_in_dir(node_index);
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
                let state_map_val = get_state_map(self, &epoch);
                match state_map_val {
                    Ok(curr) => Ok(curr.get_child_state_in_dir(dir)),
                    Err(_) => Err(HistoryTreeNodeError::NoChildInTreeAtEpoch(epoch, dir)),
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
                    let mut chosen_ep = self.get_birth_epoch();
                    for existing_ep in &self.epochs {
                        if *existing_ep <= epoch {
                            chosen_ep = *existing_ep;
                        }
                    }
                    self.get_child_at_existing_epoch(chosen_ep, direction)
                    // let mut curr_ep = self.get_birth_epoch();
                    // let mut i = 0;
                    // while curr_ep <= epoch && i < self.epochs.len() - 1 {
                    //     i += 1;
                    //     curr_ep = self.epochs[i];
                    // }
                    // if (i == 0) {
                    //     self.get_child_at_existing_epoch(self.epochs[i], direction)
                    // } else {
                    //     self.get_child_at_existing_epoch(self.epochs[i - 1], direction)
                    // }
                }
            }
        }
    }

    pub fn get_state_at_existing_epoch(
        &self,
        epoch: u64,
    ) -> Result<HistoryNodeState<H>, HistoryTreeNodeError> {
        get_state_map(self, &epoch)
            .map_err(|_| HistoryTreeNodeError::NodeDidNotHaveExistingStateAtEp(self.label, epoch))
    }

    pub fn get_state_at_epoch(
        &self,
        epoch: u64,
    ) -> Result<HistoryNodeState<H>, HistoryTreeNodeError> {
        if self.get_birth_epoch() > epoch {
            Err(HistoryTreeNodeError::NodeDidNotExistAtEp(self.label, epoch))
        } else {
            let mut chosen_ep = self.get_birth_epoch();
            for existing_ep in &self.epochs {
                if *existing_ep <= epoch {
                    chosen_ep = *existing_ep;
                }
            }
            self.get_state_at_existing_epoch(chosen_ep)
            // let mut curr_ep = self.get_birth_epoch();
            // let mut i = 0;
            // while curr_ep <= epoch && i < self.epochs.len() - 1 {
            //     i += 1;
            //     curr_ep = self.epochs[i];
            // }
            // if (i == 0) {
            //     self.get_state_at_existing_epoch(self.epochs[i])
            // } else {
            //     self.get_state_at_existing_epoch(self.epochs[i - 1])
            // }
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
            hash_val: H::merge(&[self.get_value()?, hash_label::<H>(self.label)]),
            epoch_version: epoch_val,
        })
    }

    pub fn to_node_child_state(&self) -> Result<HistoryChildState<H>, HistoryTreeNodeError> {
        let epoch_val = self.get_latest_epoch()?;
        Ok(HistoryChildState {
            dummy_marker: DummyChildState::Real,
            location: self.location,
            label: self.label,
            hash_val: H::merge(&[self.get_value()?, hash_label::<H>(self.label)]),
            epoch_version: epoch_val,
        })
    }
}

/////// Helpers //////

pub fn get_empty_root<H: Hasher, S: Storage<HistoryNodeState<H>>>(
    ep: Option<u64>,
) -> HistoryTreeNode<H, S> {
    let label = NodeLabel::new(0u64, 0u32);
    let loc = 0;
    let parent = 0;
    let mut node: HistoryTreeNode<H, S> = HistoryTreeNode::new(label, loc, parent, NodeType::Root);
    if let Some(epoch) = ep {
        node.epochs.push(epoch);
    }
    node
}

pub fn get_leaf_node<H: Hasher, S: Storage<HistoryNodeState<H>>>(
    label: NodeLabel,
    location: usize,
    value: &[u8],
    parent: usize,
    birth_epoch: u64,
) -> HistoryTreeNode<H, S> {
    let mut node = HistoryTreeNode {
        label,
        location,
        epochs: vec![birth_epoch],
        parent,
        node_type: NodeType::Leaf,
        #[cfg(test)]
        state_map: HashMap::new(),
        _s: PhantomData,
        _h: PhantomData,
    };

    let mut new_state = HistoryNodeState::new();
    new_state.value = H::merge(&[H::hash(&[]), H::hash(value)]);

    set_state_map(&mut node, &birth_epoch, new_state);

    node
}

pub fn get_leaf_node_without_empty<H: Hasher, S: Storage<HistoryNodeState<H>>>(
    label: NodeLabel,
    location: usize,
    value: &[u8],
    parent: usize,
    birth_epoch: u64,
) -> HistoryTreeNode<H, S> {
    let mut node = HistoryTreeNode {
        label,
        location,
        epochs: vec![birth_epoch],
        parent,
        node_type: NodeType::Leaf,
        #[cfg(test)]
        state_map: HashMap::new(),
        _s: PhantomData,
        _h: PhantomData,
    };

    let mut new_state = HistoryNodeState::new();
    new_state.value = H::hash(value);

    set_state_map(&mut node, &birth_epoch, new_state);

    node
}

pub fn get_leaf_node_without_hashing<H: Hasher, S: Storage<HistoryNodeState<H>>>(
    label: NodeLabel,
    location: usize,
    value: H::Digest,
    parent: usize,
    birth_epoch: u64,
) -> HistoryTreeNode<H, S> {
    let mut node = HistoryTreeNode {
        label,
        location,
        epochs: vec![birth_epoch],
        parent,
        node_type: NodeType::Leaf,
        #[cfg(test)]
        state_map: HashMap::new(),
        _s: PhantomData,
        _h: PhantomData,
    };

    let mut new_state = HistoryNodeState::new();
    new_state.value = value;

    set_state_map(&mut node, &birth_epoch, new_state);

    node
}

pub fn get_interior_node<H: Hasher, S: Storage<HistoryNodeState<H>>>(
    label: NodeLabel,
    location: usize,
    value: H::Digest,
    parent: usize,
    birth_epoch: u64,
    child_states: [HistoryChildState<H>; 2],
) -> HistoryTreeNode<H, S> {
    let mut node = HistoryTreeNode {
        label,
        location,
        epochs: vec![birth_epoch],
        parent,
        node_type: NodeType::Interior,
        #[cfg(test)]
        state_map: HashMap::new(),
        _s: PhantomData,
        _h: PhantomData,
    };

    let new_state = HistoryNodeState {
        value,
        child_states,
    };

    set_state_map(&mut node, &birth_epoch, new_state);

    node
}
