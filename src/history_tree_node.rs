// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::serialization::{from_digest, to_digest};
use crate::storage::{Storable, Storage};
use crate::{node_state::*, Direction, ARITY};
use winter_crypto::Hasher;

use crate::errors::{HistoryTreeNodeError, StorageError};

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Leaf,
    Root,
    Interior,
}

pub type HistoryInsertionNode<H, S> = (Direction, HistoryChildState<H, S>);
pub type HistoryNodeHash<H> = Option<H>;

/**
 * HistoryNode will represent a generic interior node of a compressed history tree
 **/
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HistoryTreeNode<H, S> {
    pub(crate) azks_id: Vec<u8>,
    pub label: NodeLabel,
    pub location: usize,
    pub epochs: Vec<u64>,
    pub parent: usize,
    // Just use usize and have the 0th position be empty and that can be the parent of root. This makes things simpler.
    pub node_type: NodeType,
    // Note that the NodeType along with the parent/children being options
    // allows us to use this struct to represent child and parent nodes as well.
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}

// parameters are azks_id and location
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeKey(pub(crate) Vec<u8>, pub(crate) usize);

impl<H: Hasher, S: Storage> Storable<S> for HistoryTreeNode<H, S> {
    type Key = NodeKey;

    fn identifier() -> String {
        String::from("HistoryTreeNode")
    }
}

impl<H: Hasher, S: Storage> Clone for HistoryTreeNode<H, S> {
    fn clone(&self) -> Self {
        Self {
            azks_id: self.azks_id.clone(),
            label: self.label,
            location: self.location,
            epochs: self.epochs.clone(),
            parent: self.parent,
            node_type: self.node_type,
            _s: PhantomData,
            _h: PhantomData,
        }
    }
}

impl<H: Hasher, S: Storage> HistoryTreeNode<H, S> {
    fn new(
        azks_id: Vec<u8>,
        label: NodeLabel,
        location: usize,
        parent: usize,
        node_type: NodeType,
    ) -> Self {
        HistoryTreeNode {
            azks_id,
            label,
            location,
            epochs: vec![],
            parent, // Root node is its own parent
            node_type,
            _s: PhantomData,
            _h: PhantomData,
        }
    }

    pub(crate) fn write_to_storage(&self) -> Result<(), StorageError> {
        Self::store(NodeKey(self.azks_id.clone(), self.location), self)
    }

    // Inserts a single leaf node and updates the required hashes
    pub fn insert_single_leaf(
        &mut self,
        new_leaf: Self,
        azks_id: &[u8],
        epoch: u64,
        num_nodes: &mut usize,
    ) -> Result<(), HistoryTreeNodeError> {
        self.insert_single_leaf_helper(new_leaf, azks_id, epoch, num_nodes, true)
    }

    // Inserts a single leaf node
    pub fn insert_single_leaf_without_hash(
        &mut self,
        new_leaf: Self,
        azks_id: &[u8],
        epoch: u64,
        num_nodes: &mut usize,
    ) -> Result<(), HistoryTreeNodeError> {
        self.insert_single_leaf_helper(new_leaf, azks_id, epoch, num_nodes, false)
    }

    // Inserts a single leaf node and updates the required hashes,
    // if hashing is true
    pub fn insert_single_leaf_helper(
        &mut self,
        mut new_leaf: Self,
        azks_id: &[u8],
        epoch: u64,
        num_nodes: &mut usize,
        hashing: bool,
    ) -> Result<(), HistoryTreeNodeError> {
        let (lcs_label, dir_leaf, dir_self) = self
            .label
            .get_longest_common_prefix_and_dirs(new_leaf.get_label());

        if self.is_root() {
            new_leaf.location = *num_nodes;
            new_leaf.write_to_storage()?;
            *num_nodes += 1;
            // the root should always be instantiated with dummy children in the beginning
            let child_state = self.get_child_at_epoch(self.get_latest_epoch()?, dir_leaf)?;
            if child_state.dummy_marker == DummyChildState::Dummy {
                new_leaf.parent = self.location;
                self.set_node_child_without_hash(epoch, dir_leaf, &new_leaf)?;
                self.write_to_storage()?;
                new_leaf.write_to_storage()?;

                if hashing {
                    new_leaf.update_hash(epoch)?;
                    let mut new_self =
                        Self::retrieve(NodeKey(self.azks_id.clone(), self.location))?;
                    new_self.update_hash(epoch)?;
                }

                *self = Self::retrieve(NodeKey(self.azks_id.clone(), self.location))?;
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
                let mut parent = Self::retrieve(NodeKey(self.azks_id.clone(), self.parent))?;
                let self_dir_in_parent = parent.get_direction_at_ep(self, epoch)?;
                let new_node_location = *num_nodes;
                let mut new_node = HistoryTreeNode::new(
                    azks_id.to_vec(),
                    lcs_label,
                    new_node_location,
                    parent.location,
                    NodeType::Interior,
                );
                new_node.epochs.push(epoch);
                new_node.write_to_storage()?;
                *num_nodes += 1;
                // Add this node in the correct dir and child node in the other direction
                new_leaf.parent = new_node.location;
                new_leaf.write_to_storage()?;

                self.parent = new_node.location;
                self.write_to_storage()?;

                new_node.set_node_child_without_hash(epoch, dir_leaf, &new_leaf)?;
                new_node.set_node_child_without_hash(epoch, dir_self, self)?;

                parent.set_node_child_without_hash(epoch, self_dir_in_parent, &new_node)?;
                if hashing {
                    new_leaf.update_hash(epoch)?;
                    self.update_hash(epoch)?;
                    new_node = Self::retrieve(NodeKey(self.azks_id.clone(), new_node.location))?;
                    new_node.update_hash(epoch)?;
                }
                new_node.write_to_storage()?;
                parent.write_to_storage()?;
                *self = Self::retrieve(NodeKey(self.azks_id.clone(), self.location))?;
                Ok(())
            }
            None => {
                // case where the current node is equal to the lcs
                let child_st = self.get_child_at_epoch(self.get_latest_epoch()?, dir_leaf)?;

                match child_st.dummy_marker {
                    DummyChildState::Dummy => {
                        Err(HistoryTreeNodeError::CompressionError(self.label))
                    }
                    DummyChildState::Real => {
                        let mut child_node =
                            Self::retrieve(NodeKey(self.azks_id.clone(), child_st.location))?;
                        child_node.insert_single_leaf_helper(
                            new_leaf, azks_id, epoch, num_nodes, hashing,
                        )?;
                        if hashing {
                            *self = Self::retrieve(NodeKey(self.azks_id.clone(), self.location))?;
                            self.update_hash(epoch)?;
                            self.write_to_storage()?;
                        }
                        *self = Self::retrieve(NodeKey(self.azks_id.clone(), self.location))?;
                        Ok(())
                    }
                }
            }
        }
    }

    /// Updates the hash of this node as stored in its parent,
    /// provided the children of this node have already updated their own versions
    /// in this node and epoch is contained in the state_map
    /// Also assumes that `set_child_without_hash` has already been called
    pub(crate) fn update_hash(&mut self, epoch: u64) -> Result<(), HistoryTreeNodeError> {
        match self.node_type {
            NodeType::Leaf => {
                // the hash of this is just the value, simply place in parent
                let leaf_hash_val = H::merge(&[self.get_value()?, hash_label::<H>(self.label)]);
                self.update_hash_at_parent(epoch, leaf_hash_val)
            }
            _ => {
                // the root has no parent, so the hash must only be stored within the value
                let mut hash_digest = self.hash_node(epoch)?;
                if self.is_root() {
                    hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
                }
                let epoch_state = self.get_state_at_epoch(epoch)?;

                let mut updated_state = epoch_state;
                updated_state.value = from_digest::<H>(hash_digest)?;
                set_state_map(self, &epoch, updated_state)?;

                self.write_to_storage()?;
                let hash_digest = H::merge(&[hash_digest, hash_label::<H>(self.label)]);
                self.update_hash_at_parent(epoch, hash_digest)
            }
        }
    }

    fn hash_node(&self, epoch: u64) -> Result<H::Digest, HistoryTreeNodeError> {
        let epoch_node_state = self.get_state_at_epoch(epoch)?;
        let mut new_hash = H::hash(&[]);
        for child_index in 0..ARITY {
            new_hash = H::merge(&[
                new_hash,
                to_digest::<H>(
                    &epoch_node_state
                        .get_child_state_in_dir(child_index)
                        .hash_val,
                )
                .unwrap(),
            ]);
        }
        Ok(new_hash)
    }

    fn update_hash_at_parent(
        &mut self,
        epoch: u64,
        new_hash_val: H::Digest,
    ) -> Result<(), HistoryTreeNodeError> {
        if self.is_root() {
            Ok(())
        } else {
            let parent = &mut Self::retrieve(NodeKey(self.azks_id.clone(), self.parent))?;
            if parent.get_latest_epoch()? < epoch {
                let (_, dir_self, _) = parent
                    .label
                    .get_longest_common_prefix_and_dirs(self.get_label());
                parent.set_node_child_without_hash(epoch, dir_self, self)?;
                parent.write_to_storage()?;
                *parent = Self::retrieve(NodeKey(self.azks_id.clone(), self.parent))?;
            }
            match get_state_map(parent, &epoch) {
                Err(_) => Err(HistoryTreeNodeError::ParentNextEpochInvalid(epoch)),
                Ok(parent_state) => match parent.get_direction_at_ep(self, epoch)? {
                    None => Err(HistoryTreeNodeError::HashUpdateOnlyAllowedAfterNodeInsertion),
                    Some(s_dir) => {
                        let mut parent_updated_state = parent_state;
                        let mut self_child_state =
                            parent_updated_state.get_child_state_in_dir(s_dir);
                        self_child_state.hash_val = from_digest::<H>(new_hash_val)?;
                        parent_updated_state.child_states[s_dir] = self_child_state;
                        set_state_map(parent, &epoch, parent_updated_state)?;
                        parent.write_to_storage()?;

                        Ok(())
                    }
                },
            }
        }
    }

    pub(crate) fn set_child_without_hash(
        &mut self,
        epoch: u64,
        child: &HistoryInsertionNode<H, S>,
    ) -> Result<(), HistoryTreeNodeError> {
        let (direction, child_node) = child.clone();
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
                    )?;
                    Ok(())
                }
                Err(_) => {
                    set_state_map(
                        self,
                        &epoch,
                        match self.get_state_at_epoch(self.get_latest_epoch()?) {
                            Ok(latest_st) => latest_st,
                            Err(_) => HistoryNodeState::<H, S>::new(),
                        },
                    )?;

                    match self.get_latest_epoch() {
                        Ok(latest) => {
                            if latest != epoch {
                                self.epochs.push(epoch);
                            }
                        }
                        Err(_) => {
                            self.epochs.push(epoch);
                        }
                    }
                    self.write_to_storage()?;
                    self.set_child_without_hash(epoch, child)
                }
            },
            Direction::None => Err(HistoryTreeNodeError::NoDirectionInSettingChild(
                self.get_label().get_val(),
                child_node.label.get_val(),
            )),
        }
    }

    pub(crate) fn set_node_child_without_hash(
        &mut self,
        epoch: u64,
        dir: Direction,
        child: &Self,
    ) -> Result<(), HistoryTreeNodeError> {
        let node_as_child_state = child.to_node_unhashed_child_state()?;
        let insertion_node = (dir, node_as_child_state);
        self.set_child_without_hash(epoch, &insertion_node)
    }

    ////// getrs for this node ////

    pub(crate) fn get_value_at_epoch(&self, epoch: u64) -> Result<H::Digest, HistoryTreeNodeError> {
        Ok(to_digest::<H>(&self.get_state_at_epoch(epoch)?.value).unwrap())
    }

    pub(crate) fn get_value_without_label_at_epoch(
        &self,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        if self.is_leaf() {
            return self.get_value_at_epoch(epoch);
        }
        let children = self.get_state_at_epoch(epoch)?.child_states;
        let mut new_hash = H::hash(&[]);
        for child in children.iter().take(ARITY) {
            new_hash = H::merge(&[new_hash, to_digest::<H>(&child.hash_val).unwrap()]);
        }
        Ok(new_hash)
    }

    pub(crate) fn get_child_location_at_epoch(
        &self,
        epoch: u64,
        dir: Direction,
    ) -> Result<usize, HistoryTreeNodeError> {
        Ok(self.get_child_at_epoch(epoch, dir)?.location)
    }

    // gets value at current epoch
    pub(crate) fn get_value(&self) -> Result<H::Digest, HistoryTreeNodeError> {
        Ok(get_state_map(self, &self.get_latest_epoch()?)
            .map(|node_state| to_digest::<H>(&node_state.value).unwrap())?)
    }

    pub(crate) fn get_birth_epoch(&self) -> u64 {
        self.epochs[0]
    }

    fn get_label(&self) -> NodeLabel {
        self.label
    }

    // gets the direction of node, i.e. if it's a left
    // child or right. If not found, return None
    fn get_direction_at_ep(&self, node: &Self, ep: u64) -> Result<Direction, HistoryTreeNodeError> {
        let mut outcome: Direction = None;
        let state_at_ep = self.get_state_at_epoch(ep)?;
        for node_index in 0..ARITY {
            let node_val = state_at_ep.get_child_state_in_dir(node_index);
            let node_label = node_val.label;
            if node_label == node.get_label() {
                outcome = Some(node_index)
            }
        }
        Ok(outcome)
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
    ) -> Result<HistoryChildState<H, S>, HistoryTreeNodeError> {
        match direction {
            Direction::None => Err(HistoryTreeNodeError::DirectionIsNone),
            Direction::Some(dir) => {
                Ok(get_state_map(self, &epoch).map(|curr| curr.get_child_state_in_dir(dir))?)
            }
        }
    }

    pub fn get_child_at_epoch(
        &self,
        epoch: u64,
        direction: Direction,
    ) -> Result<HistoryChildState<H, S>, HistoryTreeNodeError> {
        match direction {
            Direction::None => Err(HistoryTreeNodeError::DirectionIsNone),
            Direction::Some(dir) => {
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
                }
            }
        }
    }

    pub fn get_state_at_existing_epoch(
        &self,
        epoch: u64,
    ) -> Result<HistoryNodeState<H, S>, HistoryTreeNodeError> {
        get_state_map(self, &epoch)
            .map_err(|_| HistoryTreeNodeError::NodeDidNotHaveExistingStateAtEp(self.label, epoch))
    }

    pub fn get_state_at_epoch(
        &self,
        epoch: u64,
    ) -> Result<HistoryNodeState<H, S>, HistoryTreeNodeError> {
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
        }
    }

    /* Functions for compression-related operations */

    pub(crate) fn get_latest_epoch(&self) -> Result<u64, HistoryTreeNodeError> {
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
    ) -> Result<HistoryChildState<H, S>, HistoryTreeNodeError> {
        Ok(HistoryChildState {
            dummy_marker: DummyChildState::Real,
            location: self.location,
            label: self.label,
            hash_val: from_digest::<H>(H::merge(&[
                self.get_value()?,
                hash_label::<H>(self.label),
            ]))?,
            epoch_version: self.get_latest_epoch()?,
            _h: PhantomData,
            _s: PhantomData,
        })
    }

    pub fn to_node_child_state(&self) -> Result<HistoryChildState<H, S>, HistoryTreeNodeError> {
        Ok(HistoryChildState {
            dummy_marker: DummyChildState::Real,
            location: self.location,
            label: self.label,
            hash_val: from_digest::<H>(H::merge(&[
                self.get_value()?,
                hash_label::<H>(self.label),
            ]))?,
            epoch_version: self.get_latest_epoch()?,
            _h: PhantomData,
            _s: PhantomData,
        })
    }
}

/////// Helpers //////

pub fn get_empty_root<H: Hasher, S: Storage>(
    azks_id: &[u8],
    ep: Option<u64>,
) -> Result<HistoryTreeNode<H, S>, HistoryTreeNodeError> {
    let mut node = HistoryTreeNode::new(
        azks_id.to_vec(),
        NodeLabel::new(0u64, 0u32),
        0,
        0,
        NodeType::Root,
    );
    if let Some(epoch) = ep {
        node.epochs.push(epoch);
        let new_state = HistoryNodeState::new();
        set_state_map(&mut node, &epoch, new_state)?;
    }

    Ok(node)
}

pub fn get_leaf_node<H: Hasher, S: Storage>(
    azks_id: &[u8],
    label: NodeLabel,
    location: usize,
    value: &[u8],
    parent: usize,
    birth_epoch: u64,
) -> Result<HistoryTreeNode<H, S>, HistoryTreeNodeError> {
    let mut node = HistoryTreeNode {
        azks_id: azks_id.to_vec(),
        label,
        location,
        epochs: vec![birth_epoch],
        parent,
        node_type: NodeType::Leaf,
        _s: PhantomData,
        _h: PhantomData,
    };

    let mut new_state = HistoryNodeState::new();
    new_state.value = from_digest::<H>(H::merge(&[H::hash(&[]), H::hash(value)]))?;

    set_state_map(&mut node, &birth_epoch, new_state)?;

    Ok(node)
}

pub fn get_leaf_node_without_hashing<H: Hasher, S: Storage>(
    azks_id: &[u8],
    label: NodeLabel,
    location: usize,
    value: H::Digest,
    parent: usize,
    birth_epoch: u64,
) -> Result<HistoryTreeNode<H, S>, HistoryTreeNodeError> {
    let mut node = HistoryTreeNode {
        azks_id: azks_id.to_vec(),
        label,
        location,
        epochs: vec![birth_epoch],
        parent,
        node_type: NodeType::Leaf,
        // state_map: HashMap::new(),
        _s: PhantomData,
        _h: PhantomData,
    };

    let mut new_state = HistoryNodeState::new();
    new_state.value = from_digest::<H>(value).unwrap();

    set_state_map(&mut node, &birth_epoch, new_state)?;

    Ok(node)
}

pub(crate) fn set_state_map<H: Hasher, S: Storage>(
    node: &mut HistoryTreeNode<H, S>,
    key: &u64,
    val: HistoryNodeState<H, S>,
) -> Result<(), StorageError> {
    HistoryNodeState::store(
        NodeStateKey(node.azks_id.clone(), node.label, *key as usize),
        &val,
    )?;
    Ok(())
}

pub(crate) fn get_state_map<H: Hasher, S: Storage>(
    node: &HistoryTreeNode<H, S>,
    key: &u64,
) -> Result<HistoryNodeState<H, S>, StorageError> {
    HistoryNodeState::<H, S>::retrieve(NodeStateKey(
        node.azks_id.clone(),
        node.label,
        *key as usize,
    ))
}
