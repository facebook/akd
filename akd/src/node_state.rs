// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The representation for the label of a history tree node.

use crate::errors::HistoryTreeNodeError;
use crate::serialization::{digest_deserialize, digest_serialize, from_digest};
use crate::storage::types::StorageType;
use crate::storage::Storable;
use crate::{Direction, ARITY};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    fmt::{self, Debug},
};
use winter_crypto::Hasher;

/// Represents a node's label & associated hash
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Node<H: Hasher> {
    /// the label associated with the accompanying hash
    pub label: NodeLabel,
    /// the hash associated to this label
    #[serde(serialize_with = "digest_serialize")]
    #[serde(deserialize_with = "digest_deserialize")]
    pub hash: H::Digest,
}

// can't use #derive because it doesn't bind correctly
// #derive and generics are not friendly; might make Debug weird too ...
// see also:
// https://users.rust-lang.org/t/why-does-deriving-clone-not-work-in-this-case-but-implementing-manually-does/29075
// https://github.com/rust-lang/rust/issues/26925
impl<H: Hasher> Copy for Node<H> {}

impl<H: Hasher> Clone for Node<H> {
    fn clone(&self) -> Node<H> {
        *self
    }
}

/// The NodeLabel struct represents the label for a HistoryTreeNode.
/// Since the label itself may have any number of zeros pre-pended,
/// just using a native type, unless it is a bit-vector, wouldn't work.
/// Hence, we need a custom representation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeLabel {
    /// val stores a binary string as a u64
    pub val: u64,
    /// len keeps track of how long the binary string is
    pub len: u32,
}

impl PartialOrd for NodeLabel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeLabel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        //`label_len`, `label_val`
        let len_cmp = self.len.cmp(&other.len);
        if let std::cmp::Ordering::Equal = len_cmp {
            self.val.cmp(&other.val)
        } else {
            len_cmp
        }
    }
}

impl NodeLabel {
    /// Creates a new NodeLabel representing the root.
    pub const fn root() -> Self {
        Self::new(0, 0)
    }

    /// Creates a new NodeLabel with the given value and len.
    pub const fn new(val: u64, len: u32) -> Self {
        NodeLabel { val, len }
    }

    /// Gets the length of a NodeLabel.
    pub fn get_len(&self) -> u32 {
        self.len
    }

    /// Gets the value of a NodeLabel.
    pub fn get_val(&self) -> u64 {
        self.val
    }

    /// Generate a random NodeLabel for testing purposes
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // FIXME: should we always select length-64 labels?
        Self {
            val: rng.next_u64(),
            len: 64,
        }
    }

    /// Returns the bit at a specified index, and a 0 on an out of range index
    fn get_bit_at(&self, index: u32) -> u64 {
        if index >= self.len {
            return 0;
        }
        (self.val >> (self.len - index - 1)) & 1
    }

    /// Returns the prefix of a specified length, and the entire value on an out of range length
    pub(crate) fn get_prefix(&self, len: u32) -> Self {
        if len >= self.get_len() {
            return *self;
        }
        if len == 0 {
            return Self::root();
        }
        Self::new(self.val >> (self.len - len), len)
    }

    /// Takes as input a pointer to the caller and another NodeLabel,
    /// returns a NodeLabel that is the longest common prefix of the two.
    pub fn get_longest_common_prefix(&self, other: Self) -> Self {
        let shorter_len = if self.get_len() < other.get_len() {
            self.get_len()
        } else {
            other.get_len()
        };

        let mut prefix_len = 0;
        while prefix_len <= shorter_len
            && self.get_bit_at(prefix_len) == other.get_bit_at(prefix_len)
        {
            prefix_len += 1;
        }

        self.get_prefix(prefix_len)
    }

    /// Takes as input a pointer to self, another NodeLabel and returns the tuple representing:
    /// * the longest common prefix,
    /// * the direction, with respect to the longest common prefix, of other,
    /// * the direction, with respect to the longest common prefix, of self.
    /// If either the node itself, or other is the longest common prefix, the
    /// direction of the longest common prefix node is None.
    pub fn get_longest_common_prefix_and_dirs(&self, other: Self) -> (Self, Direction, Direction) {
        let lcp_label = self.get_longest_common_prefix(other);
        let dir_other = lcp_label.get_dir(other);
        let dir_self = lcp_label.get_dir(*self);
        (lcp_label, dir_other, dir_self)
    }

    /// Gets the direction of other with respect to self, if self is a prefix of other.
    /// If self is not a prefix of other, then returns None.
    pub fn get_dir(&self, other: Self) -> Direction {
        if self.get_len() >= other.get_len() {
            return Direction::None;
        }
        if other.get_prefix(self.get_len()) != *self {
            return Direction::None;
        }
        Direction::Some(other.get_bit_at(self.get_len()) as usize)
    }
}

/// Hashes a label of type NodeLabel using the hash function provided by
/// the generic type H.
pub fn hash_label<H: Hasher>(label: NodeLabel) -> H::Digest {
    let byte_label_len = H::hash(&label.get_len().to_be_bytes());
    H::merge_with_int(byte_label_len, label.get_val())
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound = "")]
/// A HistoryNodeState represents the state of a [crate::history_tree_node::HistoryTreeNode] at a given epoch.
/// As you may see, when looking at [HistoryChildState], the node needs to include
/// its hashed value, the hashed values of its children and the labels of its children.
/// This allows the various algorithms in [crate::history_tree_node::HistoryTreeNode] to build proofs for the tree at
/// any given epoch, without having to do a traversal of the history tree to find siblings.
/// The hash value of this node at this state.
/// To be used in its parent, alongwith the label.
pub struct HistoryNodeState {
    /// The hash at this node state
    pub value: Vec<u8>,
    /// The states of the children at this time
    pub child_states: [Option<HistoryChildState>; ARITY],
    /// A unique key
    pub key: NodeStateKey,
}

/// This struct is just used for storage access purposes.
/// parameters are node label and epoch
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct NodeStateKey(pub NodeLabel, pub u64);

impl PartialOrd for NodeStateKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeStateKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        //`label_len`, `label_val`, `epoch`
        let label_cmp = self.0.len.cmp(&other.0.len);
        if let std::cmp::Ordering::Equal = label_cmp {
            let value_cmp = self.0.val.cmp(&other.0.val);
            if let std::cmp::Ordering::Equal = value_cmp {
                self.1.cmp(&self.1)
            } else {
                value_cmp
            }
        } else {
            label_cmp
        }
    }
}

impl Storable for HistoryNodeState {
    type Key = NodeStateKey;

    fn data_type() -> StorageType {
        StorageType::HistoryNodeState
    }

    fn get_id(&self) -> NodeStateKey {
        self.key
    }

    fn get_full_binary_key_id(key: &NodeStateKey) -> Vec<u8> {
        let mut result = vec![StorageType::HistoryNodeState as u8];
        result.extend_from_slice(&key.0.len.to_be_bytes());
        result.extend_from_slice(&key.0.val.to_be_bytes());
        result.extend_from_slice(&key.1.to_be_bytes());

        result
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<NodeStateKey, String> {
        if bin.len() < 21 {
            return Err("Not enough bytes to form a proper key".to_string());
        }

        let len_bytes: [u8; 4] = bin[1..=4].try_into().expect("Slice with incorrect length");
        let val_bytes: [u8; 8] = bin[5..=12].try_into().expect("Slice with incorrect length");
        let epoch_bytes: [u8; 8] = bin[13..=20]
            .try_into()
            .expect("Slice with incorrect length");
        let len = u32::from_be_bytes(len_bytes);
        let val = u64::from_be_bytes(val_bytes);
        let epoch = u64::from_be_bytes(epoch_bytes);

        Ok(NodeStateKey(NodeLabel::new(val, len), epoch))
    }
}

unsafe impl Sync for HistoryNodeState {}

impl HistoryNodeState {
    /// Creates a new [HistoryNodeState]
    pub fn new<H: Hasher>(key: NodeStateKey) -> Result<Self, HistoryTreeNodeError> {
        const INIT: Option<HistoryChildState> = None;
        Ok(HistoryNodeState {
            value: from_digest::<H>(H::hash(&[0u8]))?,
            child_states: [INIT; ARITY],
            key,
        })
    }

    /// Returns a copy of the child state, in the calling HistoryNodeState in the given direction.
    pub(crate) fn get_child_state_in_dir(&self, dir: usize) -> Option<HistoryChildState> {
        self.child_states[dir].clone()
    }
}

impl Clone for HistoryNodeState {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            child_states: self.child_states.clone(),
            key: self.key,
        }
    }
}

// To use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type.
impl fmt::Display for HistoryNodeState {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "\tvalue = {:?}", self.value)?;
        for i in 0..ARITY {
            writeln!(f, "\tchildren {}: {:?}", i, self.child_states[i])?;
        }
        write!(f, "")
    }
}

/// This struct represents the state of the child of a node at a given epoch
/// and contains all the information its parent might need about it in an operation.
/// The dummy_marker represents whether this child was real or a dummy.
/// In particular, the children of a leaf node are dummies.
#[derive(Debug, Serialize, Deserialize, Eq)]
pub struct HistoryChildState {
    /// Child node's label
    pub label: NodeLabel,
    /// Child node's hash value
    pub hash_val: Vec<u8>,
    /// Child node's state this epoch being pointed to here
    pub epoch_version: u64,
}

unsafe impl Sync for HistoryChildState {}

impl HistoryChildState {
    /// Instantiates a new [HistoryChildState] with given label and hash val.
    pub fn new<H: Hasher>(
        label: NodeLabel,
        hash_val: H::Digest,
        ep: u64,
    ) -> Result<Self, HistoryTreeNodeError> {
        Ok(HistoryChildState {
            label,
            hash_val: from_digest::<H>(hash_val)?,
            epoch_version: ep,
        })
    }
}

impl Clone for HistoryChildState {
    fn clone(&self) -> Self {
        Self {
            label: self.label,
            hash_val: self.hash_val.clone(),
            epoch_version: self.epoch_version,
        }
    }
}

impl PartialEq for HistoryChildState {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
            && self.hash_val == other.hash_val
            && self.epoch_version == other.epoch_version
    }
}

impl fmt::Display for HistoryChildState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\n\t\t label = {:?}
                \n\t\t hash = {:?},
                \n\t\t epoch_version = {:?}\n\n",
            self.label, self.hash_val, self.epoch_version
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // Test for equality
    #[test]
    pub fn test_node_label_equal_leading_one() {
        let label_1 = NodeLabel::new(10000000u64, 8u32);
        let label_2 = NodeLabel::new(10000000u64, 8u32);
        assert!(
            label_1 == label_2,
            "Identical labels with leading one not found equal!"
        )
    }

    #[test]
    pub fn test_node_label_equal_leading_zero() {
        let label_1 = NodeLabel::new(10000000u64, 9u32);
        #[allow(clippy::zero_prefixed_literal)]
        let label_2 = NodeLabel::new(010000000u64, 9u32);
        assert!(
            label_1 == label_2,
            "Identical labels with leading zero not found equal!"
        )
    }

    #[test]
    pub fn test_node_label_unequal_values() {
        let label_1 = NodeLabel::new(10000000u64, 9u32);
        let label_2 = NodeLabel::new(110000000u64, 9u32);
        assert!(label_1 != label_2, "Unequal labels found equal!")
    }

    #[test]
    pub fn test_node_label_equal_values_unequal_len() {
        let label_1 = NodeLabel::new(10000000u64, 8u32);
        let label_2 = NodeLabel::new(10000000u64, 9u32);
        assert!(
            label_1 != label_2,
            "Identical labels with unequal lengths not found equal!"
        )
    }

    // Test for get_longest_common_prefix

    #[test]
    pub fn test_node_label_lcs_with_self_leading_one() {
        let label_1 = NodeLabel::new(10000000u64, 8u32);
        let label_2 = NodeLabel::new(10000000u64, 8u32);
        let expected = NodeLabel::new(10000000u64, 8u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with self with leading one, not equal to itself!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_with_self_leading_zero() {
        let label_1 = NodeLabel::new(0b10000000u64, 9u32);
        let label_2 = NodeLabel::new(0b10000000u64, 9u32);
        let expected = NodeLabel::new(0b10000000u64, 9u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with self with leading zero, not equal to itself!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_self_prefix_leading_one() {
        let label_1 = NodeLabel::new(0b1000u64, 4u32);
        let label_2 = NodeLabel::new(0b10000000u64, 8u32);
        let expected = NodeLabel::new(0b1000u64, 4u32);

        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with self with leading one, not equal to itself!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_self_prefix_leading_zero() {
        let label_1 = NodeLabel::new(0b10000000u64, 9u32);
        let label_2 = NodeLabel::new(0b10000000u64, 9u32);
        let expected = NodeLabel::new(0b10000000u64, 9u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with self with leading zero, not equal to itself!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_other_one() {
        let label_1 = NodeLabel::new(0b10000000u64, 8u32);
        let label_2 = NodeLabel::new(0b11000000u64, 8u32);
        let expected = NodeLabel::new(0b1u64, 1u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with other with leading one, not equal to expected!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_other_zero() {
        let label_1 = NodeLabel::new(0b10000000u64, 9u32);
        let label_2 = NodeLabel::new(0b11000000u64, 9u32);
        let expected = NodeLabel::new(0b1u64, 2u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with other with leading zero, not equal to expected!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_empty() {
        let label_1 = NodeLabel::new(0b10000000u64, 9u32);
        let label_2 = NodeLabel::new(0b11000000u64, 8u32);
        let expected = NodeLabel::new(0b0u64, 0u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring should be empty!"
        )
    }
    #[test]
    pub fn test_node_label_lcs_some_leading_one() {
        let label_1 = NodeLabel::new(0b11010000u64, 8u32);
        let label_2 = NodeLabel::new(0b11011000u64, 8u32);
        let expected = NodeLabel::new(0b1101u64, 4u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with other with leading one, not equal to expected!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_some_leading_zero() {
        let label_1 = NodeLabel::new(0b11010000u64, 9u32);
        let label_2 = NodeLabel::new(0b11011000u64, 9u32);
        let expected = NodeLabel::new(0b1101u64, 5u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with other with leading zero, not equal to expected!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_dirs_some_leading_zero() {
        let label_1 = NodeLabel::new(0b11010000u64, 9u32);
        let label_2 = NodeLabel::new(0b11011000u64, 9u32);
        let expected = (
            NodeLabel::new(0b1101u64, 5u32),
            Direction::Some(1),
            Direction::Some(0),
        );
        let computed = label_1.get_longest_common_prefix_and_dirs(label_2);
        assert!(
        computed == expected,
        "Longest common substring or direction with other with leading zero, not equal to expected!"
    )
    }

    #[test]
    pub fn test_node_label_lcs_dirs_some_leading_one() {
        let label_1 = NodeLabel::new(0b11010000u64, 8u32);
        let label_2 = NodeLabel::new(0b11011000u64, 8u32);
        let expected = (
            NodeLabel::new(0b1101u64, 4u32),
            Direction::Some(1),
            Direction::Some(0),
        );
        let computed = label_1.get_longest_common_prefix_and_dirs(label_2);
        assert!(
        computed == expected,
        "Longest common substring or direction with other with leading zero, not equal to expected!"
    )
    }

    #[test]
    pub fn test_node_label_lcs_dirs_self_leading_one() {
        let label_1 = NodeLabel::new(0b1101u64, 4u32);
        let label_2 = NodeLabel::new(0b11011000u64, 8u32);
        let expected = (
            NodeLabel::new(0b1101u64, 4u32),
            Direction::Some(1),
            Direction::None,
        );
        let computed = label_1.get_longest_common_prefix_and_dirs(label_2);
        assert!(
            computed == expected,
            "Longest common substring or direction with other with leading zero, not equal to expected!"
        )
    }

    #[test]
    pub fn test_get_dir_large() {
        for i in 1..65 {
            let mut rng = OsRng;
            let label_1 = NodeLabel::random(&mut rng);
            let pos = i;
            let pos_32 = pos as u32;
            let label_2 = label_1.get_prefix(pos_32); //NodeLabel::new(0b11011000u64, 1u32);
            let mut direction = Direction::Some(label_1.get_bit_at(pos).try_into().unwrap());
            if pos == 64 {
                direction = Direction::None;
            }
            let computed = label_2.get_dir(label_1);
            assert!(
                computed == direction,
                "Direction not equal to expected. Node = {:?}, prefix = {:?}",
                label_1,
                label_2
            )
        }
    }

    #[test]
    pub fn test_get_dir_example() {
        let label_1 = NodeLabel::new(10049430782486799941u64, 64u32);
        let label_2 = NodeLabel::new(23u64, 5u32);
        let direction = Direction::None;
        let computed = label_2.get_dir(label_1);
        assert!(
            computed == direction,
            "Direction not equal to expected. Node = {:?}, prefix = {:?}, computed = {:?}",
            label_1,
            label_2,
            computed
        )
    }

    #[test]
    pub fn test_get_prefix_small() {
        let label_1 = NodeLabel::new(
            0b1000101101110110110000000000110101110001000000000110011001000101u64,
            64u32,
        );
        let prefix_len = 10u32;
        let label_2 = NodeLabel::new(0b1000101101u64, prefix_len);
        let computed = label_1.get_prefix(prefix_len);
        assert!(
            computed == label_2,
            "Direction not equal to expected. Node = {:?}, prefix = {:?}, computed = {:?}",
            label_1,
            label_2,
            computed
        )
    }

    // Test for serialization / deserialization

    #[test]
    pub fn serialize_deserialize() {
        use winter_crypto::hashers::Blake3_256;
        use winter_crypto::Hasher;
        use winter_math::fields::f128::BaseElement;

        type Blake3 = Blake3_256<BaseElement>;

        let label = NodeLabel { val: 0, len: 0 };
        let hash = Blake3::hash(b"hello, world!");
        let node = Node::<Blake3> { label, hash };

        let serialized = bincode::serialize(&node).unwrap();
        let deserialized: Node<Blake3> = bincode::deserialize(&serialized).unwrap();

        assert_eq!(node.label, deserialized.label);
        assert_eq!(node.hash, deserialized.hash);
    }
}
