// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{Direction, ARITY};
use crypto::Hasher;
use std::{
    array,
    convert::TryInto,
    fmt::{self, Debug},
};

#[cfg(any(test, feature = "bench"))]
use rand::{CryptoRng, RngCore};

#[derive(Debug, Copy, Clone)]
pub struct NodeLabel {
    pub val: u64,
    pub len: u32,
}

impl NodeLabel {
    pub fn new(val: u64, len: u32) -> Self {
        NodeLabel { val, len }
    }

    pub fn get_len(&self) -> u32 {
        self.len
    }
    pub fn get_val(&self) -> u64 {
        self.val
    }

    #[cfg(any(test, feature = "bench"))]
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
    fn get_prefix(&self, len: u32) -> Self {
        if len >= self.get_len() {
            return *self;
        }
        if len == 0 {
            return Self::new(0, 0);
        }
        Self::new(self.val >> (self.len - len), len)
    }

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

    pub fn get_longest_common_prefix_and_dirs(&self, other: Self) -> (Self, Direction, Direction) {
        let lcp_label = self.get_longest_common_prefix(other);
        let dir_other = lcp_label.get_dir(other);
        let dir_self = lcp_label.get_dir(*self);
        (lcp_label, dir_other, dir_self)
    }

    pub fn get_dir(&self, other: Self) -> Direction {
        if self.get_len() >= other.get_len() {
            return Direction::None;
        }
        if other.get_prefix(self.get_len()) != *self {
            return Direction::None;
        }
        Direction::Some(other.get_bit_at(self.get_len()).try_into().unwrap())
        // let other_self_difference = other.get_len() - self.get_len();
        // let self_at_other_len = self.get_val().wrapping_shl(other_self_difference);
        // let other_xored = self_at_other_len ^ other.get_val();
        // let dir: usize = other_xored
        //     .wrapping_shr(other_self_difference - 1)
        //     .try_into()
        //     .unwrap();
        // Direction::Some(dir)
    }
}

impl PartialEq for NodeLabel {
    fn eq(&self, other: &Self) -> bool {
        self.val == other.val && self.len == other.len
    }
}

pub fn hash_label<H: Hasher>(label: NodeLabel) -> H::Digest {
    let byte_label_len = H::hash(&label.get_len().to_ne_bytes());
    H::merge_with_int(byte_label_len, label.get_val())
}

#[derive(Debug)]
pub struct HistoryNodeState<H: Hasher> {
    pub value: H::Digest,
    pub child_states: [HistoryChildState<H>; ARITY],
}

impl<H: Hasher> HistoryNodeState<H> {
    pub fn new() -> Self {
        let mut children = [HistoryChildState::<H>::new_dummy(); ARITY];
        HistoryNodeState {
            value: H::hash(&[0u8]),
            child_states: children,
        }
    }

    pub fn get_child_state_in_dir(&self, dir: usize) -> HistoryChildState<H> {
        self.child_states[dir]
    }
}

impl<H: Hasher> Default for HistoryNodeState<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher> Clone for HistoryNodeState<H> {
    fn clone(&self) -> Self {
        Self {
            value: self.value,
            child_states: self.child_states,
        }
    }
}

/*

pub type HistoryChildLabel = NodeLabel;

pub type HistoryChildHash<H: Hasher> = Option<H::Digest>;

pub type HistoryChildEpochVersion = Option<u64>;

pub type HistoryChildLocation = Option<usize>;


#[derive(Debug, Copy, Clone)]
pub struct HistoryChildState<H: Hasher> {
    pub location: HistoryChildLocation,
    pub label: HistoryChildLabel,
    pub hash_val: HistoryChildHash<H>,
    pub epoch_version: HistoryChildEpochVersion,
}
*/
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DummyChildState {
    Dummy,
    Real,
}
#[derive(Debug)]
pub struct HistoryChildState<H: Hasher> {
    pub dummy_marker: DummyChildState,
    pub location: usize,
    pub label: NodeLabel,
    pub hash_val: H::Digest,
    pub epoch_version: u64,
}

impl<H: Hasher> HistoryChildState<H> {
    pub fn new(loc: usize, label: NodeLabel, hash_val: H::Digest, ep: u64) -> Self {
        HistoryChildState {
            dummy_marker: DummyChildState::Real,
            location: loc,
            label,
            hash_val,
            epoch_version: ep,
        }
    }

    pub fn new_dummy() -> Self {
        HistoryChildState {
            dummy_marker: DummyChildState::Dummy,
            location: 0,
            label: NodeLabel::new(0, 0),
            hash_val: H::hash(&[0u8]),
            epoch_version: 0,
        }
    }
}

impl<H: Hasher> Clone for HistoryChildState<H> {
    fn clone(&self) -> Self {
        Self {
            dummy_marker: self.dummy_marker,
            location: self.location,
            label: self.label,
            hash_val: self.hash_val,
            epoch_version: self.epoch_version,
        }
    }
}

impl<H: Hasher> Copy for HistoryChildState<H> {}

impl<H: Hasher> PartialEq for HistoryChildState<H> {
    fn eq(&self, other: &Self) -> bool {
        self.dummy_marker == other.dummy_marker
            && self.location == other.location
            && self.label == other.label
            && self.hash_val == other.hash_val
            && self.epoch_version == other.epoch_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        println!("{:?}", label_1.get_longest_common_prefix(label_2));
        println!("{:?}", expected);
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
        use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
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
        let mut direction = Direction::None;
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
}
