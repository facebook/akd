// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::serialization::from_digest;
use crate::storage::{Storable, Storage};
use crate::{Direction, ARITY};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::{
    convert::TryInto,
    fmt::{self, Debug},
};
use winter_crypto::Hasher;

use rand::{CryptoRng, RngCore};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    }
}

pub fn hash_label<H: Hasher>(label: NodeLabel) -> H::Digest {
    let byte_label_len = H::hash(&label.get_len().to_ne_bytes());
    H::merge_with_int(byte_label_len, label.get_val())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HistoryNodeState<H, S> {
    pub value: Vec<u8>,
    pub child_states: Vec<HistoryChildState<H, S>>,
}

// parameters are azks_id, node location, and epoch
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeStateKey(pub(crate) Vec<u8>, pub(crate) NodeLabel, pub(crate) usize);

impl<H: Hasher, S: Storage> Storable<S> for HistoryNodeState<H, S> {
    type Key = NodeStateKey;

    fn identifier() -> String {
        String::from("HistoryNodeState")
    }
}

impl<H: Hasher, S: Storage> HistoryNodeState<H, S> {
    pub fn new() -> Self {
        let children = vec![HistoryChildState::<H, S>::new_dummy(); ARITY];
        HistoryNodeState {
            value: from_digest::<H>(H::hash(&[0u8])).unwrap(),
            child_states: children,
        }
    }

    pub fn get_child_state_in_dir(&self, dir: usize) -> HistoryChildState<H, S> {
        self.child_states[dir].clone()
    }
}

impl<H: Hasher, S: Storage> Default for HistoryNodeState<H, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher, S: Storage> Clone for HistoryNodeState<H, S> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            child_states: self.child_states.clone(),
        }
    }
}

// To use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type.
impl<H: Hasher, S: Storage> fmt::Display for HistoryNodeState<H, S> {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "\tvalue = {:?}", self.value).unwrap();
        for i in 0..ARITY {
            writeln!(f, "\tchildren {}: {:#}", i, self.child_states[i]).unwrap();
        }
        write!(f, "")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DummyChildState {
    Dummy,
    Real,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryChildState<H, S> {
    pub dummy_marker: DummyChildState,
    pub location: usize,
    pub label: NodeLabel,
    pub hash_val: Vec<u8>,
    pub epoch_version: u64,
    pub(crate) _h: PhantomData<H>,
    pub(crate) _s: PhantomData<S>,
}

// parameters are azks_id, node location, epoch, child index
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ChildStateKey(
    pub(crate) Vec<u8>,
    pub(crate) usize,
    pub(crate) usize,
    pub(crate) usize,
);

impl<H: Hasher, S: Storage> Storable<S> for HistoryChildState<H, S> {
    type Key = ChildStateKey;

    fn identifier() -> String {
        String::from("HistoryChildState")
    }
}

impl<H: Hasher, S: Storage> HistoryChildState<H, S> {
    pub fn new(loc: usize, label: NodeLabel, hash_val: H::Digest, ep: u64) -> Self {
        HistoryChildState {
            dummy_marker: DummyChildState::Real,
            location: loc,
            label,
            hash_val: from_digest::<H>(hash_val).unwrap(),
            epoch_version: ep,
            _h: PhantomData,
            _s: PhantomData,
        }
    }

    pub fn new_dummy() -> Self {
        HistoryChildState {
            dummy_marker: DummyChildState::Dummy,
            location: 0,
            label: NodeLabel::new(0, 0),
            hash_val: from_digest::<H>(H::hash(&[0u8])).unwrap(),
            epoch_version: 0,
            _h: PhantomData,
            _s: PhantomData,
        }
    }
}

impl<H: Hasher, S: Storage> Clone for HistoryChildState<H, S> {
    fn clone(&self) -> Self {
        Self {
            dummy_marker: self.dummy_marker,
            location: self.location,
            label: self.label,
            hash_val: self.hash_val.clone(),
            epoch_version: self.epoch_version,
            _h: PhantomData,
            _s: PhantomData,
        }
    }
}

impl<H: Hasher, S: Storage> PartialEq for HistoryChildState<H, S> {
    fn eq(&self, other: &Self) -> bool {
        self.dummy_marker == other.dummy_marker
            && self.location == other.location
            && self.label == other.label
            && self.hash_val == other.hash_val
            && self.epoch_version == other.epoch_version
    }
}

impl<H: Hasher, S: Storage> fmt::Display for HistoryChildState<H, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\n\t\t location = {:?}
                \n\t\t label = {:?}
                \n\t\t hash = {:?},
                \n\t\t epoch_version = {:?}\n\n",
            self.location, self.label, self.hash_val, self.epoch_version
        )
    }
}

/*

use serde::{ Serializer, Deserializer};
use winter_utils::{Serializable, Deserializable, SliceReader};


fn hash_digest_serialize<S, H>(input: &H::Digest, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer, H: Hasher
{
    let mut output = vec![];
    input.write_into(&mut output);
    s.serialize_bytes(&output)
}

pub fn hash_digest_deserialize<'de, D, H>(deserializer: D) -> Result<H::Digest, D::Error>
where
    D: Deserializer<'de>, H: Hasher
{
    let input: &[u8] = Deserialize::deserialize(deserializer).unwrap();
    Ok(H::Digest::read_from(&mut SliceReader {
        source: &input,
        pos: 0,
    }).unwrap()) // FIXME
}

mod hash_digest_serde {

    use serde::{ Serializer, Deserializer, Deserialize};
    use crypto::{ Hasher };
    use winter_utils::{Serializable, Deserializable, SliceReader};

    pub fn serialize<S, H>(input: &H::Digest, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, H: Hasher
    {
        let mut output = vec![];
        input.write_into(&mut output);
        s.serialize_bytes(&output)
    }

    pub fn deserialize<'de, D, H>(deserializer: D) -> Result<H::Digest, D::Error>
    where
        D: Deserializer<'de>, H: Hasher
    {
        let input: &[u8] = Deserialize::deserialize(deserializer).unwrap();
        Ok(H::Digest::read_from(&mut SliceReader {
            source: &input,
            pos: 0,
        }).unwrap()) // FIXME
    }
}

*/

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
}
