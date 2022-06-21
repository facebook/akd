// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The representation for the label of a tree node.

#[cfg(feature = "serde_serialization")]
use crate::serialization::{
    bytes_deserialize_hex, bytes_serialize_hex, digest_deserialize, digest_serialize,
};
use crate::{Direction, EMPTY_LABEL};

#[cfg(feature = "rand")]
use rand::{CryptoRng, Rng, RngCore};

use std::{
    convert::TryInto,
    fmt::{self, Debug},
};
use winter_crypto::Hasher;

/// Represents a node's label & associated hash
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct Node<H: Hasher> {
    /// the label associated with the accompanying hash
    pub label: NodeLabel,
    /// the hash associated to this label
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "digest_serialize")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "digest_deserialize")
    )]
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

/// The NodeLabel struct represents the label for a TreeNode.
/// Since the label itself may have any number of zeros pre-pended,
/// just using a native type, unless it is a bit-vector, wouldn't work.
/// Hence, we need a custom representation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct NodeLabel {
    /// val stores a binary string as a u64
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "bytes_serialize_hex")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "bytes_deserialize_hex")
    )]
    pub val: [u8; 32],
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

impl fmt::Display for NodeLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(0x{}, {})", hex::encode(&self.val), self.len)
    }
}

impl NodeLabel {
    /// Creates a new NodeLabel representing the root.
    pub fn root() -> Self {
        Self::new([0u8; 32], 0)
    }

    /// Creates a new NodeLabel with the given value and len.
    pub fn new(val: [u8; 32], len: u32) -> Self {
        NodeLabel { val, len }
    }

    /// Gets the length of a NodeLabel.
    pub fn get_len(&self) -> u32 {
        self.len
    }

    /// Gets the value of a NodeLabel.
    pub fn get_val(&self) -> [u8; 32] {
        self.val
    }

    /// Generate a random NodeLabel for testing purposes
    #[cfg(feature = "rand")]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // FIXME: should we always select length-64 labels?
        Self {
            val: rng.gen(),
            len: 256,
        }
    }

    /// Returns the bit at a specified index, and a 0 on an out of range index
    fn get_bit_at(&self, index: u32) -> u8 {
        if index >= self.len {
            return 0;
        }

        let usize_index: usize = index.try_into().unwrap();
        let index_full_blocks = usize_index / 8;
        let index_remainder = usize_index % 8;
        (self.val[index_full_blocks] >> (7 - index_remainder)) & 1
    }

    /// Returns the prefix of a specified length, and the entire value on an out of range length
    pub(crate) fn get_prefix(&self, len: u32) -> Self {
        if len >= self.get_len() {
            return *self;
        }
        if len == 0 {
            return Self::new([0u8; 32], 0);
        }

        let usize_len: usize = (len - 1).try_into().unwrap();
        let len_remainder = usize_len % 8;
        let len_div = usize_len / 8;

        let mut out_val = [0u8; 32];
        out_val[..len_div].clone_from_slice(&self.val[..len_div]);
        out_val[len_div] = (self.val[len_div] >> (7 - len_remainder)) << (7 - len_remainder);

        Self::new(out_val, len)
    }

    // The sibling of a node in a binary tree has the same label as its sibling
    // except its last bit is flipped (e.g., 000 and 001 are siblings).
    // This function returns the sibling prefix of a specified length.
    // The rest of the node label after the flipped bit is padded with zeroes.
    // For instance, 010100 (length = 6) with sibling prefix length = 3 is 01[1]000 (length = 3)
    // -- [bit] denoting flipped bit.
    pub(crate) fn get_sibling_prefix(&self, mut len: u32) -> Self {
        if len > self.get_len() {
            len = self.get_len();
        }

        if len == 0 {
            return Self::new([0u8; 32], 0);
        }

        let usize_len: usize = (len - 1).try_into().unwrap();
        let byte_index = usize_len / 8;
        let bit_index = usize_len % 8;

        let bit_flip_marker: u8 = 0b1 << (7 - bit_index);

        let mut val = self.get_val();
        val[byte_index] ^= bit_flip_marker;

        let mut out_val = [0u8; 32];
        out_val[..byte_index].clone_from_slice(&self.val[..byte_index]);
        out_val[byte_index] = (val[byte_index] >> (7 - bit_index)) << (7 - bit_index);

        Self::new(out_val, len)
    }

    /// Takes as input a pointer to the caller and another NodeLabel,
    /// returns a NodeLabel that is the longest common prefix of the two.
    #[must_use]
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
        if *self == EMPTY_LABEL || other == EMPTY_LABEL {
            return EMPTY_LABEL;
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
    let hash_input = [&label.get_len().to_be_bytes()[..], &label.get_val()].concat();
    H::hash(&hash_input)
}

#[cfg(any(test, feature = "public-tests"))]
pub(crate) fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

// Use test profile here other wise cargo complains function is never used.
#[allow(unused)]
fn byte_arr_from_u64_suffix(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[24..32].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    pub fn test_get_bit_at_small() {
        let val = 0b1010u64 << 60;
        let expected = 1;
        let label = NodeLabel::new(byte_arr_from_u64(val), 4);
        let computed = label.get_bit_at(2);
        assert!(
            expected == computed,
            "get_bit_at(2) wrong for the 4 digit label 10! Expected {:?} and got {:?}",
            expected,
            computed
        )
    }

    #[test]
    pub fn test_get_bit_at_medium_1() {
        let val = 0b1u64 << 63;
        let expected = 1;
        let label = NodeLabel::new(byte_arr_from_u64(val), 256);
        let computed = label.get_bit_at(0);
        assert!(
            expected == computed,
            "get_bit_at(2) wrong for the 4 digit label 10! Expected {:?} and got {:?}",
            expected,
            computed
        )
    }

    #[test]
    pub fn test_get_bit_at_medium_2() {
        let val = 0b1u64 << 63;
        let expected = 0;
        let label = NodeLabel::new(byte_arr_from_u64(val), 256);
        let computed = label.get_bit_at(190);
        assert!(
            expected == computed,
            "get_bit_at(2) wrong for the 4 digit label 10! Expected {:?} and got {:?}",
            expected,
            computed
        )
    }

    #[test]
    pub fn test_get_bit_at_large() {
        let mut val = [0u8; 32];
        val[2] = 128u8 + 32u8;
        let expected = 1;
        let label = NodeLabel::new(val, 256);
        let computed = label.get_bit_at(16);
        assert!(
            expected == computed,
            "get_bit_at(2) wrong for the 4 digit label 10! Expected {:?} and got {:?}",
            expected,
            computed
        )
    }

    #[test]
    pub fn test_byte_arr_from_u64_small() {
        let val = 0b1010u64 << 60;
        let mut expected = [0u8; 32];
        expected[0] = 0b10100000u8;
        let computed = byte_arr_from_u64(val);
        assert!(
            expected == computed,
            "Byte from u64 conversion wrong for small u64! Expected {:?} and got {:?}",
            expected,
            computed
        )
    }

    #[test]
    pub fn test_byte_arr_from_u64_medium() {
        let val = 0b101010101010u64 << 52;
        let mut expected = [0u8; 32];
        expected[0] = 0b10101010u8;
        expected[1] = 0b10100000u8;
        let computed = byte_arr_from_u64(val);
        assert!(
            expected == computed,
            "Byte from u64 conversion wrong for medium, ~2 byte u64! Expected {:?} and got {:?}",
            expected,
            computed
        )
    }

    #[test]
    pub fn test_byte_arr_from_u64_larger() {
        let val = 0b01011010101101010101010u64 << 41;
        let mut expected = [0u8; 32];
        expected[2] = 0b01010100u8;
        expected[1] = 0b10110101u8;
        expected[0] = 0b01011010u8;
        let computed = byte_arr_from_u64(val);
        assert!(
            expected == computed,
            "Byte from u64 conversion wrong for larger, ~3 byte u64! Expected {:?} and got {:?}",
            expected,
            computed
        )
    }

    // Test for equality
    #[test]
    pub fn test_node_label_equal_leading_one() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64), 8u32);
        assert!(
            label_1 == label_2,
            "Identical labels with leading one not found equal!"
        )
    }

    #[test]
    pub fn test_node_label_equal_leading_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(010000000u64), 9u32);
        assert!(
            label_1 == label_2,
            "Identical labels with leading zero not found equal!"
        )
    }

    #[test]
    pub fn test_node_label_unequal_values() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(110000000u64), 9u32);
        assert!(label_1 != label_2, "Unequal labels found equal!")
    }

    #[test]
    pub fn test_node_label_equal_values_unequal_len() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64), 9u32);
        assert!(
            label_1 != label_2,
            "Identical labels with unequal lengths not found equal!"
        )
    }

    // Test for get_longest_common_prefix

    #[test]
    pub fn test_node_label_with_self_leading_one() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64), 8u32);
        let expected = NodeLabel::new(byte_arr_from_u64(10000000u64), 8u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with self with leading one, not equal to itself!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_with_self_leading_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64), 9u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b10000000u64), 9u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with self with leading zero, not equal to itself!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_self_prefix_leading_one() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b1000u64), 4u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64), 8u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b1000u64), 4u32);
        let computed = label_1.get_longest_common_prefix(label_2);
        assert!(
            computed == expected,
            "Longest common substring with self with leading one, not equal to itself! Expected: {:?}, Got: {:?}",
            expected, computed
        )
    }

    #[test]
    pub fn test_node_label_lcs_self_prefix_leading_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64), 9u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b10000000u64), 9u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with self with leading zero, not equal to itself!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_other_one() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 56), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 56), 8u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32);
        let computed = label_1.get_longest_common_prefix(label_2);
        assert!(
            computed == expected,
            "Longest common substring with other with leading one, not equal to expected! Expected: {:?}, Computed: {:?}",
            expected, computed
        )
    }

    #[test]
    pub fn test_node_label_lcs_other_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 55), 9u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b1u64 << 62), 2u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with other with leading zero, not equal to expected!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_empty() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 56), 8u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b0u64), 0u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring should be empty!"
        )
    }
    #[test]
    pub fn test_node_label_lcs_some_leading_one() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 56), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with other with leading one, not equal to expected!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_some_leading_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 55), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 55), 9u32);
        let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 59), 5u32);
        assert!(
            label_1.get_longest_common_prefix(label_2) == expected,
            "Longest common substring with other with leading zero, not equal to expected!"
        )
    }

    #[test]
    pub fn test_node_label_lcs_dirs_some_leading_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 55), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 55), 9u32);
        let expected = (
            NodeLabel::new(byte_arr_from_u64(0b1101u64 << 59), 5u32),
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
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 56), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
        let expected = (
            NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32),
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
        let label_1 = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
        let expected = (
            NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32),
            Direction::Some(1),
            Direction::None,
        );
        let computed = label_1.get_longest_common_prefix_and_dirs(label_2);
        assert!(
            computed == expected,
            "Longest common substring or direction with other with leading zero, not equal to expected! Computed = {:?} and expected = {:?}",
            computed, expected
        )
    }

    #[test]
    pub fn test_get_dir_large() {
        for i in 1..257 {
            let mut rng = OsRng;
            let label_1 = NodeLabel::random(&mut rng);
            let pos = i;
            let label_2 = label_1.get_prefix(pos);
            let mut direction = Direction::Some(label_1.get_bit_at(pos).try_into().unwrap());
            if pos == 256 {
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
        let label_1 = NodeLabel::new(byte_arr_from_u64(10049430782486799941u64), 64u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(23u64), 5u32);
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
            byte_arr_from_u64(
                0b1000101101110110110000000000110101110001000000000110011001000101u64,
            ),
            64u32,
        );
        let prefix_len = 10u32;
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b1000101101u64 << 54), prefix_len);
        let computed = label_1.get_prefix(prefix_len);
        assert!(
            computed == label_2,
            "Direction not equal to expected. Node = {:?}, prefix = {:?}, computed = {:?}",
            label_1,
            label_2,
            computed
        )
    }

    #[test]
    pub fn test_get_sibling_prefix() {
        let label0 = NodeLabel::new(byte_arr_from_u64(0b0 << 63), 1);
        let label0_sibling = NodeLabel::new(byte_arr_from_u64(0b1 << 63), 1);

        assert!(label0.get_sibling_prefix(1) == label0_sibling);

        let label1 = NodeLabel::new(byte_arr_from_u64(0b1 << 63), 1);
        let label1_sibling = NodeLabel::new(byte_arr_from_u64(0b0 << 63), 1);

        assert!(label1.get_sibling_prefix(1) == label1_sibling);

        let label_rand_len_30 = NodeLabel::new(
            byte_arr_from_u64(
                0b1010000000000110001111001000001000001000110100101010111111001110u64,
            ),
            30,
        );
        let label_rand_len_30_prefix_15_sibling = NodeLabel::new(
            byte_arr_from_u64(
                0b1010000000000100000000000000000000000000000000000000000000000000u64,
            ),
            15,
        );

        assert!(label_rand_len_30.get_sibling_prefix(15) == label_rand_len_30_prefix_15_sibling);

        let label_rand_len_256 = NodeLabel::new(
            byte_arr_from_u64_suffix(
                0b1010000000000110001111001000001000001000110100101010111111001110u64,
            ),
            256,
        );
        let label_rand_len_256_prefix_256_sibling = NodeLabel::new(
            byte_arr_from_u64_suffix(
                0b1010000000000110001111001000001000001000110100101010111111001111u64,
            ),
            256,
        );

        assert!(
            label_rand_len_256.get_sibling_prefix(256) == label_rand_len_256_prefix_256_sibling
        );
    }

    // Test for serialization / deserialization

    #[test]
    pub fn serialize_deserialize() {
        use winter_crypto::hashers::Blake3_256;
        use winter_crypto::Hasher;
        use winter_math::fields::f128::BaseElement;

        type Blake3 = Blake3_256<BaseElement>;

        let label = NodeLabel {
            val: byte_arr_from_u64(0),
            len: 0,
        };
        let hash = Blake3::hash(b"hello, world!");
        let node = Node::<Blake3> { label, hash };

        let serialized = bincode::serialize(&node).unwrap();
        let deserialized: Node<Blake3> = bincode::deserialize(&serialized).unwrap();

        assert_eq!(node.label, deserialized.label);
        assert_eq!(node.hash, deserialized.hash);
    }
}
