// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the specifics for NodeLabel only, other types don't have the
//! same level of detail and aren't broken into sub-modules

use crate::hash::Digest;
use crate::{Direction, SizeOf};

#[cfg(feature = "serde_serialization")]
use crate::utils::serde_helpers::{bytes_deserialize_hex, bytes_serialize_hex};
#[cfg(feature = "nostd")]
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};

#[cfg(test)]
mod tests;

/// The label used for an empty node
pub const EMPTY_LABEL: NodeLabel = NodeLabel {
    label_val: [1u8; 32],
    label_len: 0,
};

/// Represents the label of a AKD node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct NodeLabel {
    #[cfg_attr(
        feature = "serde_serialization",
        serde(serialize_with = "bytes_serialize_hex")
    )]
    #[cfg_attr(
        feature = "serde_serialization",
        serde(deserialize_with = "bytes_deserialize_hex")
    )]
    /// Stores a binary string as a 32-byte array of `u8`s
    pub label_val: [u8; 32],
    /// len keeps track of how long the binary string is in bits
    pub label_len: u32,
}

impl SizeOf for NodeLabel {
    fn size_of(&self) -> usize {
        self.label_val.len() + core::mem::size_of::<u32>()
    }
}

impl PartialOrd for NodeLabel {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeLabel {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // `label_len`, `label_val`
        let len_cmp = self.label_len.cmp(&other.label_len);
        if let core::cmp::Ordering::Equal = len_cmp {
            self.label_val.cmp(&other.label_val)
        } else {
            len_cmp
        }
    }
}

impl core::fmt::Display for NodeLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "(0x{}, {})", hex::encode(self.label_val), self.label_len)
    }
}

impl NodeLabel {
    /// Hash a [NodeLabel] into a digest, length-prefixing the label's value
    pub fn hash(&self) -> Digest {
        crate::hash::hash(&self.to_bytes())
    }

    pub(crate) fn to_bytes(self) -> Vec<u8> {
        [&self.label_len.to_be_bytes(), &self.label_val[..]].concat()
    }

    /// Takes as input a pointer to the caller and another [NodeLabel],
    /// returns a NodeLabel that is the longest common prefix of the two.
    pub fn get_longest_common_prefix(&self, other: NodeLabel) -> Self {
        let shorter_len = if self.label_len < other.label_len {
            self.label_len
        } else {
            other.label_len
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

    /// Returns the bit at a specified index, and a 0 on an out of range index
    ///
    /// Note that this is calculated from the right, for example:
    /// let mut label = [0u8; 32];
    /// label[0] = 0b10100000u8;
    /// We should get outputs as follows:
    /// * label.get_bit_at(0) = 1
    /// * label.get_bit_at(1) = 0
    /// * label.get_bit_at(2) = 1
    /// * label.get_bit_at(3) = 0
    /// * label.get_bit_at(4) = 0
    /// * label.get_bit_at(5) = 0
    /// * label.get_bit_at(6) = 0
    /// * label.get_bit_at(7) = 0
    fn get_bit_at(&self, index: u32) -> u8 {
        if index >= self.label_len {
            return 0;
        }

        let usize_index: usize = index.try_into().unwrap();
        let index_full_blocks = usize_index / 8;
        let index_remainder = usize_index % 8;
        (self.label_val[index_full_blocks] >> (7 - index_remainder)) & 1
    }

    /// Returns the prefix of a specified length, and the entire value on an out of range length
    pub fn get_prefix(&self, len: u32) -> Self {
        if len >= self.label_len {
            return *self;
        }
        if len == 0 {
            return Self {
                label_val: [0u8; 32],
                label_len: 0,
            };
        }

        let usize_len: usize = (len - 1).try_into().unwrap();
        let len_remainder = usize_len % 8;
        let len_div = usize_len / 8;

        let mut out_val = [0u8; 32];
        out_val[..len_div].clone_from_slice(&self.label_val[..len_div]);
        out_val[len_div] = (self.label_val[len_div] >> (7 - len_remainder)) << (7 - len_remainder);

        Self {
            label_val: out_val,
            label_len: len,
        }
    }

    /// Creates a new NodeLabel representing the root.
    pub fn root() -> Self {
        Self::new([0u8; 32], 0)
    }

    /// Creates a new NodeLabel with the given value and len (in bits).
    pub fn new(val: [u8; 32], len: u32) -> Self {
        NodeLabel {
            label_val: val,
            label_len: len,
        }
    }

    /// Gets the length of a NodeLabel in bits.
    pub fn get_len(&self) -> u32 {
        self.label_len
    }

    /// Gets the value of a NodeLabel.
    pub fn get_val(&self) -> [u8; 32] {
        self.label_val
    }

    /// The sibling of a node in a binary tree has the same label as its sibling
    /// except its last bit is flipped (e.g., 000 and 001 are siblings).
    /// This function returns the sibling prefix of a specified length.
    /// The rest of the node label after the flipped bit is padded with zeroes.
    /// For instance, 010100 (length = 6) with sibling prefix length = 3 is 01[1]000 (length = 3)
    /// -- [bit] denoting flipped bit.
    pub fn get_sibling_prefix(&self, mut len: u32) -> Self {
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
        out_val[..byte_index].clone_from_slice(&self.label_val[..byte_index]);
        out_val[byte_index] = (val[byte_index] >> (7 - bit_index)) << (7 - bit_index);

        Self::new(out_val, len)
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
        Direction::try_from(other.get_bit_at(self.get_len())).unwrap()
    }
}
