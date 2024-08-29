// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains the specifics for NodeLabel only, other types don't have the
//! same level of detail and aren't broken into sub-modules

use crate::{configuration::Configuration, PrefixOrdering, SizeOf};

#[cfg(feature = "serde_serialization")]
use crate::utils::serde_helpers::{bytes_deserialize_hex, bytes_serialize_hex};
#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::String;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

/// Represents the label of an AKD node
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

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Bit {
    Zero = 0u8,
    One = 1u8,
}

impl NodeLabel {
    /// Returns the value of the [NodeLabel]
    pub fn value<TC: Configuration>(&self) -> Vec<u8> {
        TC::compute_node_label_value(&self.to_bytes())
    }

    pub(crate) fn to_bytes(self) -> Vec<u8> {
        [&self.label_len.to_be_bytes(), &self.label_val[..]].concat()
    }

    /// Outputs whether or not self is a prefix of the other [NodeLabel]
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.label_len > other.label_len {
            return false;
        }
        (0..self.label_len).all(|i| self.get_bit_at(i) == other.get_bit_at(i))
    }

    /// Takes as input a pointer to the caller and another [NodeLabel],
    /// returns a [NodeLabel] that is the longest common prefix of the two.
    pub fn get_longest_common_prefix<TC: Configuration>(&self, other: NodeLabel) -> Self {
        let empty_label = TC::empty_label();
        if *self == empty_label || other == empty_label {
            return empty_label;
        }

        let shorter_len = if self.label_len < other.label_len {
            self.label_len
        } else {
            other.label_len
        };

        let mut prefix_len = 0;
        while prefix_len < shorter_len
            && self.get_bit_at(prefix_len) == other.get_bit_at(prefix_len)
        {
            prefix_len += 1;
        }

        self.get_prefix(prefix_len)
    }

    /// Returns the bit at a specified index (either a 0 or a 1). Will
    /// throw an error if the index is out of range
    /// (exceeds or is equal to the length of the label in bits)
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
    fn get_bit_at(&self, index: u32) -> Result<Bit, String> {
        if index >= self.label_len {
            return Err(format!(
                "Index out of range: index = {index}, label_len = {label_len}",
                index = index,
                label_len = self.label_len
            ));
        }
        get_bit_from_slice(&self.label_val, index)
    }

    /// Returns the prefix of a specified length, and the entire value if the length is >= 256
    pub fn get_prefix(&self, len: u32) -> Self {
        if len >= 256 {
            return *self;
        }
        if len == 0 {
            return Self {
                label_val: [0u8; 32],
                label_len: 0,
            };
        }

        let usize_len: usize = (len - 1) as usize;
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

    /// Creates a new [NodeLabel] with the given value and len (in bits).
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

    /// Gets the prefix ordering of other with respect to self, if self is a prefix of other.
    /// If self is not a prefix of other, then this returns [PrefixOrdering::Invalid].
    pub fn get_prefix_ordering(&self, other: Self) -> PrefixOrdering {
        if self.get_len() >= other.get_len() {
            return PrefixOrdering::Invalid;
        }
        if other.get_prefix(self.get_len()) != self.get_prefix(self.get_len()) {
            // Note: we check self.get_prefix(self.get_len()) here instead of just *self
            // because equality checks for a [NodeLabel] do not ignore the bits of label_val set
            // beyond label_len.
            return PrefixOrdering::Invalid;
        }
        if let Ok(bit) = other.get_bit_at(self.get_len()) {
            return PrefixOrdering::from(bit);
        }

        PrefixOrdering::Invalid
    }
}

/// Returns the bit at a specified index (either a 0 or a 1) of a slice of bytes
///
/// If the index is out of range (exceeds or is equal to the length of the input in bytes * 8),
/// returns an error
fn get_bit_from_slice(input: &[u8], index: u32) -> Result<Bit, String> {
    if (input.len() as u32) * 8 <= index {
        return Err(format!(
            "Input is too short: index = {index}, input.len() = {}",
            input.len()
        ));
    }
    let usize_index: usize = index as usize;
    let index_full_blocks = usize_index / 8;
    let index_remainder = usize_index % 8;
    if (input[index_full_blocks] >> (7 - index_remainder)) & 1 == 0 {
        Ok(Bit::Zero)
    } else {
        Ok(Bit::One)
    }
}
