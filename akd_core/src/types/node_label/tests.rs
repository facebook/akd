// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Tests for node labels

use super::*;
#[cfg(feature = "nostd")]
use alloc::vec;
use core::convert::TryFrom;
use rand::{thread_rng, Rng};

// ================= Test helpers ================= //

fn random_label() -> crate::NodeLabel {
    let mut rng = thread_rng();
    crate::NodeLabel {
        label_val: rng.gen::<[u8; 32]>(),
        label_len: 256,
    }
}

// Creates a byte array of 32 bytes from a u64
// Note that this representation is big-endian, and
// places the bits to the front of the output byte_array.
fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

// Creates a byte array of 32 bytes from a u64
// Note that this representation is little-endian, and
// places the bits to the front of the output byte_array.
fn byte_arr_from_u64_le(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

// Creates a byte array of 32 bytes from a u64
// Note that this representation is big-endian, and
// places the bits to the back of the output byte_array.
fn byte_arr_from_u64_suffix(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[24..32].clone_from_slice(&input_arr[..8]);
    output_arr
}

/// This test tests get_bit_at on a small label of len 4.
/// The label is logically equal to the binary string "1010"
/// and should return the corresponding bits.
#[test]
pub fn test_get_bit_at_small() {
    let val = 0b1010u64 << 60;
    let expected = vec![1, 0, 1, 0];
    let label = NodeLabel::new(byte_arr_from_u64(val), 4);
    for (index, item) in expected.iter().enumerate().take(4) {
        assert!(
            *item == label.get_bit_at(index as u32),
            "get_bit_at({}) wrong for the 4 digit label 0b1010! Expected {:?} and got {:?}",
            index,
            *item,
            label.get_bit_at(index as u32)
        )
    }
    for index in 4u32..256u32 {
        assert_eq!(
            label.get_bit_at(index),
            0,
            "Index {} should be 0 in a label of length 4 but it doesn't!",
            index
        );
    }
}

/// In this test, we have a label of length 256, logically equal to
/// 1 followed by 255 0s. We want to make sure its 0th bit is read out as 1.
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

// In this test, we have a label of length 256, logically equal to
// 1 followed by 255 0s. We want to make sure its 190th bit is read out as 0.
// We have this because the string itself has only one non-zero bit and we still want
// to check beyond the 0th index.
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

/// This test creates a label of length 256 logically equal to
/// "0000 0000 0000 0000 1010 0000" followed by all 0s. We know that the
/// first non-zero bit is at position 16, and we want to check that.
#[test]
pub fn test_get_bit_at_large() {
    let mut val = [0u8; 32];
    // 128u8 = 0b1000 0000u8 and 32u8 = 0b10 0000u8, hence their
    // sum is "1010 0000"
    val[2] = 128u8 + 32u8;
    // create the label
    let label = NodeLabel::new(val, 256);
    // val[2] is positions 16-23 (both included),
    // so we want to check everything till there.
    let expected = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
    ];

    // the vector expected covers the first 24 indices.
    for (index, item) in expected.iter().enumerate().take(24) {
        let index_32 = index as u32;
        assert!(
            *item == label.get_bit_at(index_32),
            "get_bit_at({}) wrong for the 256 digit label 0000 0000 0000 0000 1010 0000! Expected {:?} and got {:?}",
            index,
            *item,
            label.get_bit_at(index_32)
        )
    }
    // Everything after the first 24 indixes is 0
    for index in 24..256 {
        let index_32 = index as u32;
        assert!(
            0 == label.get_bit_at(index_32),
            "get_bit_at({}) wrong for the 256 digit label 0000 0000 0000 0000 1010 0000! Expected {:?} and got {:?}",
            index,
            0,
            label.get_bit_at(index_32)
        )
    }
}

/// This test is testing our helper function byte_arr_from_u64, which
/// we mainly use for testing. Still we want it to be correct!
/// We call it "small" since it only tests what would
/// result in 1 non-zero byte.
#[test]
pub fn test_byte_arr_from_u64_small() {
    // This val is 2 copies of "10" followed by all 0s.
    // This should be converted into the byte array of all 0s
    // but with the first two byte 0b10100000u8.
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

/// This test is testing our helper function byte_arr_from_u64, which
/// we mainly use for testing. Still we want it to be correct!
/// It is only testing for 2 non-zero bytes.
#[test]
pub fn test_byte_arr_from_u64_medium() {
    // This val is 6 copies of "10" followed by all 0s.
    // This should be converted into the byte array of all 0s
    // but with the first two bytes 0b10101010u8 and 0b10100000u8.
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

/// This test is testing our helper function byte_arr_from_u64, which
/// we mainly use for testing. Still we want it to be correct!
/// It is only testing for 3 non-zero bytes.
#[test]
pub fn test_byte_arr_from_u64_larger() {
    // This string was hand-generated for testing so that
    // all three non-zero bytes were distinct.
    let val = 0b01011010101101010101010u64 << 41;
    let mut expected = [0u8; 32];
    expected[0] = 0b01011010u8;
    expected[1] = 0b10110101u8;
    expected[2] = 0b01010100u8;

    let computed = byte_arr_from_u64(val);
    assert!(
        expected == computed,
        "Byte from u64 conversion wrong for larger, ~3 byte u64! Expected {:?} and got {:?}",
        expected,
        computed
    )
}

/// Test two NodeLabels for equality, when their leading bit is 1.
#[test]
pub fn test_node_label_equal_leading_one() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    assert!(
        label_1 == label_2,
        "Identical labels with leading one not found equal!"
    )
}

/// Test two NodeLabels for equality, when their leading bit is 0.
#[test]
pub fn test_node_label_equal_leading_zero() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(100000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
    assert!(
        label_1 == label_2,
        "Identical labels with leading zero not found equal!"
    )
}

/// Test two NodeLabels for inequality, when their leading bit is 1.
#[test]
pub fn test_node_label_unequal_values() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(110000000u64), 9u32);
    assert!(label_1 != label_2, "Unequal labels found equal!")
}

/// Test two NodeLabels for inequality due to differing length, when their leading bit is 1.
#[test]
pub fn test_node_label_equal_values_unequal_len() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
    assert!(
        label_1 != label_2,
        "Identical labels with unequal lengths not found equal!"
    )
}

/// Test for get_longest_common_prefix between a label and itself being itself. Leading 1.
#[test]
pub fn test_node_label_lcp_with_self_leading_one() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with self with leading one, not equal to itself!"
    )
}

/// Test for get_longest_common_prefix between a label and a zero-length node label.
#[test]
pub fn test_node_label_lcp_with_zero_length_label() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0u64), 0u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0u64), 2u32);
    let expected = label_1;
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with zero-length label, not equal to zero-length label!"
    );
    assert!(
        label_2.get_longest_common_prefix(label_1) == expected,
        "Longest common substring with zero-length label, not equal to zero-length label!"
    );
}

/// Test for get_longest_common_prefix between a label and its prefix.
#[test]
pub fn test_node_label_lcp_with_prefix_label() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(01u64 << 62), 2u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(01u64 << 62), 3u32);
    let expected = label_1;
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with prefix label, not equal to prefix label!"
    );
    assert!(
        label_2.get_longest_common_prefix(label_1) == expected,
        "Longest common substring with prefix label, not equal to prefix label!"
    );
}

/// Test for get_longest_common_prefix between a label and itself being itself. Leading 0.
#[test]
pub fn test_node_label_lcp_with_self_leading_zero() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with self with leading zero, not equal to itself!"
    )
}

/// Test for get_longest_common_prefix between a label and a prefix of this label. Leading 1.
#[test]
pub fn test_node_label_lcp_self_prefix_leading_one() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b1000u64 << 60), 4u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1000u64 << 60), 4u32);
    let computed = label_1.get_longest_common_prefix(label_2);
    assert!(
        computed == expected,
        "Longest common substring with self with leading one, not equal to itself! Expected: {:?}, Got: {:?}",
        expected, computed
    )
}

/// Test for get_longest_common_prefix between a label and a prefix of this label. Leading 0.
#[test]
pub fn test_node_label_lcp_self_prefix_leading_zero() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 7u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 7u32);
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with self with leading zero, not equal to itself!"
    )
}

/// Test for get_longest_common_prefix between two labels starting at the bit 1.
#[test]
pub fn test_node_label_lcp_other_one() {
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

/// Test for get_longest_common_prefix between two labels starting at the bits 01.
#[test]
pub fn test_node_label_lcp_other_zero() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1u64 << 62), 2u32);
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with other with leading zero, not equal to expected!"
    )
}

/// Test for get_longest_common_prefix between two labels which have no common prefix.
#[test]
pub fn test_node_label_lcp_empty() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b0u64), 0u32);
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring should be empty!"
    )
}

/// Test for get_longest_common_prefix between two labels starting at the bits 1101.
#[test]
pub fn test_node_label_lcp_some_leading_one() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32);
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with other with leading one, not equal to expected!"
    )
}

/// Test for get_longest_common_prefix between two labels starting at the bits 01101.
#[test]
pub fn test_node_label_lcp_some_leading_zero() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 59), 5u32);
    assert!(
        label_1.get_longest_common_prefix(label_2) == expected,
        "Longest common substring with other with leading zero, not equal to expected!"
    )
}

/// Test for get_longest_common_prefix_and_dirs with leading bit 0, where the lcp is equal to neither
/// label and hence both self and other get directions with respect to the lcp. Lcp has leading bit 0.
#[test]
pub fn test_node_label_lcp_dirs_some_leading_zero() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 55), 9u32);
    let expected = (
        NodeLabel::new(byte_arr_from_u64(0b1101u64 << 59), 5u32),
        // label_2 should go to the right
        Direction::Right,
        // label_1 should go to the left
        Direction::Left,
    );
    let computed = label_1.get_longest_common_prefix_and_dirs(label_2);
    assert!(
    computed == expected,
    "Longest common substring or direction with other with leading zero, not equal to expected!"
)
}

/// Test for get_longest_common_prefix_and_dirs with leading bit 0, where the lcp is equal to neither
/// label and hence both self and other get directions with respect to the lcp. Lcp has leading bit 1.
#[test]
pub fn test_node_label_lcp_dirs_some_leading_one() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
    let expected = (
        NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32),
        // label_2 should go right
        Direction::Right,
        // label_1 should go left
        Direction::Left,
    );
    let computed = label_1.get_longest_common_prefix_and_dirs(label_2);
    assert!(
    computed == expected,
    "Longest common substring or direction with other with leading zero, not equal to expected!"
)
}

/// Test for get_longest_common_prefix_and_dirs with leading bit 1, where the lcp is equal to one of
/// the queried labels.
#[test]
pub fn test_node_label_lcp_dirs_self_leading_one() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
    let expected = (
        NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32),
        // label_2 includes a 1 appended to label_1
        Direction::Right,
        // label_1 is the lcp
        Direction::None,
    );
    let computed = label_1.get_longest_common_prefix_and_dirs(label_2);
    assert!(
        computed == expected,
        "Longest common substring or direction with other with leading zero, not equal to expected! Computed = {:?} and expected = {:?}",
        computed, expected
    )
}

/// This test tests get_dir by manually computing the prefix and the bit
/// immediately following the prefix of that length.
#[test]
pub fn test_get_dir_large() {
    for i in 0..257 {
        let label_1 = random_label();
        let pos = i;
        // if prefix is of len 256, this will get the entire random string
        let label_2 = label_1.get_prefix(pos);
        // if the prefix is of length pos, then we want to get the prefix in that position, since the
        // label's value is indexed on 0, so the bit following the prefix of len "pos" is at position pos.
        let mut direction = Direction::try_from(label_1.get_bit_at(pos)).unwrap();
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

/// This test just serves as another example of get_dir and this time we want to use little endian encoding
/// since we are using more complex u64 values.
#[test]
pub fn test_get_dir_example() {
    // 23 in little endian is 10111 and 10049430782486799941u64 begins with
    // the prefix 00110100, hence, label_1 is not a prefix of label_2.
    let label_1 = NodeLabel::new(byte_arr_from_u64_le(10049430782486799941u64), 64u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64_le(23u64), 5u32);
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

/// This test gets a prefix for a hard-coded random string and makes sure it is equal to a hand-computed value.
#[test]
pub fn test_get_prefix_small() {
    let label_1 = NodeLabel::new(
        byte_arr_from_u64(0b1000101101110110110000000000110101110001000000000110011001000101u64),
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

/// Test for the function get_sibling_prefix.
#[test]
pub fn test_get_sibling_prefix() {
    let label0 = NodeLabel::new(byte_arr_from_u64(0b0 << 63), 1);
    let label0_sibling = NodeLabel::new(byte_arr_from_u64(0b1 << 63), 1);

    assert!(label0.get_sibling_prefix(1) == label0_sibling);

    let label1 = NodeLabel::new(byte_arr_from_u64(0b1 << 63), 1);
    let label1_sibling = NodeLabel::new(byte_arr_from_u64(0b0 << 63), 1);

    assert!(label1.get_sibling_prefix(1) == label1_sibling);

    // Our hand-coded random string to be parsed with len 30
    let label_rand_len_30 = NodeLabel::new(
        byte_arr_from_u64(0b1010000000000110001111001000001000001000110100101010111111001110u64),
        30,
    );
    // Another hand-coded random string of length 15 with common prefix 1010 0000 0000 01
    // with label_rand_len_30 and the next bit after this should be flipped and hence 0.
    let label_rand_len_30_prefix_15_sibling =
        NodeLabel::new(byte_arr_from_u64(0b10100000000001u64 << 50), 15);
    // The prefix with len 15 of label_rand_len_30 is 1000000000011 and to get a
    // sibling of len 15, we replace it with 1010000000010
    assert!(label_rand_len_30.get_sibling_prefix(15) == label_rand_len_30_prefix_15_sibling);

    let label_rand_len_256 = NodeLabel::new(
        byte_arr_from_u64_suffix(
            0b1010000000000110001111001000001000001000110100101010111111001110u64,
        ),
        256,
    );

    // Only the last bit is flipped!
    let label_rand_len_256_prefix_256_sibling = NodeLabel::new(
        byte_arr_from_u64_suffix(
            0b1010000000000110001111001000001000001000110100101010111111001111u64,
        ),
        256,
    );

    assert!(label_rand_len_256.get_sibling_prefix(256) == label_rand_len_256_prefix_256_sibling);
}

#[test]
pub fn test_is_prefix_of() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b01u64 << 62), 4u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b010u64 << 61), 5u32);
    let label_3 = NodeLabel::new(byte_arr_from_u64(0b0u64), 4u32);

    // empty label is prefix of all labels
    assert_eq!(EMPTY_LABEL.is_prefix_of(&label_1), true);
    assert_eq!(EMPTY_LABEL.is_prefix_of(&label_2), true);
    assert_eq!(EMPTY_LABEL.is_prefix_of(&label_3), true);

    // every label is a prefix of itself
    assert_eq!(label_1.is_prefix_of(&label_1), true);
    assert_eq!(label_2.is_prefix_of(&label_2), true);
    assert_eq!(label_3.is_prefix_of(&label_3), true);

    // valid prefixes
    assert_eq!(label_1.is_prefix_of(&label_2), true);

    // invalid prefixes
    assert_eq!(label_1.is_prefix_of(&label_3), false);
    assert_eq!(label_2.is_prefix_of(&label_1), false);
    assert_eq!(label_2.is_prefix_of(&label_3), false);
    assert_eq!(label_3.is_prefix_of(&label_1), false);
    assert_eq!(label_3.is_prefix_of(&label_2), false);
}
