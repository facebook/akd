// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Tests for node labels

use super::*;
use crate::test_config_sync;
#[cfg(feature = "nostd")]
use alloc::vec;
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

// This test tests get_bit_at on a small label of len 4.
// The label is logically equal to the binary string "1010"
// and should return the corresponding bits.
#[test]
fn test_get_bit_at_small() {
    let val = 0b1010u64 << 60;
    let expected = vec![Bit::One, Bit::Zero, Bit::One, Bit::Zero];
    let label = NodeLabel::new(byte_arr_from_u64(val), 4);
    for (index, item) in expected.iter().enumerate().take(4) {
        assert!(
            *item == label.get_bit_at(index as u32).unwrap(),
            "get_bit_at({}) wrong for the 4 digit label 0b1010! Expected {:?} and got {:?}",
            index,
            *item,
            label.get_bit_at(index as u32)
        )
    }
    for index in 4u32..256u32 {
        assert!(
            label.get_bit_at(index).is_err(),
            "Index {index} should be out of range"
        );
    }
}

// In this test, we have a label of length 256, logically equal to
// 1 followed by 255 0s. We want to make sure its 0th bit is read out as 1.
#[test]
fn test_get_bit_at_medium_1() {
    let val = 0b1u64 << 63;
    let expected = Bit::One;
    let label = NodeLabel::new(byte_arr_from_u64(val), 256);
    let computed = label.get_bit_at(0).unwrap();
    assert!(
        expected == computed,
        "{}",
        "get_bit_at(2) wrong for the 4 digit label 10! Expected {expected:?} and got {computed:?}"
    )
}

// In this test, we have a label of length 256, logically equal to
// 1 followed by 255 0s. We want to make sure its 190th bit is read out as 0.
// We have this because the string itself has only one non-zero bit and we still want
// to check beyond the 0th index.
#[test]
fn test_get_bit_at_medium_2() {
    let val = 0b1u64 << 63;
    let expected = Bit::Zero;
    let label = NodeLabel::new(byte_arr_from_u64(val), 256);
    let computed = label.get_bit_at(190).unwrap();
    assert!(
        expected == computed,
        "{}",
        "get_bit_at(2) wrong for the 4 digit label 10! Expected {expected:?} and got {computed:?}"
    )
}

// This test creates a label of length 256 logically equal to
// "0000 0000 0000 0000 1010 0000" followed by all 0s. We know that the
// first non-zero bit is at position 16, and we want to check that.
#[test]
fn test_get_bit_at_large() {
    let mut val = [0u8; 32];
    // 128u8 = 0b1000 0000u8 and 32u8 = 0b10 0000u8, hence their
    // sum is "1010 0000"
    val[2] = 128u8 + 32u8;
    // create the label
    let label = NodeLabel::new(val, 256);
    // val[2] is positions 16-23 (both included),
    // so we want to check everything till there.
    let expected_raw = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
    ];
    let expected = expected_raw
        .iter()
        .map(|x| if *x == 0 { Bit::Zero } else { Bit::One })
        .collect::<Vec<Bit>>();

    // the vector expected covers the first 24 indices.
    for (index, item) in expected.iter().enumerate().take(24) {
        let index_32 = index as u32;
        assert!(
            *item == label.get_bit_at(index_32).unwrap(),
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
            Bit::Zero == label.get_bit_at(index_32).unwrap(),
            "get_bit_at({}) wrong for the 256 digit label 0000 0000 0000 0000 1010 0000! Expected {:?} and got {:?}",
            index,
            Bit::Zero,
            label.get_bit_at(index_32)
        )
    }
}

// This test is testing our helper function byte_arr_from_u64, which
// we mainly use for testing. Still we want it to be correct!
// We call it "small" since it only tests what would
// result in 1 non-zero byte.
#[test]
fn test_byte_arr_from_u64_small() {
    // This val is 2 copies of "10" followed by all 0s.
    // This should be converted into the byte array of all 0s
    // but with the first two byte 0b10100000u8.
    let val = 0b1010u64 << 60;
    let mut expected = [0u8; 32];
    expected[0] = 0b10100000u8;
    let computed = byte_arr_from_u64(val);
    assert!(
        expected == computed,
        "{}",
        "Byte from u64 conversion wrong for small u64! Expected {expected:?} and got {computed:?}"
    )
}

// This test is testing our helper function byte_arr_from_u64, which
// we mainly use for testing. Still we want it to be correct!
// It is only testing for 2 non-zero bytes.
#[test]
fn test_byte_arr_from_u64_medium() {
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
        "{}", "Byte from u64 conversion wrong for medium, ~2 byte u64! Expected {expected:?} and got {computed:?}"
    )
}

// This test is testing our helper function byte_arr_from_u64, which
// we mainly use for testing. Still we want it to be correct!
// It is only testing for 3 non-zero bytes.
#[test]
fn test_byte_arr_from_u64_larger() {
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
        "{}", "Byte from u64 conversion wrong for larger, ~3 byte u64! Expected {expected:?} and got {computed:?}"
    )
}

// Test two NodeLabels for equality, when their leading bit is 1.
#[test]
fn test_node_label_equal_leading_one() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    assert!(
        label_1 == label_2,
        "Identical labels with leading one not found equal!"
    )
}

// Test two NodeLabels for equality, when their leading bit is 0.
#[test]
fn test_node_label_equal_leading_zero() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(100000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
    assert!(
        label_1 == label_2,
        "Identical labels with leading zero not found equal!"
    )
}

// Test two NodeLabels for inequality, when their leading bit is 1.
#[test]
fn test_node_label_unequal_values() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(110000000u64), 9u32);
    assert!(label_1 != label_2, "Unequal labels found equal!")
}

// Test two NodeLabels for inequality due to differing length, when their leading bit is 1.
#[test]
fn test_node_label_equal_values_unequal_len() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
    assert!(
        label_1 != label_2,
        "Identical labels with unequal lengths not found equal!"
    )
}

// Test for get_longest_common_prefix between a label and itself being itself. Leading 1.
test_config_sync!(test_node_label_lcp_with_self_leading_one);
fn test_node_label_lcp_with_self_leading_one<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with self with leading one, not equal to itself!"
    )
}

// Test for get_longest_common_prefix between a label and a zero-length node label.
test_config_sync!(test_node_label_lcp_with_zero_length_label);
fn test_node_label_lcp_with_zero_length_label<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0u64), 0u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0u64), 2u32);
    let expected = label_1;
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with zero-length label, not equal to zero-length label!"
    );
    assert!(
        label_2.get_longest_common_prefix::<TC>(label_1) == expected,
        "Longest common substring with zero-length label, not equal to zero-length label!"
    );
}

// Test for get_longest_common_prefix between a label and its prefix.
test_config_sync!(test_node_label_lcp_with_prefix_label);
fn test_node_label_lcp_with_prefix_label<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(01u64 << 62), 2u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(01u64 << 62), 3u32);
    let expected = label_1;
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with prefix label, not equal to prefix label!"
    );
    assert!(
        label_2.get_longest_common_prefix::<TC>(label_1) == expected,
        "Longest common substring with prefix label, not equal to prefix label!"
    );
}

// Test for get_longest_common_prefix between a label and itself being itself. Leading 0.
test_config_sync!(test_node_label_lcp_with_self_leading_zero);
fn test_node_label_lcp_with_self_leading_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with self with leading zero, not equal to itself!"
    )
}

// Test for get_longest_common_prefix between a label and a prefix of this label. Leading 1.
test_config_sync!(test_node_label_lcp_self_prefix_leading_one);
fn test_node_label_lcp_self_prefix_leading_one<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b1000u64 << 60), 4u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1000u64 << 60), 4u32);
    let computed = label_1.get_longest_common_prefix::<TC>(label_2);
    assert!(
        computed == expected,
        "{}", "Longest common substring with self with leading one, not equal to itself! Expected: {expected:?}, Got: {computed:?}"
    )
}

// Test for get_longest_common_prefix between a label and a prefix of this label. Leading 0.
test_config_sync!(test_node_label_lcp_self_prefix_leading_zero);
fn test_node_label_lcp_self_prefix_leading_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 7u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 7u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with self with leading zero, not equal to itself!"
    )
}

// Test for get_longest_common_prefix between two labels starting at the bit 1.
test_config_sync!(test_node_label_lcp_other_one);
fn test_node_label_lcp_other_one<TC: Configuration>() {
    let label_1: NodeLabel = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32);
    let computed = label_1.get_longest_common_prefix::<TC>(label_2);
    assert!(
        computed == expected,
        "{}", "Longest common substring with other with leading one, not equal to expected! Expected: {expected:?}, Computed: {computed:?}"
    )
}

// Test for get_longest_common_prefix between two labels starting at the bits 01.
test_config_sync!(test_node_label_lcp_other_zero);
fn test_node_label_lcp_other_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1u64 << 62), 2u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with other with leading zero, not equal to expected!"
    )
}

// Test for get_longest_common_prefix between two labels which have no common prefix.
test_config_sync!(test_node_label_lcp_empty);
fn test_node_label_lcp_empty<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b0u64), 0u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring should be empty!"
    )
}

// Test for get_longest_common_prefix between two labels starting at the bits 1101.
test_config_sync!(test_node_label_lcp_some_leading_one);
fn test_node_label_lcp_some_leading_one<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with other with leading one, not equal to expected!"
    )
}

// Test for get_longest_common_prefix between two labels starting at the bits 01101.
test_config_sync!(test_node_label_lcp_some_leading_zero);
fn test_node_label_lcp_some_leading_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 59), 5u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with other with leading zero, not equal to expected!"
    )
}

// This test tests get_dir by manually computing the prefix and the bit
// immediately following the prefix of that length.
test_config_sync!(test_get_dir_large);
fn test_get_dir_large<TC: Configuration>() {
    for i in 0..256 {
        let label_1 = random_label();
        let pos = i;
        // if prefix is of len 256, this will get the entire random string
        let label_2 = label_1.get_prefix(pos);
        // if the prefix is of length pos, then we want to get the prefix in that position, since the
        // label's value is indexed on 0, so the bit following the prefix of len "pos" is at position pos.
        let expected = PrefixOrdering::from(label_1.get_bit_at(pos).unwrap());
        let computed = label_2.get_prefix_ordering(label_1);
        assert!(
            computed == expected,
            "{}",
            "Direction not equal to expected. Node = {label_1:?}, prefix = {label_2:?}"
        )
    }
}

// This test just serves as another example of get_dir and this time we want to use little endian encoding
// since we are using more complex u64 values.
#[test]
fn test_get_dir_example() {
    // 23 in little endian is 10111 and 10049430782486799941u64 begins with
    // the prefix 00110100, hence, label_1 is not a prefix of label_2.
    let label_1 = NodeLabel::new(byte_arr_from_u64_le(10049430782486799941u64), 64u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64_le(23u64), 5u32);
    let expected = PrefixOrdering::Invalid;
    let computed = label_2.get_prefix_ordering(label_1);
    assert!(
        computed == expected,
        "{}", "Direction not equal to expected. Node = {label_1:?}, prefix = {label_2:?}, computed = {computed:?}"
    )
}

// This test gets a prefix for a hard-coded random string and makes sure it is equal to a hand-computed value.
#[test]
fn test_get_prefix_small() {
    let label_1 = NodeLabel::new(
        byte_arr_from_u64(0b1000101101110110110000000000110101110001000000000110011001000101u64),
        64u32,
    );
    let prefix_len = 10u32;
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b1000101101u64 << 54), prefix_len);
    let computed = label_1.get_prefix(prefix_len);
    assert!(
        computed == label_2,
        "{}", "Direction not equal to expected. Node = {label_1:?}, prefix = {label_2:?}, computed = {computed:?}"
    )
}

test_config_sync!(test_is_prefix_of);
fn test_is_prefix_of<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b01u64 << 62), 4u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b010u64 << 61), 5u32);
    let label_3 = NodeLabel::new(byte_arr_from_u64(0b0u64), 4u32);

    // empty label is prefix of all labels
    assert_eq!(TC::empty_label().is_prefix_of(&label_1), true);
    assert_eq!(TC::empty_label().is_prefix_of(&label_2), true);
    assert_eq!(TC::empty_label().is_prefix_of(&label_3), true);

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

// This test gets a prefix for a hard-coded random string and makes sure it is equal to a hand-computed value.
#[test]
fn test_get_prefix_ordering_with_invalid_bits() {
    let invalid_label = NodeLabel::new(
        byte_arr_from_u64(0b0000101101110110110000000000110101110001000000000110011001000101u64),
        1u32,
    );

    // Simple test case
    let some_label = NodeLabel::new(byte_arr_from_u64(0u64), 64u32);
    assert_eq!(
        invalid_label.get_prefix_ordering(some_label),
        PrefixOrdering::WithZero
    );

    // Zero-length label should not return PrefixOrdering::Invalid
    let zero_length_invalid_bits_label = NodeLabel::new(byte_arr_from_u64(1), 0);
    assert_eq!(
        zero_length_invalid_bits_label.get_prefix_ordering(some_label),
        PrefixOrdering::WithZero
    );
}
