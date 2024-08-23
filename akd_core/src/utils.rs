// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Utility functions

#[cfg(feature = "nostd")]
use alloc::vec::Vec;

/// This array is: [2, 4, 16, 256, 65536, 2^32] and is used in get_marker_versions() as
/// an efficiency optimization
const MARKER_VERSION_SKIPLIST: [u64; 7] = [1, 1 << 1, 1 << 2, 1 << 4, 1 << 8, 1 << 16, 1 << 32];

/// a list of past marker versions used by history proofs
pub type PastMarkerVersions = Vec<u64>;

/// a list of future marker versions used by history proofs
pub type FutureMarkerVersions = Vec<u64>;

/// Retrieve log_2 of the marker version, referring to the exponent
/// of the largest power of two that is at most the input version
/// Note: This will panic if called on version = 0
pub(crate) fn get_marker_version_log2(version: u64) -> u64 {
    assert!(
        version != 0,
        "get_marker_version_log2 called with version = 0"
    );
    64 - (version.leading_zeros() as u64) - 1
}

/// Returns the position of the first 1 in the binary representation of the input
fn get_bit_length(input: u64) -> u64 {
    let leading_zeros = input.leading_zeros() as u64;
    if leading_zeros > 64 {
        panic!("get_bit_length input has more than 64 leading zeros");
    }
    64 - leading_zeros
}

/// Return two (possibly empty) lists of marker versions, given
/// a start_version and end_version for the range of update proofs, along with
/// a final epoch.
///
/// The first list contains versions which should be checked for membership,
/// and the second list contains versions which should be checked for non-membership.
///
/// Roughly, the intervals should be organized as follows:
/// 1 --- { previous marker versions } --- [start_version, end_version] --- { future marker versions } --- epoch
///
/// This function also assumes that start_version <= end_version <= epoch. This will panic if start_version = 0.
///
/// The past marker versions are determined as follows:
///
/// 1. Include the largest power of 2 that is less than start_version.
/// 2. Include the largest element of MARKER_VERSION_SKIPLIST that is less than start_version.
/// 3. Include at most a log_2(start_version) number of versions between start_version and the
///    largest power of 2 less than start_version, determined as follows: For each bit position i
///    in start_version, if the bit is 1, include the value of start_version with the ith bit set
///    to 0 and followed by trailing zeros.
///
/// As a concrete example, if start_version = 85, the past marker versions would be [16, 64, 80, 84].
/// Since:
/// 01010101 => 85
/// 01010100 => 84
/// 01010000 => 80
/// 01000000 => 64
///
/// And 16 comes from MARKER_VERSION_SKIPLIST.
///
/// The future marker versions are determined as follows:
///
/// 1. Include all powers of 2 that begin from start_version, up until the smallest element in
///    MARKER_VERSION_SKIPLIST that is greater than start_version.
/// 2. Include all elements of MARKER_VERSION_SKIPLIST that are between start_version and epoch.
/// 3. Include at most a log_2(start_version) number of versions between start_version and the
///    smallest power of 2 greater than start_version, determined as follows: For each bit position i
///    in start_version, if the bit is 0, include the value of start_version with the ith bit set
///    to 1 and followed by trailing zeros.
///
/// As a concrete example, if start_version = 85, the future marker versions would be
/// [86, 88, 96, 128, 256, 65536, 2^32] (potentially truncated depending on if any of these
/// numbers exceed epoch).
///
/// Since:
/// 01010101 => 85
/// 01010110 => 86
/// 01011000 => 88
/// 01100000 => 96
/// 10000000 => 128
///
/// And the remainder of the list comes from MARKER_VERSION_SKIPLIST.
///
/// Note that the past marker versions do not contain start_version, as this would be redundant
/// in the history proof (since membership is already checked for start_version).
pub fn get_marker_versions(
    start_version: u64,
    end_version: u64,
    epoch: u64,
) -> (PastMarkerVersions, FutureMarkerVersions) {
    // Compute past marker versions
    let mut past_marker_versions: Vec<u64> = Vec::new();

    let skiplist_past_index: usize = find_max_index_in_skiplist(start_version);
    if MARKER_VERSION_SKIPLIST[skiplist_past_index] != start_version {
        past_marker_versions.push(MARKER_VERSION_SKIPLIST[skiplist_past_index]);
    }
    let start_version_log2 = 1 << get_marker_version_log2(start_version);
    if start_version_log2 != start_version
        && (past_marker_versions.is_empty()
            || start_version_log2 != past_marker_versions[past_marker_versions.len() - 1])
    {
        past_marker_versions.push(start_version_log2);
    }

    let start_version_length = get_bit_length(start_version);
    for i in (0..start_version_length).rev() {
        let shift = 1 << i;
        // Check if the bit of start_version at position i is 1
        if start_version & shift != 0 {
            let shift_mask = (shift - 1) | shift;
            let past_version = start_version & !shift_mask;
            if past_version != 0
                && (past_marker_versions.is_empty()
                    || past_version != past_marker_versions[past_marker_versions.len() - 1])
            {
                past_marker_versions.push(past_version);
            }
        }
    }

    // Compute future marker versions
    let mut future_marker_versions: Vec<u64> = Vec::new();

    let end_version_length = get_bit_length(end_version);
    let mut future_version: u64 = end_version;
    for i in 0..end_version_length {
        let shift = 1 << i;
        // Check if the bit of end_version at position i is 0
        if end_version & shift == 0 {
            future_version |= shift;
            future_version &= !(shift - 1);
            if future_version <= epoch {
                future_marker_versions.push(future_version);
            }
        }
    }

    let endv_index: usize = find_max_index_in_skiplist(end_version);
    let epoch_index: usize = find_max_index_in_skiplist(epoch);
    let skiplist_slice = &MARKER_VERSION_SKIPLIST[endv_index + 1_usize..epoch_index + 1_usize];

    let next_marker_log2 = get_marker_version_log2(end_version) + 1;
    let final_marker_log2 = get_marker_version_log2(epoch);
    for i in next_marker_log2..(final_marker_log2 + 1) {
        let val = 1 << i;
        if !skiplist_slice.is_empty() && val >= skiplist_slice[0] {
            // Don't need to add any more powers of 2, can just append the skiplist slice
            break;
        }
        future_marker_versions.push(1 << i);
    }
    future_marker_versions.extend_from_slice(skiplist_slice);

    (past_marker_versions, future_marker_versions)
}

// Given an input u64 and a sorted array of u64s, find the largest index for which
// the corresponding array element is less than the input.
//
// This implementation performs a linear search over the MARKER_VERSION_SKIPLIST array,
// but since it is sorted, it could be faster to do a binary search. However, given that
// the array is small, there shouldn't be too much of a difference
// between a binary search and a linear one. But if this ends up being problematic
// in the future, it could certainly be optimized.
//
// Note that if the input is less than the smallest element of the array, then this
// function will panic.
fn find_max_index_in_skiplist(input: u64) -> usize {
    if input < MARKER_VERSION_SKIPLIST[0] {
        panic!("find_max_index_in_skiplist called with input less than smallest element of MARKER_VERSION_SKIPLIST");
    }
    let mut i = 0;
    while i < MARKER_VERSION_SKIPLIST.len() {
        if input < MARKER_VERSION_SKIPLIST[i] {
            break;
        }
        i += 1;
    }
    i - 1
}

/// Corresponds to the I2OSP() function from RFC8017, prepending the length of
/// a byte array to the byte array (so that it is ready for serialization and hashing)
///
/// Input byte array cannot be > 2^64-1 in length
pub fn i2osp_array(input: &[u8]) -> Vec<u8> {
    [&(input.len() as u64).to_be_bytes(), input].concat()
}

/// Serde serialization helpers
#[cfg(feature = "serde_serialization")]
pub mod serde_helpers {
    use hex::{FromHex, ToHex};
    use serde::Deserialize;

    use crate::AzksValue;

    /// A serde hex serializer for bytes
    pub fn bytes_serialize_hex<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<[u8]>,
    {
        let hex_str = &x.as_ref().encode_hex_upper::<String>();
        s.serialize_str(hex_str)
    }

    /// A serde hex deserializer for bytes
    pub fn bytes_deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: AsRef<[u8]> + FromHex,
        <T as FromHex>::Error: core::fmt::Display,
    {
        let hex_str = String::deserialize(deserializer)?;
        T::from_hex(hex_str).map_err(serde::de::Error::custom)
    }

    /// Serialize a digest
    pub fn azks_value_hex_serialize<S>(x: &AzksValue, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        bytes_serialize_hex(&x.0, s)
    }

    /// Deserialize an [AzksValue]
    pub fn azks_value_hex_deserialize<'de, D>(deserializer: D) -> Result<AzksValue, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(AzksValue(bytes_deserialize_hex(deserializer)?))
    }

    /// Serialize a digest
    pub fn azks_value_serialize<S>(x: &AzksValue, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde_bytes::Serialize;
        x.0.to_vec().serialize(s)
    }

    /// Deserialize an [AzksValue]
    pub fn azks_value_deserialize<'de, D>(deserializer: D) -> Result<AzksValue, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = <Vec<u8> as serde_bytes::Deserialize>::deserialize(deserializer)?;
        Ok(AzksValue(
            crate::hash::try_parse_digest(&buf).map_err(serde::de::Error::custom)?,
        ))
    }
}

#[cfg(feature = "public_tests")]
/// Macro used for running tests with different configurations
/// NOTE(new_config): When adding new configurations, add them here as well
#[macro_export]
macro_rules! test_config_sync {
    ( $x:ident ) => {
        paste::paste! {
            #[cfg(feature = "whatsapp_v1")]
            #[test]
            fn [<$x _ whatsapp_v1_config>]() {
                $x::<$crate::WhatsAppV1Configuration>()
            }

            #[cfg(feature = "experimental")]
            #[test]
            fn [<$x _ experimental_config>]() {
                $x::<$crate::ExperimentalConfiguration<$crate::ExampleLabel>>()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rand::{rngs::OsRng, Rng};

    #[test]
    fn test_get_marker_versions() {
        assert_eq!(
            (vec![16, 64], vec![66, 68, 72, 80, 96, 128]),
            get_marker_versions(65, 65, 128)
        );
        assert_eq!(
            (vec![16, 64, 80, 84], vec![86, 88, 96, 128, 256, 65536]),
            get_marker_versions(85, 85, 65537)
        );
        assert_eq!((vec![], vec![6, 8, 16]), get_marker_versions(1, 5, 33));

        assert_eq!((vec![], vec![6, 8, 16]), get_marker_versions(2, 5, 33));

        assert_eq!((vec![2], vec![6, 8, 16]), get_marker_versions(3, 5, 33));

        assert_eq!((vec![4], vec![13, 14, 16]), get_marker_versions(6, 12, 128));

        assert_eq!(
            (vec![4], vec![13, 14, 16, 256]),
            get_marker_versions(6, 12, 256)
        );

        assert_eq!(
            (vec![16, 128], vec![131, 132, 136, 144, 160, 192, 256]),
            get_marker_versions(130, 130, 256)
        );
    }

    #[derive(Clone)]
    enum RangeType {
        Small,
        Medium,
        Large,
    }

    fn gen_versions(
        rng: &mut OsRng,
        start_type: &RangeType,
        end_type: &RangeType,
        epoch_type: &RangeType,
    ) -> (u64, u64, u64) {
        let small_jump = 10;
        let medium_jump = 1000;
        let start_version: u64 = rng.gen_range(match start_type {
            RangeType::Small => 1..small_jump,
            RangeType::Medium => 1..medium_jump,
            RangeType::Large => 1..u64::MAX - 2 * (small_jump + medium_jump),
        });
        let end_version: u64 = rng.gen_range(match end_type {
            RangeType::Small => start_version..start_version + small_jump,
            RangeType::Medium => start_version..start_version + medium_jump,
            RangeType::Large => start_version..u64::MAX - small_jump - medium_jump,
        });
        let epoch: u64 = rng.gen_range(match epoch_type {
            RangeType::Small => end_version..end_version + small_jump,
            RangeType::Medium => end_version..end_version + medium_jump,
            RangeType::Large => end_version..u64::MAX,
        });
        (start_version, end_version, epoch)
    }

    #[test]
    fn test_marker_version_invariants() {
        // Ensure that all invariants hold for a variety of inputs to get_marker_versions()

        let iterations = 10000;
        let options = [RangeType::Small, RangeType::Medium, RangeType::Large];
        let mut rng = OsRng;
        for (start_type, end_type, epoch_type) in itertools::iproduct!(&options, &options, &options)
        {
            for _ in 0..iterations {
                let (start_version, end_version, epoch) =
                    gen_versions(&mut rng, start_type, end_type, epoch_type);

                let (past_versions, future_versions) =
                    get_marker_versions(start_version, end_version, epoch);

                // Ensure that all past versions are less than the start version
                for version in past_versions.iter() {
                    assert!(version < &start_version);
                }

                // Ensure that all future versions are greater than the end version
                for version in future_versions.iter() {
                    assert!(version > &end_version);
                }

                // Ensure that all future versions are less than or equal to the epoch
                for version in future_versions.iter() {
                    assert!(version <= &epoch);
                }

                // Ensure that all past versions are unique and sorted
                let mut past_versions_sorted = past_versions.clone();
                past_versions_sorted.sort();
                assert!(past_versions_sorted == past_versions);
                past_versions_sorted.dedup();
                assert_eq!(past_versions_sorted.len(), past_versions.len());

                // Ensure that all future versions are unique and sorted
                let mut future_versions_sorted = future_versions.clone();
                future_versions_sorted.sort();
                assert!(future_versions_sorted == future_versions);
                future_versions_sorted.dedup();
                assert_eq!(future_versions_sorted.len(), future_versions.len());
            }
        }
    }
}
