// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Utility functions

#[cfg(feature = "nostd")]
use alloc::vec::Vec;

/// a list of past marker versions used by history proofs
pub type PastMarkerVersions = Vec<u64>;

/// a list of future marker versions used by history proofs
pub type FutureMarkerVersions = Vec<u64>;

/// Retrieve log_2 of the marker version, referring to the exponent
/// of the largest power of two that is at most the input version
/// Note: This will panic if called on version = 0
pub fn get_marker_version_log2(version: u64) -> u64 {
    64 - (version.leading_zeros() as u64) - 1
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
/// In this implementation, the set of previous marker versions consists of the largest power of 2
/// that is at most start_version (or is empty if start_version is already a power of 2). The set of
/// future marker versions is as described in SEEMless: the consecutively increasing set of versions
/// from end_version until the next power of 2, and then all consecutive powers of 2 up until the
/// epoch.
///
/// This will panic if start_version = 0
pub fn get_marker_versions(
    start_version: u64,
    end_version: u64,
    epoch: u64,
) -> (PastMarkerVersions, FutureMarkerVersions) {
    // Compute past marker versions
    let mut past_marker_versions: Vec<u64> = Vec::new();
    let start_marker = 1 << get_marker_version_log2(start_version);
    if start_marker < start_version {
        past_marker_versions.push(start_marker);
    }

    // Compute future marker versions
    let next_marker_log2 = get_marker_version_log2(end_version) + 1;
    let final_marker_log2 = get_marker_version_log2(epoch);
    let mut future_marker_versions: Vec<u64> =
        ((end_version + 1)..(1 << next_marker_log2)).collect();
    for i in next_marker_log2..(final_marker_log2 + 1) {
        future_marker_versions.push(1 << i);
    }

    (past_marker_versions, future_marker_versions)
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

    #[test]
    fn test_get_marker_versions() {
        assert_eq!(
            (vec![], vec![6, 7, 8, 16, 32]),
            get_marker_versions(1, 5, 33)
        );

        assert_eq!(
            (vec![], vec![6, 7, 8, 16, 32]),
            get_marker_versions(2, 5, 33)
        );

        assert_eq!(
            (vec![2], vec![6, 7, 8, 16, 32]),
            get_marker_versions(3, 5, 33)
        );

        assert_eq!(
            (vec![4], vec![13, 14, 15, 16, 32, 64, 128]),
            get_marker_versions(6, 12, 128)
        );

        assert_eq!(
            (vec![4], vec![13, 14, 15, 16, 32, 64]),
            get_marker_versions(6, 12, 127)
        );
    }
}
