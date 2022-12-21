// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Utility functions

use crate::hash::Digest;
use crate::{AkdLabel, AkdValue, NodeLabel};

#[cfg(feature = "nostd")]
use alloc::vec::Vec;
#[cfg(feature = "rand")]
use rand::{distributions::Alphanumeric, CryptoRng, Rng};

/// Retrieve the marker version
pub fn get_marker_version(version: u64) -> u64 {
    64 - (version.leading_zeros() as u64) - 1
}

/// Corresponds to the I2OSP() function from RFC8017, prepending the length of
/// a byte array to the byte array (so that it is ready for serialization and hashing)
///
/// Input byte array cannot be > 2^64-1 in length
pub fn i2osp_array(input: &[u8]) -> Vec<u8> {
    [&(input.len() as u64).to_be_bytes(), input].concat()
}

/// Used by the client to supply a commitment nonce and value to reconstruct the commitment, via:
/// commitment = H(i2osp_array(value), i2osp_array(nonce))
pub(crate) fn generate_commitment_from_nonce_client(
    value: &crate::AkdValue,
    nonce: &[u8],
) -> crate::hash::Digest {
    crate::hash::hash(&[i2osp_array(value), i2osp_array(nonce)].concat())
}

/// Hash a leaf epoch and proof with a given [AkdValue]
pub(crate) fn hash_leaf_with_value(value: &crate::AkdValue, epoch: u64, proof: &[u8]) -> Digest {
    let commitment = crate::utils::generate_commitment_from_nonce_client(value, proof);
    crate::hash::merge_with_int(commitment, epoch)
}

/// Used by the server to produce a commitment proof for an AkdLabel, version, and AkdValue.
/// Computes nonce = H(commitment key || label || version || i2osp_array(value))
pub fn get_commitment_nonce(
    commitment_key: &[u8],
    label: &NodeLabel,
    version: u64,
    value: &AkdValue,
) -> Digest {
    crate::hash::hash(
        &[
            commitment_key,
            &label.to_bytes(),
            &version.to_be_bytes(),
            &i2osp_array(value),
        ]
        .concat(),
    )
}

/// To convert a regular label (arbitrary string of bytes) into a [NodeLabel], we compute the
/// output as: H(label || stale || version)
///
/// Specifically, we concatenate the following together:
/// - I2OSP(len(label) as u64, label)
/// - A single byte encoded as 0u8 if "stale", 1u8 if "fresh"
/// - A u64 representing the version
/// These are all interpreted as a single byte array and hashed together, with the output
/// of the hash returned.
pub(crate) fn get_hash_from_label_input(label: &AkdLabel, stale: bool, version: u64) -> Vec<u8> {
    let stale_bytes = if stale { &[0u8] } else { &[1u8] };
    let hashed_label = crate::hash::hash(
        &[
            &crate::utils::i2osp_array(label)[..],
            stale_bytes,
            &version.to_be_bytes(),
        ]
        .concat(),
    );
    hashed_label.to_vec()
}

/// Used by the server to produce a commitment for an AkdLabel, version, and AkdValue
///
/// nonce = H(commitment_key, label, version, i2osp_array(value))
/// commmitment = H(i2osp_array(value), i2osp_array(nonce))
///
/// The nonce value is used to create a hiding and binding commitment using a
/// cryptographic hash function. Note that it is derived from the label, version, and
/// value (even though the binding to value is somewhat optional).
///
/// Note that this commitment needs to be a hash function (random oracle) output
pub fn commit_value(
    commitment_key: &[u8],
    label: &NodeLabel,
    version: u64,
    value: &AkdValue,
) -> Digest {
    let nonce = get_commitment_nonce(commitment_key, label, version, value);
    crate::hash::hash(&[i2osp_array(value), i2osp_array(&nonce)].concat())
}

#[cfg(feature = "rand")]
pub(crate) fn get_random_str<R: CryptoRng + Rng>(rng: &mut R) -> String {
    rng.sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Serde serialization helpers
#[cfg(feature = "serde_serialization")]
pub mod serde_helpers {
    use hex::{FromHex, ToHex};
    use serde::Deserialize;

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
    pub fn digest_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde_bytes::Serialize;
        x.to_vec().serialize(s)
    }

    /// Deserialize a digest
    pub fn digest_deserialize<'de, D>(
        deserializer: D,
    ) -> Result<[u8; crate::hash::DIGEST_BYTES], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = <Vec<u8> as serde_bytes::Deserialize>::deserialize(deserializer)?;
        crate::hash::try_parse_digest(&buf).map_err(serde::de::Error::custom)
    }
}
