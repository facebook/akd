// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Utility functions

use crate::hash::Digest;
use crate::{AkdValue, NodeLabel};

#[cfg(feature = "nostd")]
use alloc::vec::Vec;
#[cfg(feature = "rand")]
use rand::{distributions::Alphanumeric, CryptoRng, Rng};

/// Retrieve the marker version
pub fn get_marker_version(version: u64) -> u64 {
    64u64 - (version.leading_zeros() as u64) - 1u64
}

/// Corresponds to the I2OSP() function from RFC8017, prepending the length of
/// a byte array to the byte array (so that it is ready for serialization and hashing)
///
/// Input byte array cannot be > 2^64-1 in length
pub fn i2osp_array(input: &[u8]) -> Vec<u8> {
    [&(input.len() as u64).to_be_bytes(), input].concat()
}

/// Generate a commitproof from the client proof
pub fn generate_commitment_from_proof_client(
    value: &crate::AkdValue,
    proof: &[u8],
) -> crate::hash::Digest {
    crate::hash::hash(&[i2osp_array(value), i2osp_array(proof)].concat())
}

/// Used by the server to produce a commitment proof for an AkdLabel, version, and AkdValue
pub fn get_commitment_proof(commitment_key: &[u8], label: &NodeLabel, value: &AkdValue) -> Digest {
    crate::hash::hash(&[commitment_key, &label.label_val, &i2osp_array(value)].concat())
}

/// Used by the server to produce a commitment for an AkdLabel, version, and AkdValue
///
/// proof = H(commitment_key, label, version, value)
/// commmitment = H(value, proof)
///
/// The proof value is a nonce used to create a hiding and binding commitment using a
/// cryptographic hash function. Note that it is derived from the label, version, and
/// value (even though the binding to value is somewhat optional).
///
/// Note that this commitment needs to be a hash function (random oracle) output
pub fn commit_value(commitment_key: &[u8], label: &NodeLabel, value: &AkdValue) -> Digest {
    let proof = get_commitment_proof(commitment_key, label, value);
    crate::hash::hash(&[i2osp_array(value), i2osp_array(&proof)].concat())
}

/// Used by the client to supply a commitment proof and value to reconstruct the commitment
pub fn bind_commitment(value: &AkdValue, proof: &[u8]) -> Digest {
    crate::hash::hash(&[i2osp_array(value), i2osp_array(proof)].concat())
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
        T::from_hex(&hex_str).map_err(serde::de::Error::custom)
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
