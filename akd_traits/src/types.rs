// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Core types for key directory implementations.

use crate::Digest;

#[cfg(feature = "serde")]
mod serde_helpers {
    use hex::FromHex;

    pub fn bytes_serialize_hex<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<[u8]>,
    {
        use hex::ToHex;
        let hex_str = &x.as_ref().encode_hex_upper::<String>();
        s.serialize_str(hex_str)
    }

    pub fn bytes_deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: AsRef<[u8]> + FromHex,
        <T as FromHex>::Error: core::fmt::Display,
    {
        use serde::Deserialize;
        let hex_str = String::deserialize(deserializer)?;
        T::from_hex(hex_str).map_err(serde::de::Error::custom)
    }
}

/// The label of a particular entry in the key directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DirectoryLabel(
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_helpers::bytes_serialize_hex")
    )]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "serde_helpers::bytes_deserialize_hex")
    )]
    pub Vec<u8>,
);

impl core::ops::Deref for DirectoryLabel {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for DirectoryLabel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::convert::From<&str> for DirectoryLabel {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl core::convert::From<&String> for DirectoryLabel {
    fn from(s: &String) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

#[cfg(feature = "rand")]
impl DirectoryLabel {
    /// Gets a random label
    pub fn random<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes.to_vec())
    }
}

/// The value of a particular entry in the key directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DirectoryValue(
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serde_helpers::bytes_serialize_hex")
    )]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "serde_helpers::bytes_deserialize_hex")
    )]
    pub Vec<u8>,
);

impl core::ops::Deref for DirectoryValue {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for DirectoryValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::convert::From<&str> for DirectoryValue {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl core::convert::From<&String> for DirectoryValue {
    fn from(s: &String) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

#[cfg(feature = "rand")]
impl DirectoryValue {
    /// Gets a random value
    pub fn random<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes.to_vec())
    }
}

/// Root hash of the tree and its associated epoch.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EpochHash(pub u64, pub Digest);

impl EpochHash {
    /// Get the contained epoch
    pub fn epoch(&self) -> u64 {
        self.0
    }
    /// Get the contained hash
    pub fn hash(&self) -> Digest {
        self.1
    }
}

/// The payload that is outputted as a result of successful verification of
/// a lookup proof or history proof. This includes the fields containing the
/// epoch that the leaf was published in, the version corresponding to the value,
/// and the value itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifyResult {
    /// The epoch of this record
    pub epoch: u64,
    /// Version at this update
    pub version: u64,
    /// The plaintext value associated with the record
    pub value: DirectoryValue,
}
