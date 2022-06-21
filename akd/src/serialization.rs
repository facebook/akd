// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains serialization calls for helping serialize/deserialize digests

use crate::errors::{AkdError, TreeNodeError};

#[cfg(feature = "serde_serialization")]
use hex::{FromHex, ToHex};
#[cfg(feature = "serde_serialization")]
use serde::{Deserialize, Serialize};
use winter_crypto::{Digest, Hasher};
use winter_utils::{Deserializable, SliceReader};

/// Converts from &[u8] to H::Digest
pub fn to_digest<H: Hasher>(input: &[u8]) -> Result<H::Digest, AkdError> {
    Ok(H::Digest::read_from(&mut SliceReader::new(input))
        .map_err(|msg| TreeNodeError::DigestDeserializationFailed(format!("{}", msg)))?)
}

/// Converts from H::Digest to [u8; 32]
pub fn from_digest<H: Hasher>(input: H::Digest) -> [u8; 32] {
    input.as_bytes()
}

/// A serde serializer for the type `winter_crypto::Digest`
#[cfg(feature = "serde_serialization")]
pub fn digest_serialize<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Digest,
{
    x.as_bytes().serialize(s)
}

/// A serde deserializer for the type `winter_crypto::Digest`
#[cfg(feature = "serde_serialization")]
pub fn digest_deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Digest,
{
    let buf = <[u8; 32]>::deserialize(deserializer)?;
    T::read_from(&mut SliceReader::new(&buf)).map_err(serde::de::Error::custom)
}

/// A serde hex serializer for bytes
#[cfg(feature = "serde_serialization")]
pub fn bytes_serialize_hex<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: AsRef<[u8]>,
{
    let hex_str = &x.as_ref().encode_hex_upper::<String>();
    s.serialize_str(hex_str)
}

/// A serde hex deserializer for bytes
#[cfg(feature = "serde_serialization")]
pub fn bytes_deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: AsRef<[u8]> + FromHex,
    <T as FromHex>::Error: std::fmt::Display,
{
    let hex_str = String::deserialize(deserializer)?;
    T::from_hex(&hex_str).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::directory::Directory;
    use crate::ecvrf::HardCodedAkdVRF;
    use crate::errors::AkdError;
    use crate::proof_structs::{AppendOnlyProof, HistoryProof, LookupProof};
    use crate::storage::memory::AsyncInMemoryDatabase;
    use crate::storage::types::{AkdLabel, AkdValue};
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;
    type Blake3 = Blake3_256<BaseElement>;

    #[derive(Serialize, Deserialize)]
    struct Wrapper<H: Hasher> {
        #[serde(serialize_with = "digest_serialize")]
        #[serde(deserialize_with = "digest_deserialize")]
        digest: H::Digest,
    }

    #[test]
    pub fn serialize_deserialize() {
        use winter_crypto::hashers::Blake3_256;
        use winter_crypto::Hasher;
        use winter_math::fields::f128::BaseElement;

        type Blake3 = Blake3_256<BaseElement>;

        let digest = Blake3::hash(b"hello, world!");
        let wrapper = Wrapper::<Blake3> { digest };
        let serialized = bincode::serialize(&wrapper).unwrap();
        let deserialized: Wrapper<Blake3> = bincode::deserialize(&serialized).unwrap();
        assert_eq!(wrapper.digest, deserialized.digest);
    }

    // Serialization tests for proof structs

    #[tokio::test]
    pub async fn lookup_proof_roundtrip() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();

        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3_256<BaseElement>>(&db, &vrf, false)
            .await
            .unwrap();
        akd.publish::<Blake3_256<BaseElement>>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await
        .unwrap();
        // Generate latest proof
        let lookup_proof = akd
            .lookup::<Blake3_256<BaseElement>>(AkdLabel::from_utf8_str("hello"))
            .await
            .unwrap();

        let serialized = bincode::serialize(&lookup_proof).unwrap();
        let deserialized: LookupProof<Blake3> = bincode::deserialize(&serialized).unwrap();

        assert_eq!(lookup_proof, deserialized);

        Ok(())
    }

    #[tokio::test]
    pub async fn history_proof_roundtrip() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3_256<BaseElement>>(&db, &vrf, false)
            .await
            .unwrap();
        akd.publish::<Blake3_256<BaseElement>>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await
        .unwrap();
        // Generate latest proof
        let history_proof = akd
            .key_history::<Blake3_256<BaseElement>>(&AkdLabel::from_utf8_str("hello"))
            .await
            .unwrap();

        let serialized = bincode::serialize(&history_proof).unwrap();
        let deserialized: HistoryProof<Blake3> = bincode::deserialize(&serialized).unwrap();

        assert_eq!(history_proof, deserialized);

        Ok(())
    }

    #[tokio::test]
    pub async fn audit_proof_roundtrip() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3_256<BaseElement>>(&db, &vrf, false)
            .await
            .unwrap();
        // Commit to the first epoch
        akd.publish::<Blake3_256<BaseElement>>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await
        .unwrap();
        // Commit to the second epoch
        akd.publish::<Blake3_256<BaseElement>>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world3"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world4"),
            ),
        ])
        .await
        .unwrap();
        // Generate audit proof for the evolution from epoch 1 to epoch 2.
        let audit_proof = akd
            .audit::<Blake3_256<BaseElement>>(1u64, 2u64)
            .await
            .unwrap();

        let serialized = bincode::serialize(&audit_proof).unwrap();
        let deserialized: AppendOnlyProof<Blake3> = bincode::deserialize(&serialized).unwrap();

        assert_eq!(audit_proof, deserialized);

        Ok(())
    }
}
