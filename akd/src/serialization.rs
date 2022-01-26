// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::HistoryTreeNodeError;
use serde::{Deserialize, Serialize};
use winter_crypto::{Digest, Hasher};
use winter_utils::{Deserializable, Serializable, SliceReader};

/// Converts from &[u8] to H::Digest
pub fn to_digest<H: Hasher>(input: &[u8]) -> Result<H::Digest, HistoryTreeNodeError> {
    H::Digest::read_from(&mut SliceReader::new(input))
        .map_err(|_| HistoryTreeNodeError::SerializationError)
}

/// Converts from H::Digest to Vec<u8>
pub fn from_digest<H: Hasher>(input: H::Digest) -> Result<Vec<u8>, HistoryTreeNodeError> {
    let mut output = vec![];
    input.write_into(&mut output);
    Ok(output)
}

/// A serde serializer for the type `winter_crypto::Digest`
pub fn digest_serialize<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Digest,
{
    x.as_bytes().serialize(s)
}

/// A serde deserializer for the type `winter_crypto::Digest`
pub fn digest_deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Digest,
{
    let buf = <[u8; 32]>::deserialize(deserializer)?;
    T::read_from(&mut SliceReader::new(&buf)).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
