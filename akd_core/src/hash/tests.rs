// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Tests for hashing

use super::*;

#[cfg(feature = "nostd")]
use alloc::vec;
use rand::{thread_rng, Rng};

fn random_hash() -> [u8; DIGEST_BYTES] {
    let mut results = crate::hash::EMPTY_DIGEST;
    let mut rng = thread_rng();
    for b in results.iter_mut().take(DIGEST_BYTES) {
        *b = rng.gen::<u8>();
    }
    results
}

#[test]
fn test_try_parse_digest() {
    let mut data = EMPTY_DIGEST;
    let digest = try_parse_digest(&data).unwrap();
    assert_eq!(EMPTY_DIGEST, digest);
    data[0] = 1;
    let digest = try_parse_digest(&data).unwrap();
    assert_ne!(EMPTY_DIGEST, digest);

    let data_bad_length = vec![0u8; DIGEST_BYTES + 1];
    assert!(try_parse_digest(&data_bad_length).is_err());
}

#[cfg(feature = "blake3")]
mod blake3_tests {
    use super::super::*;

    #[test]
    fn test_hash_validity() {
        let data = super::random_hash();
        let hash = hash(&data);
        let expected: [u8; DIGEST_BYTES] = ::blake3::hash(&data).into();

        assert_eq!(expected, hash);
    }
}

#[cfg(feature = "sha256")]
mod sha256_tests {
    use super::super::*;
    use ::sha2::Digest;

    #[test]
    fn test_hash_validity() {
        let data = super::random_hash();
        let hash = hash(&data);
        let expected: [u8; DIGEST_BYTES] = ::sha2::Sha256::digest(&data).into();

        assert_eq!(expected, hash);
    }
}

#[cfg(feature = "sha512")]
mod sha512_tests {
    use super::super::*;
    use ::sha2::Digest;

    #[test]
    fn test_hash_validity() {
        let data = super::random_hash();
        let hash = hash(&data);
        let expected: [u8; DIGEST_BYTES] = ::sha2::Sha512::digest(&data).into();

        assert_eq!(expected, hash);
    }
}

#[cfg(feature = "sha512_256")]
mod sha512_tests {
    use super::super::*;
    use ::sha2::Digest;

    #[test]
    fn test_hash_validity() {
        let data = super::random_hash();
        let hash = hash(&data);
        let expected: [u8; DIGEST_BYTES] = ::sha2::Sha512_256::digest(&data).into();

        assert_eq!(expected, hash);
    }
}

#[cfg(feature = "sha3_256")]
mod sha3_256_tests {
    use super::super::*;
    use ::sha3::Digest;

    #[test]
    fn test_hash_validity() {
        let data = super::random_hash();
        let hash = hash(&data);
        let expected: [u8; DIGEST_BYTES] = ::sha3::Sha3_256::digest(&data).into();

        assert_eq!(expected, hash);
    }
}

#[cfg(feature = "sha3_512")]
mod sha3_512_tests {
    use super::super::*;
    use ::sha3::Digest;

    #[test]
    fn test_hash_validity() {
        let data = super::random_hash();
        let hash = hash(&data);
        let expected: [u8; DIGEST_BYTES] = ::sha3::Sha3_512::digest(&data).into();

        assert_eq!(expected, hash);
    }
}
