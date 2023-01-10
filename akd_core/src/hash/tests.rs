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

#[test]
fn test_merge_validity() {
    let hashes = [random_hash(), random_hash(), random_hash(), random_hash()];
    let merged = merge(&hashes);
    let data = hashes.concat();
    let expected = hash(&data);

    assert_eq!(expected, merged);
}

#[test]
fn test_merge_int_validity() {
    let random_epoch = thread_rng().gen::<u64>();
    let random_hash = random_hash();
    let merged = merge_with_u64(random_hash, random_epoch);

    let data = vec![random_hash.to_vec(), random_epoch.to_be_bytes().to_vec()].concat();
    let expected = hash(&data);

    assert_eq!(expected, merged);
}
