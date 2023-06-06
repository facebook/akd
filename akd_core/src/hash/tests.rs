// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Tests for hashing

use super::*;

#[cfg(feature = "nostd")]
use alloc::vec;

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
