// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! # Key Directory Framework
//!
//! This crate provides the abstract [`KeyDirectory`] trait that
//! defines the interface for any key directory implementation.
//! Both server-side operations (publish, lookup, key history, audit) and
//! client-side verification are part of the trait.

#![warn(missing_docs)]

pub mod bench;
pub mod errors;
pub mod traits;
pub mod types;

/// Digest type (32-byte hash).
pub type Digest = [u8; 32];

pub use errors::KeyDirectoryError;
pub use traits::KeyDirectory;
pub use types::{DirectoryLabel, DirectoryValue, EpochHash, VerifyResult};
