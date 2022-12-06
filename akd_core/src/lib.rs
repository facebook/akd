// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Core utilities for the auditable-key-directory `akd` and `akd_client` crates.
//! Mainly contains (1) hashing utilities and (2) type definitions as well as (3)
//! protobuf specifications for all external types
//!
//! The default configuration is to utilize the standard-library (`std`) along with
//! blake3 hashing (from the [blake3] crate). If you wish to customize which hash and
//! which features are utilized, you can pass --no-default-features on the command line
//! or `default-features = false` in your Cargo.toml import to disable all the default features
//! which you can then enable one-by-one as you wish.

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "nostd", no_std)]
extern crate alloc;

#[cfg(all(feature = "protobuf", not(feature = "nostd")))]
pub mod proto;

pub mod ecvrf;
pub mod hash;
pub mod utils;
pub mod verify;

pub mod types;
pub use types::*;

/// The arity of the tree. Should EXACTLY match the ARITY within
/// the AKD crate (i.e. akd::ARITY)
pub const ARITY: usize = 2;
