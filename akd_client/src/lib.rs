// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! # Overview
//!
//! This crate contains a "lean" client to verify AKD proofs which doesn't depend on any
//! crates other than the native hashing implementations and VRF functionality through
//! the [akd_core] crate. This makes it suitable for embedded applications, e.g. inside
//! limited clients (Android, iPhone, WebAssembly, etc) which may not have a large
//! dependency library they can pull upon.
//!
//! ## Features
//!
//! The features of this library are
//!
//! 1. **default** blake3: Blake3 256-bit hashing
//! 2. sha256: SHA2 256-bit hashing
//! 3. sha512: SHA3 512-bit hashing
//! 4. sha3_256: SHA3 256-bit hashing
//! 5. sha3_512: SHA3 512-bit hashing
//!
//! which dictate which hashing function is used by the verification components. Blake3 256-bit hashing is the default
//! implementation and utilizes the [`blake3`] crate. Features sha256 and sha512 both utilize SHA2 cryptographic functions
//! from the [`sha2`](https://crates.io/crates/sha2) crate. Lastly sha3_256 and sha3_512 features utilize the
//! [`sha3`](https://crates.io/crates/sha3) crate for their hashing implementations.
//! To utilize a hash implementation other than blake3, you should compile with
//!
//! ```bash
//! //          [disable blake3]      [enable other hash]
//! cargo build --no-default-features --features sha3_256
//! ```
//!

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "nostd", no_std)]
extern crate alloc;

// Re-expose the core functionality from akd_core (verifications, types, etc)
pub use akd_core::verify;
pub use akd_core::*;

#[cfg(feature = "protobuf")]
pub use akd_core::proto::*;

#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "wasm")]
pub use wasm::lookup_verify;
