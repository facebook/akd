// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Core utilities for the auditable key directory `akd` and `akd_client` crates.
//! Mainly contains (1) hashing utilities and (2) type definitions as well as (3)
//! protobuf specifications for all external types
//!
//! The default configuration is to utilize the standard library (`std`) along with
//! blake3 hashing (from the [blake3] crate). If you wish to customize which hash and
//! which features are utilized, you can pass --no-default-features on the command line
//! or `default-features = false` in your Cargo.toml import to disable all the default features
//! which you can then enable one-by-one as you wish.
//!
//! # Incorporating label-value pairs into the tree
//!
//! When inserting a ([AkdLabel], [AkdValue]) pair into the tree, the server commits to the [AkdValue]
//! and invokes a VRF on the [AkdLabel]. Together, these two processes form what is actually stored
//! as a node in the tree.
//!
//! ## VRF on the [AkdLabel]
//!
//! The position in which this value lies is determined by the [NodeLabel], which is the output
//! of a VRF evaluation of the [AkdLabel] and the current epoch. This is computed by the
//! `get_hash_from_label_input` function, which sets the node label as:
//! `node_label = H(label, stale, version)`
//!
//! Specifically, we concatenate the following together:
//! - `I2OSP(len(label) as u64, label)`
//! - A single byte encoded as `0u8` if "stale", `1u8` if "fresh"
//! - A `u64` representing the version
//! The resulting values are hashed together and used as the bytestring (truncated to 256 bits,
//! if necessary) that determines the exact location of the node in the tree.
//!
//! In the event that the label already exists in the tree, an additional stale label will be
//! added to the tree, with an empty value associated with it.
//!
//! ## Committing to an [AkdValue]
//!
//! The function [akd_core::commit_value] is used to commit the [AkdValue] to the tree. The actual value
//! that is stored in the node is a commitment, generated as follows:
//! - `proof = H(commitment_key, label, version, i2osp_array(value))`
//! - `commmitment = H(i2osp_array(value), i2osp_array(value))`
//!
//! Finally, the commitment is hashed together with the epoch that it ends up being inserted into the tree
//! computed as: `value_stored_in_node = H(commitment, epoch)`
//!
//! Here, `commitment_key` is a secret random value held by the server for the purposes of generating
//! these commitments.
//!
//! A client can then verify that the value stored in the tree is the same as the value they are expecting
//! upon requesting a [LookupProof] or [HistoryProof] which includes this commitment proof, and can then
//! insert their expected value and verify that it matches the node's value (indirectly, through an inclusion
//! proof in the Merkle tree). Note that without the commitment proof, a value cannot be verified, which
//! is a privacy feature that prevents an auditor from learning the value of a node.
//!
//!
//!

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
