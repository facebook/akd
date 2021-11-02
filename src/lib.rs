// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of a verifiable key directory (VKD), also known as a verifiable registery.
//!
//! # Overview
//! A verifiable key directory (VKD) is an example of an authenticated
//! data structure. A VKD lets a server commit to a key-value store as it evolves over a
//! sequence of timesteps, also known as epochs.
//!
//! The security of this protocol relies on the following two assumptions for all parties:
//! * a small commitment is viewable by all users,
//! * at any given epoch transition, there exists at least one honest auditor,
//!   who audits the server's latest commitment, relative to the previous commitment.
//!
//!
//! ## Statelessness
//! This library is meant to be stateless, in that it runs without storing a majority of the data
//! locally, where the code is running, and instead, uses a [storage::Storage] as a generic type.
//!
//! ## Setup
//! A [directory::Directory] represents a VKD. To setup a [directory::Directory], call
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
//!
#![warn(missing_docs)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate rand;

pub mod append_only_zks;
pub mod directory;
pub mod history_tree_node;
pub mod node_state;
pub mod proof_structs;
mod serialization;
pub mod storage;

pub mod auditor;
pub mod client;
pub mod errors;

#[cfg(test)]
pub mod tests;

/// The arity of the underlying tree structure of the vkd.
pub const ARITY: usize = 2;

/// This type is used to indicate a direction for a
/// particular node relative to its parent.
pub type Direction = Option<usize>;
