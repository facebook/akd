// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of a verifiable key directory (VKD)
//!
//!
//! A verifiable key directory (VKD) is an example of an authenticated
//! data structure. A VKD lets a server commit to a key-value store as it evolves over a
//! sequence of timesteps, also known as epochs.
//! The security of this protocol relies on the following two assumptions for all parties:
//! * a small commitment is viewable by all users,
//! * at any given epoch transition, there exists at least one honest auditor,
//!   who audits the server's latest commitment, relative to the previous commitment.
//!
//!
extern crate rand;

pub mod append_only_zks;
pub mod history_tree_node;
pub mod node_state;
pub mod proof_structs;
mod serialization;
pub mod storage;

pub mod errors;
pub mod seemless_auditor;
pub mod seemless_client;
pub mod seemless_directory;

#[cfg(test)]
pub mod tests;

pub const ARITY: usize = 2;

/// This type is used to indicate a direction for a
/// particular node relative to its parent.
pub type Direction = Option<usize>;
