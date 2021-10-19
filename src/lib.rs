// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

extern crate rand;

pub mod append_only_zks;
pub mod errors;
pub mod history_tree_node;
pub mod node_state;
pub mod seemless_directory;
mod serialization;
pub mod storage;
pub use errors::*;

pub mod proof_structs;
pub use proof_structs::*;

pub mod seemless_auditor;
pub mod seemless_client;

#[cfg(test)]
pub mod tests;

pub const ARITY: usize = 2;

pub type Direction = Option<usize>;
