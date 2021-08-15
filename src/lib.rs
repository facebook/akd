// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

extern crate rand;

pub mod append_only_zks;
pub mod errors;
pub mod history_tree_node;
pub mod node_state;
pub mod seemless_directory;
mod serialization;
pub mod storage;
pub use errors::*;

#[cfg(test)]
mod tests;

pub const ARITY: usize = 2;

pub type Direction = Option<usize>;
