// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A CLI tool for generating directory fixtures for debug and testing purposes.
//! Run cargo run -- --help for options. Example command:
//!
//!   cargo run -- \
//!     --user "User1: 1, (9, 'abc'), (10, 'def')" \
//!     --user "User2: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10" \
//!     --epochs 10 \
//!     --max_updates 5 \
//!     --capture_states 9 10 \
//!     --capture_deltas 10
//!

mod examples;
mod generator;
mod parser;
mod writer;

pub mod reader;

/// Re-export generator run function.
pub use generator::run;
