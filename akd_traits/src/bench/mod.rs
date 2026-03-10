// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Generic benchmarking harness for key directory implementations.

pub mod stats;

pub use stats::ProofSizeOf;

use crate::types::{DirectoryLabel, DirectoryValue};
use async_trait::async_trait;

use crate::traits::KeyDirectory;

/// Trait that key directory implementations provide to set up benchmark fixtures.
#[async_trait]
pub trait BenchmarkSetup: 'static {
    /// The key directory type being benchmarked.
    type Directory: KeyDirectory;

    /// Create a fresh directory instance for benchmarking.
    async fn create_directory() -> Self::Directory;

    /// Generate a batch of deterministic test label-value pairs.
    fn generate_test_data(num_entries: usize, seed: u64) -> Vec<(DirectoryLabel, DirectoryValue)>;

    /// A descriptive name for this implementation (used in benchmark names).
    fn name() -> &'static str;
}

#[cfg(feature = "bench")]
mod criterion_benches;
#[cfg(feature = "bench")]
pub use criterion_benches::*;
