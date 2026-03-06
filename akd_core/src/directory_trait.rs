// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Abstract trait for a verifiable key directory.
//!
//! Both AKD (Merkle-tree-based) and other implementations (e.g. polynomial-commitment-based)
//! can implement this trait, enabling consumers to swap backends.

use async_trait::async_trait;

use crate::types::{AkdLabel, AkdValue, EpochHash};
use crate::verify::history::HistoryParams;

/// Abstract Verifiable Key Directory interface.
///
/// This trait defines the core operations that any verifiable key directory
/// must support: publishing updates, looking up entries, querying key history,
/// and generating audit proofs. Proof types and errors are backend-specific
/// associated types.
#[cfg_attr(docsrs, doc(cfg(not(feature = "nostd"))))]
#[async_trait]
pub trait VerifiableKeyDirectory: Send + Sync {
    /// The proof type returned by a single-key lookup.
    type LookupProof: Send + Sync;
    /// The proof type returned by a key history query.
    type HistoryProof: Send + Sync;
    /// The proof type returned by an audit between two epochs.
    type AuditProof: Send + Sync;
    /// The public key type for this directory.
    type PublicKey: Send + Sync;
    /// The error type for this directory.
    type Error: std::error::Error + Send + Sync;

    /// Publish a batch of label-value updates to the directory, returning the
    /// new epoch and root hash.
    async fn publish(
        &self,
        updates: Vec<(AkdLabel, AkdValue)>,
    ) -> Result<EpochHash, Self::Error>;

    /// Generate a lookup proof for a single label at the latest epoch.
    async fn lookup(
        &self,
        label: AkdLabel,
    ) -> Result<(Self::LookupProof, EpochHash), Self::Error>;

    /// Generate lookup proofs for multiple labels at the latest epoch.
    async fn batch_lookup(
        &self,
        labels: &[AkdLabel],
    ) -> Result<(Vec<Self::LookupProof>, EpochHash), Self::Error>;

    /// Generate a key history proof for a label.
    async fn key_history(
        &self,
        label: &AkdLabel,
        params: HistoryParams,
    ) -> Result<(Self::HistoryProof, EpochHash), Self::Error>;

    /// Generate an audit proof between two epochs.
    async fn audit(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Self::AuditProof, Self::Error>;

    /// Retrieve the public key for this directory.
    async fn get_public_key(&self) -> Result<Self::PublicKey, Self::Error>;

    /// Retrieve the current epoch and root hash.
    async fn get_epoch_hash(&self) -> Result<EpochHash, Self::Error>;
}
