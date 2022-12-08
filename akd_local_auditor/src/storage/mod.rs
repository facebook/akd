// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module holds the generic storage interaction layer trait along with the underlying implemented
//! storage interactions. We need to implement the trait for a [Box] of the same trait in order to support
//! passing the boxed implementations around. This is required for the async nature of the command and Rust's
//! type inference engine

use akd::local_auditing::{AuditBlob, AuditBlobName};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use clap::Subcommand;
use std::convert::TryFrom;

// ************************************ Implementations ************************************ //

pub mod dynamodb;
pub mod s3;

/// Storage options for retrieving audit proofs
#[derive(Subcommand, Clone, Debug)]
pub enum StorageSubcommand {
    /// Amazon S3 compatible storage
    S3(s3::S3ClapSettings),
    /// DynamoDB
    DynamoDb(dynamodb::DynamoDbClapSettings),
}

// ************************************ Trait and Type Definitions ************************************ //

/// Represents the summary of an epoch, and a unique key referring to the raw object in native storage (if needed)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct EpochSummary {
    /// The name of the audit-blob decomposed into parts
    pub name: AuditBlobName,
    /// Unique idenfier for the blob in question
    pub key: String,
}

impl TryFrom<&str> for EpochSummary {
    type Error = anyhow::Error;

    fn try_from(potential_key: &str) -> Result<Self, Self::Error> {
        let name = AuditBlobName::try_from(potential_key).map_err(|err| anyhow!("{:?}", err))?;

        Ok(Self {
            name,
            key: potential_key.to_string(),
        })
    }
}

/// Options for proof index lookup operations
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ProofIndexCacheOption {
    /// Don't utilize a cache
    NoCache,
    /// Utilize the underlying proof lookup cache
    UseCache,
}

/// Represents a storage of audit proofs and READ ONLY interaction to retrieve the proof objects
#[async_trait]
pub trait AuditProofStorage: Sync + Send + std::fmt::Debug {
    /// The default cache control option for proof listings for this storage implementation
    fn default_cache_control(&self) -> ProofIndexCacheOption;

    /// List the proofs in the storage medium.
    async fn list_proofs(&self, cache_control: ProofIndexCacheOption) -> Result<Vec<EpochSummary>>;

    /// Retrieve an audit proof from the storage medium. If the underlying storage implementation
    /// requires the epoch summaries in order to re-retrieve a specific epoch, it is up to that
    /// implementation to cache the information. Example: See the AWS S3 implementation
    async fn get_proof(&self, epoch: &EpochSummary) -> Result<AuditBlob>;
}

// We need to implement the trait for a Box<dyn Trait> in order to utilize a box further downstream
// which allows us to have multiple implementations of the AuditProofStorage without a separate logic/code
// path for each implementation
//
// See the discussion here: https://stackoverflow.com/questions/71933895/why-cant-boxdyn-trait-be-pased-to-a-function-with-mut-trait-as-parameter
#[async_trait]
impl<APS: ?Sized> AuditProofStorage for Box<APS>
where
    APS: AuditProofStorage,
{
    /// The default cache control option for proof listings for this storage implementation
    #[allow(unconditional_recursion)]
    fn default_cache_control(&self) -> ProofIndexCacheOption {
        self.default_cache_control()
    }

    /// List the proofs in the storage medium.
    async fn list_proofs(&self, cache_control: ProofIndexCacheOption) -> Result<Vec<EpochSummary>> {
        self.list_proofs(cache_control).await
    }

    /// Retrieve an audit proof from the storage medium. If the underlying storage implementation
    /// requires the epoch summaries in order to re-retrieve a specific epoch, it is up to that
    /// implementation to cache the information. Example: See the AWS S3 implementation
    async fn get_proof(&self, epoch: &EpochSummary) -> Result<AuditBlob> {
        self.get_proof(epoch).await
    }
}
