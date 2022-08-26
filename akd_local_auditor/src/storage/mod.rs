// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module holds the generic storage interaction layer trait along with the underlying implemented
//! storage interactions

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
    // /// DynamoDB
    // DynamoDb(dynamodb::DynamoDbClapSettings),
}

// ************************************ Trait and Type Definitions ************************************ //

/// Represents the summary of an epoch, and a unique key referring to the raw object in native storage (if needed)
#[derive(Clone)]
pub struct EpochSummary {
    /// The name of the audit-blob decomposed into parts
    pub name: akd::proto::AuditBlobName,
    /// Unique idenfier for the blob in question
    pub key: String,
}

impl TryFrom<&str> for EpochSummary {
    type Error = anyhow::Error;

    fn try_from(potential_key: &str) -> Result<Self, Self::Error> {
        let name = akd::proto::AuditBlobName::try_from(potential_key.to_string())
            .map_err(|err| anyhow!("{}", err))?;

        Ok(Self {
            name,
            key: potential_key.to_string(),
        })
    }
}

/// Represents a storage of audit proofs and READ ONLY interaction to retrieve the proof objects
#[async_trait]
pub trait AuditProofStorage: Sync + Send {
    /// List the proofs in the storage medium.
    async fn list_proofs(&self) -> Result<Vec<EpochSummary>>;

    /// Retrieve an audit proof from the storage medium. If the underlying storage implementation
    /// requires the epoch summaries in order to re-retrieve a specific epoch, it is up to that
    /// implementation to cache the information. Example: See the AWS S3 implementation
    async fn get_proof(&self, epoch: u64) -> Result<akd::proto::AuditBlob>;
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
    /// List the proofs in the storage medium.
    async fn list_proofs(&self) -> Result<Vec<EpochSummary>> {
        self.list_proofs().await
    }

    /// Retrieve an audit proof from the storage medium. If the underlying storage implementation
    /// requires the epoch summaries in order to re-retrieve a specific epoch, it is up to that
    /// implementation to cache the information. Example: See the AWS S3 implementation
    async fn get_proof(&self, epoch: u64) -> Result<akd::proto::AuditBlob> {
        self.get_proof(epoch).await
    }
}
