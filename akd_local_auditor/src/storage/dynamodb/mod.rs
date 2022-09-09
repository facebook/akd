// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module comprises AWS DynamoDb bucket READ ONLY access to download and parse
//! Audit Proofs. THIS IS JUST A SAMPLE AND IS NOT IMPLEMENTED. This will be rounded
//! out later if support is to be added for dynamo db

use super::ProofIndexCacheOption;
use anyhow::Result;
use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb as dynamo;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Region;
use aws_smithy_http::endpoint::Endpoint;
use clap::Args;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(test)]
mod test;

use super::EpochSummary;

const MIN_TABLE_CHARS: usize = 3;
const MAX_TABLE_CHARS: usize = 255;
const ALLOWED_TABLE_CHARS: [char; 65] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'z', '.', '-', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '_',
];

fn validate_table_name(s: &str) -> Result<String, String> {
    let str = s.to_string();
    if str.len() < MIN_TABLE_CHARS || str.len() > MAX_TABLE_CHARS {
        return Err(format!(
            "Table name must be between [{}, {}] characters in length. Gave {}",
            MIN_TABLE_CHARS,
            MAX_TABLE_CHARS,
            str.len()
        ));
    }

    for c in str.chars() {
        if !ALLOWED_TABLE_CHARS.iter().any(|v| c == *v) {
            return Err(format!("Character '{}' is not allowed in table name. Table names must contain lower-case letters, numbers, '-', '_', and '.' only.", c));
        }
    }
    Ok(str)
}

/// Connect to DynamoDb which holds the "listing" information
/// on audit proofs, but the true blobs are stored in S3. (It's just
/// indexed lookups of S3)
#[derive(Args, Debug, Clone)]
pub struct DynamoDbClapSettings {
    /// The dynamoDb table name
    #[clap(long, short,
        value_parser = validate_table_name)]
    table: String,

    /// The AWS region where the dynamo db cluster lives
    #[clap(long, short)]
    region: String,

    /// The S3 bucket where the audit proofs are stored
    #[clap(
        long,
        value_parser = super::s3::validate_bucket_name
    )]
    bucket: String,

    /// [OPTIONAL] AWS DynamoDb custom endpoint
    #[clap(long, value_parser = super::s3::validate_uri)]
    dynamo_endpoint: Option<String>,

    /// [OPTIONAL] AWS S3 bucket custom endpoint
    #[clap(long, value_parser = super::s3::validate_uri)]
    s3_endpoint: Option<String>,

    /// [OPTIONAL] AWS Access key for the session
    #[clap(long)]
    access_key: Option<String>,

    /// [OPTIONAL] AWS secret key for the session
    #[clap(long)]
    secret_key: Option<String>,
}

#[derive(Debug)]
pub struct DynamoDbAuditStorage {
    /// The table where the audit proofs are stored
    table: String,
    /// The AWS region
    region: String,
    /// The S3 bucket which contains the underlying proof material
    bucket: String,
    /// [OPTIONAL] AWS DynamoDb custom endpoint
    dynamo_endpoint: Option<String>,
    /// [OPTIONAL] AWS S3 bucket custom endpoint
    s3_endpoint: Option<String>,
    /// [OPTIONAL] AWS Access key for the session
    access_key: Option<String>,
    /// [OPTIONAL] AWS secret key for the session
    secret_key: Option<String>,
    /// The configuration, cached for subsequent accesses
    config: Arc<RwLock<Option<aws_config::SdkConfig>>>,
    /// Cache of epoch summaries, populated with each call to list_blob_keys
    cache: Arc<RwLock<Option<Vec<super::EpochSummary>>>>,
}

impl From<&DynamoDbClapSettings> for DynamoDbAuditStorage {
    fn from(clap: &DynamoDbClapSettings) -> Self {
        Self {
            table: clap.table.clone(),
            region: clap.region.clone(),
            bucket: clap.bucket.clone(),
            dynamo_endpoint: clap.dynamo_endpoint.as_ref().cloned(),
            s3_endpoint: clap.s3_endpoint.as_ref().cloned(),
            access_key: clap.access_key.as_ref().cloned(),
            secret_key: clap.secret_key.as_ref().cloned(),
            config: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl From<&DynamoDbAuditStorage> for super::s3::S3AuditStorage {
    fn from(clap: &DynamoDbAuditStorage) -> Self {
        Self {
            bucket: clap.bucket.clone(),
            region: clap.region.clone(),
            access_key: clap.access_key.as_ref().cloned(),
            secret_key: clap.secret_key.as_ref().cloned(),
            endpoint: clap.s3_endpoint.as_ref().cloned(),
            config: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl DynamoDbAuditStorage {
    async fn get_shared_config(&self) -> aws_types::SdkConfig {
        let mut lock = self.config.write().await;
        if let Some(config) = &*lock {
            config.clone()
        } else {
            // Get the shared AWS config
            let region_provider = RegionProviderChain::first_try(Region::new(self.region.clone()))
                .or_default_provider()
                .or_else(Region::new("us-west-2"));

            let mut shared_config_loader = aws_config::from_env().region(region_provider);

            if let (Some(access_key), Some(secret_key)) = (&self.access_key, &self.secret_key) {
                let credentials = aws_types::Credentials::from_keys(access_key, secret_key, None);
                shared_config_loader = shared_config_loader.credentials_provider(credentials);
            }

            if let Some(endpoint) = &self.dynamo_endpoint {
                // THE URI IS ALREADY VALIDATED BY CLAP ARGS, hence the expect here
                let endpoint_resolver = Endpoint::immutable(endpoint.parse().expect("valid URI"));
                shared_config_loader = shared_config_loader.endpoint_resolver(endpoint_resolver);
            }

            let shared_config = shared_config_loader.load().await;

            *lock = Some(shared_config.clone());
            shared_config
        }
    }

    fn parse_summary(row: &HashMap<String, AttributeValue>) -> Result<Option<EpochSummary>> {
        if let (
            Some(AttributeValue::N(epoch)),
            Some(AttributeValue::B(phash)),
            Some(AttributeValue::B(chash)),
            Some(AttributeValue::S(blob_key)),
        ) = (
            row.get("epoch"),
            row.get("previous_hash"),
            row.get("current_hash"),
            row.get("blob"),
        ) {
            let phash_digest = akd::serialization::to_digest::<crate::Hasher>(phash.as_ref())
                .map_err(|err| anyhow::anyhow!("Error converting digest {}", err))?;
            let chash_digest = akd::serialization::to_digest::<crate::Hasher>(chash.as_ref())
                .map_err(|err| anyhow::anyhow!("Error converting digest {}", err))?;
            let audit_blob_name = akd::proto::AuditBlobName {
                epoch: epoch.parse()?,
                previous_hash: akd::serialization::from_digest::<crate::Hasher>(phash_digest),
                current_hash: akd::serialization::from_digest::<crate::Hasher>(chash_digest),
            };
            Ok(Some(EpochSummary {
                key: blob_key.clone(),
                name: audit_blob_name,
            }))
        } else {
            Ok(None)
        }
    }

    async fn query_proofs(&self) -> dynamo::paginator::ScanPaginator {
        let config = self.get_shared_config().await;
        let client = dynamo::Client::new(&config);
        client
            .scan()
            .table_name(self.table.clone())
            .into_paginator()
    }

    fn process_streamed_response(
        part: Result<dynamo::output::ScanOutput, dynamo::types::SdkError<dynamo::error::ScanError>>,
    ) -> Result<Vec<super::EpochSummary>> {
        let mut partials = vec![];
        match part {
            Err(sdk_err) => {
                return Err(anyhow::anyhow!(
                    "Error executing Query in DynamoDb: {}",
                    sdk_err
                ));
            }
            Ok(query_output) => {
                if let Some(contents) = query_output.items {
                    for map_ref in contents {
                        if let Ok(Some(partial)) = Self::parse_summary(&map_ref) {
                            partials.push(partial);
                        }
                    }
                }
            }
        }
        Ok(partials)
    }
}

#[async_trait]
impl super::AuditProofStorage for DynamoDbAuditStorage {
    fn default_cache_control(&self) -> ProofIndexCacheOption {
        ProofIndexCacheOption::NoCache
    }

    async fn list_proofs(
        &self,
        cache_control: ProofIndexCacheOption,
    ) -> Result<Vec<super::EpochSummary>> {
        use tokio_stream::StreamExt;

        {
            if let ProofIndexCacheOption::UseCache = &cache_control {
                if let Some(cache) = &*self.cache.read().await {
                    return Ok(cache.clone());
                }
            }
        }

        let mut results = vec![];
        let client = self.query_proofs().await;
        let mut stream = client.page_size(1000).send();
        while let Some(result) = stream.next().await {
            let mut maybe_item = Self::process_streamed_response(result)?;
            results.append(&mut maybe_item);
        }

        if !results.is_empty() {
            let mut update = self.cache.write().await;
            *update = Some(results.clone());
        }

        Ok(results)
    }

    async fn get_proof(&self, epoch: &super::EpochSummary) -> Result<akd::proto::AuditBlob> {
        let s3_storage: crate::storage::s3::S3AuditStorage = self.into();
        s3_storage.get_proof(epoch).await
    }
}
