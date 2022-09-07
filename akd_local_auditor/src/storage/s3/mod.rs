// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module comprises S3 bucket READ ONLY access to download and parse
//! Audit Proofs

use anyhow::{bail, Result};
use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_config::RetryConfig;
use aws_sdk_s3 as s3;
use aws_smithy_http::endpoint::Endpoint;
use clap::Args;
use log::{debug, error};
use s3::output::ListObjectsV2Output;
use s3::Region;
use std::convert::TryInto;
use std::sync::Arc;
use tokio::sync::RwLock;

const MIN_BUCKET_CHARS: usize = 3;
const MAX_BUCKET_CHARS: usize = 63;
const ALLOWED_BUCKET_CHARS: [char; 38] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '.', '-', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
];

#[cfg(test)]
mod test;

fn validate_bucket_name(s: &str) -> Result<String, String> {
    let str = s.to_string();
    if str.len() < MIN_BUCKET_CHARS || str.len() > MAX_BUCKET_CHARS {
        return Err(format!(
            "Bucket name must be between [{}, {}] characters in length. Gave {}",
            MIN_BUCKET_CHARS,
            MAX_BUCKET_CHARS,
            str.len()
        ));
    }

    for c in str.chars() {
        if !ALLOWED_BUCKET_CHARS.iter().any(|v| c == *v) {
            return Err(format!("Character '{}' is not allowed in bucket name. Bucket names must contain lower-case letters, numbers, '-', and '.' only.", c));
        }
    }
    Ok(str)
}

fn validate_uri(s: &str) -> Result<String, String> {
    let uri: http::Uri = s.parse::<http::Uri>().map_err(|err| err.to_string())?;
    match (uri.scheme(), uri.authority()) {
        (None, None) => {
            Err("URI has no scheme or authority. Relative URIs not supported".to_string())
        }
        // if there's at least a scheme (http[s]://) or authority (www.test.com) we can construct what we need
        _ => Ok(s.to_string()),
    }
}

#[derive(Args, Debug, Clone)]
pub struct S3ClapSettings {
    /// The S3 bucket where the audit proofs are stored
    #[clap(
        long,
        value_parser = validate_bucket_name
    )]
    bucket: String,

    /// The AWS region to operate in
    #[clap(long)]
    region: String,

    /// [OPTIONAL] An custom URI for the AWS endpoint
    #[clap(long, value_parser = validate_uri)]
    endpoint: Option<String>,

    /// [OPTIONAL] AWS Access key for the session
    #[clap(long)]
    access_key: Option<String>,

    /// [OPTIONAL] AWS secret key for the session
    #[clap(long)]
    secret_key: Option<String>,
}

#[derive(Debug)]
pub struct S3AuditStorage {
    /// The bucket where the audit proofs are stored
    bucket: String,
    /// The AWS region
    region: String,
    /// Customize the endpoint (useful for testing)
    endpoint: Option<String>,
    /// The access key
    access_key: Option<String>,
    /// The access secret
    secret_key: Option<String>,
    /// The configuration, cached for subsequent accesses
    config: Arc<RwLock<Option<aws_config::SdkConfig>>>,

    /// Cache of epoch summaries, populated with each call to list_blob_keys
    cache: Arc<RwLock<Option<Vec<super::EpochSummary>>>>,
}

impl From<&S3ClapSettings> for S3AuditStorage {
    fn from(clap: &S3ClapSettings) -> Self {
        Self {
            bucket: clap.bucket.clone(),
            region: clap.region.clone(),
            endpoint: clap.endpoint.as_ref().cloned(),
            access_key: clap.access_key.as_ref().cloned(),
            secret_key: clap.secret_key.as_ref().cloned(),
            config: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl S3AuditStorage {
    async fn get_shared_config(&self) -> aws_types::SdkConfig {
        let mut lock = self.config.write().await;
        if let Some(config) = &*lock {
            config.clone()
        } else {
            // Get the shared AWS config
            let region_provider = RegionProviderChain::first_try(Region::new(self.region.clone()));

            let mut shared_config_loader = aws_config::from_env().region(region_provider);

            if let (Some(access_key), Some(secret_key)) = (&self.access_key, &self.secret_key) {
                let credentials = aws_types::Credentials::from_keys(access_key, secret_key, None);
                shared_config_loader = shared_config_loader.credentials_provider(credentials);
            }

            if let Some(endpoint) = &self.endpoint {
                // THE URI IS ALREADY VALIDATED BY CLAP ARGS, hence the expect here
                let endpoint_resolver = Endpoint::immutable(endpoint.parse().expect("valid URI"));
                shared_config_loader = shared_config_loader.endpoint_resolver(endpoint_resolver);
            }

            let shared_config = shared_config_loader.load().await;

            *lock = Some(shared_config.clone());
            shared_config
        }
    }

    async fn get_config(&self) -> s3::Config {
        let shared_config = self.get_shared_config().await;
        s3::config::Builder::from(&shared_config)
            .retry_config(RetryConfig::disabled())
            .build()
    }

    async fn list_objects_v2(&self) -> s3::paginator::ListObjectsV2Paginator {
        let config = self.get_config().await;

        s3::Client::from_conf(config)
            .list_objects_v2()
            .bucket(self.bucket.clone())
            .encoding_type(s3::model::EncodingType::Url)
            .fetch_owner(false)
            .into_paginator()
    }

    async fn get_object(&self, key: &str) -> s3::client::fluent_builders::GetObject {
        let config = self.get_config().await;

        s3::Client::from_conf(config)
            .get_object()
            .bucket(self.bucket.clone())
            .key(key.to_string())
            .checksum_mode(s3::model::ChecksumMode::Enabled)
    }

    fn process_streamed_response(
        part: Result<ListObjectsV2Output, s3::types::SdkError<s3::error::ListObjectsV2Error>>,
    ) -> Result<Vec<super::EpochSummary>> {
        let mut partials = vec![];
        match part {
            Err(sdk_err) => {
                return Err(anyhow::anyhow!(
                    "Error executing list_objects_v2 in S3: {}",
                    sdk_err
                ));
            }
            Ok(list_objects_v2_output) => {
                if let Some(contents) = list_objects_v2_output.contents() {
                    for object_ref in contents {
                        let key = object_ref.key().unwrap_or("MISSING_KEY");
                        let epoch_summary: Result<super::EpochSummary> = key.try_into();
                        match epoch_summary {
                            Err(parse_err) => debug!(
                                "Failed to parse {} into an EpochSummary: {}. Skipping...",
                                key, parse_err
                            ),
                            Ok(summary) => partials.push(summary),
                        }
                    }
                }
            }
        }
        Ok(partials)
    }
}

#[async_trait]
impl super::AuditProofStorage for S3AuditStorage {
    async fn list_proofs(&self) -> Result<Vec<super::EpochSummary>> {
        use tokio_stream::StreamExt;

        let mut results = vec![];
        let client = self.list_objects_v2().await;
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

    async fn get_proof(&self, epoch: u64) -> Result<akd::proto::AuditBlob> {
        if let Some(cache) = &*(self.cache.read().await) {
            if let Some(found_key) = cache.iter().find(|item| item.name.epoch == epoch) {
                let client = self.get_object(&found_key.key).await;
                match client.send().await {
                    Err(some_err) => {
                        error!("Error executing get_object in S3 {}", some_err);
                        bail!("Error executing get_object in S3 {}", some_err);
                    }
                    Ok(result) => {
                        let bytes = result.body.collect().await?.into_bytes();
                        Ok(akd::proto::AuditBlob {
                            data: bytes.into_iter().collect::<Vec<u8>>(),
                            name: found_key.name.clone(),
                        })
                    }
                }
            } else {
                bail!("Failed to find epoch {} in keys retrieved from S3", epoch);
            }
        } else {
            bail!(
                "Object keys first need to be enumerated from S3 before we can retrieve an epoch"
            );
        }
    }
}
