// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module comprises S3 bucket READ ONLY access to download and parse
//! Audit Proofs

use super::ProofIndexCacheOption;
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
pub const DEFAULT_AWS_REGION: &str = "us-west-2";

// These are crate-visible because the dynamo tests utilize the test functions for S3 buckets
#[cfg(test)]
pub(crate) mod test;

pub(crate) fn validate_bucket_name(s: &str) -> Result<String, String> {
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

pub(crate) fn validate_uri(s: &str) -> Result<String, String> {
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
    pub(crate) bucket: String,
    /// The AWS region
    pub(crate) region: String,
    /// Customize the endpoint (useful for testing)
    pub(crate) endpoint: Option<String>,
    /// The access key
    pub(crate) access_key: Option<String>,
    /// The access secret
    pub(crate) secret_key: Option<String>,
    /// The configuration, cached for subsequent accesses
    pub(crate) config: Arc<RwLock<Option<aws_config::SdkConfig>>>,
    /// Cache of epoch summaries, populated with each call to list_blob_keys
    pub(crate) cache: Arc<RwLock<Option<Vec<super::EpochSummary>>>>,
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
    // exposed for test functionality only
    #[cfg(test)]
    pub async fn get_shared_test_config(&self) -> aws_types::SdkConfig {
        self.get_shared_config().await
    }

    async fn get_shared_config(&self) -> aws_types::SdkConfig {
        let mut lock = self.config.write().await;
        if let Some(config) = &*lock {
            config.clone()
        } else {
            // Get the shared AWS config
            let region_provider = RegionProviderChain::first_try(Region::new(self.region.clone()))
                .or_default_provider()
                .or_else(Region::new(DEFAULT_AWS_REGION));

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

    async fn get_object(&self, key: &str) -> Result<s3::client::fluent_builders::GetObject> {
        // We need to retrieve the minimum version of an object, to guarantee we see the ORIGINAL
        // status of the blob. Future versions are not supported
        let attributes = s3::Client::from_conf(self.get_config().await)
            .list_object_versions()
            .bucket(self.bucket.clone())
            .key_marker(key.to_string())
            .max_keys(1)
            .send()
            .await?;

        let mut version_count = 0usize;
        let mut min_time = std::time::SystemTime::now();
        let mut min_version = String::new();
        let mut etags = vec![];
        if let Some(versions) = attributes.versions() {
            for version in versions {
                if let Some(potential_key) = version.key() {
                    if potential_key == key {
                        if let (Some(mod_time), Some(version_id)) =
                            (version.last_modified(), version.version_id())
                        {
                            version_count += 1;
                            etags.push(
                                version
                                    .e_tag()
                                    .map(|tag| tag.to_string())
                                    .unwrap_or_else(|| "".to_string()),
                            );

                            let this_time: std::time::SystemTime = (*mod_time).try_into()?;
                            if this_time < min_time {
                                min_version = version_id.to_string();
                                min_time = this_time;
                            }
                        }
                    }
                }
            }
        }

        if version_count == 0 {
            return Err(anyhow::anyhow!(
                "Object not found with any version information"
            ));
        } else if version_count > 1 {
            // check all the versions for their associated etags, and make sure they're all the same
            let first = &etags[0];
            for etag in etags.iter().skip(1) {
                if first.cmp(etag) != std::cmp::Ordering::Equal {
                    return Err(anyhow::anyhow!("There were duplicate objects with the same key that have different etags which indicates different values. This epoch cannot be trusted ({} != {})", first, etag));
                }
            }
        }

        Ok(s3::Client::from_conf(self.get_config().await)
            .get_object()
            .bucket(self.bucket.clone())
            .version_id(min_version)
            .key(key.to_string())
            .checksum_mode(s3::model::ChecksumMode::Enabled))
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
    fn default_cache_control(&self) -> ProofIndexCacheOption {
        ProofIndexCacheOption::UseCache
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

    async fn get_proof(&self, epoch: &super::EpochSummary) -> Result<akd::proto::AuditBlob> {
        let client = self.get_object(&epoch.key).await?;
        match client.send().await {
            Err(some_err) => {
                error!("Error executing get_object in S3 {}", some_err);
                bail!("Error executing get_object in S3 {}", some_err);
            }
            Ok(result) => {
                let bytes = result.body.collect().await?.into_bytes();
                Ok(akd::proto::AuditBlob {
                    data: bytes.into_iter().collect::<Vec<u8>>(),
                    name: epoch.name.clone(),
                })
            }
        }
    }
}
