// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module comprises S3 bucket READ ONLY access to download and parse
//! Audit Proofs

use anyhow::{bail, Result};
use async_trait::async_trait;
use aws_config::RetryConfig;
use aws_sdk_s3 as s3;
use clap::Args;
use log::{debug, error};
use std::convert::TryInto;
use std::sync::Arc;
use tokio::sync::RwLock;

const MIN_BUCKET_CHARS: usize = 3;
const MAX_BUCKET_CHARS: usize = 63;
const ALLOWED_BUCKET_CHARS: [char; 38] = [
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','.','-', '1','2','3','4','5','6','7','8','9','0'
];

fn is_bucket_name_valid(s: &str) -> Result<String, String> {
    let str = s.to_string();
    if str.len() >= MIN_BUCKET_CHARS && str.len() <= MAX_BUCKET_CHARS {
        for c in str.chars() {
            if !ALLOWED_BUCKET_CHARS.iter().any(|v| c == *v) {
                return Err(format!("Character '{}' is not allowed in bucket name. Bucket names must contain lower-case letters, numbers, '-', and '.' only.", c));
            }
        }
        Ok(str)
    } else {
        Err(format!("Bucket name must be between [{}, {}] characters in length. Gave {}", MIN_BUCKET_CHARS, MAX_BUCKET_CHARS, str.len()))
    }
}

#[derive(Args, Debug, Clone)]
pub struct S3ClapSettings {
    /// The S3 bucket where the audit proofs are stored
    #[clap(
        long,
        value_parser = is_bucket_name_valid
    )]
    bucket: String,
}


pub struct S3AuditStorage {
    /// The bucket where the audit proofs are stored
    bucket: String,
    /// The configuration, cached for subsequent accesses
    config: Arc<RwLock<Option<aws_config::SdkConfig>>>,

    /// Cache of epoch summaries, populated with each call to list_blob_keys
    cache: Arc<RwLock<Option<Vec<super::EpochSummary>>>>,
}

impl From<&S3ClapSettings> for S3AuditStorage {
    fn from(clap: &S3ClapSettings) -> Self {
        Self {
            bucket: clap.bucket.clone(),
            config: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl S3AuditStorage {

    async fn get_config(&self) -> s3::Config {
        let mut lock = self.config.write().await;
        let shared_config = if let Some(config) = &*lock {
            config.clone()
        } else {
            let sc = aws_config::load_from_env().await;
            *lock = Some(sc.clone());
            sc
        };
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
            .key(key.clone())
            .checksum_mode(s3::model::ChecksumMode::Enabled)
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
            match result {
                Err(some_error) => {
                    error!("Error executing list_objects_v2 in S3 {}", some_error);
                    bail!("Error executing list_objects_v2 in S3 {}", some_error);
                }
                Ok(objects) => {
                    if let Some(contents) = objects.contents() {
                        for obj in contents {
                            if let Some(key) = obj.key() {
                                let summary: Result<super::EpochSummary> = key.try_into();
                                match summary {
                                    Ok(dbi) => results.push(dbi),
                                    Err(error) => {
                                        debug!("Error parsing blob key into DecomposedBlobItem ({}). Skipping.", error);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !results.is_empty() {
            let mut update = self.cache.write().await;
            *update = Some(results.clone());
        }

        Ok(results)
    }

    async fn get_proof(&self, epoch: u64) -> Result<akd::proto::AuditBlob> {
        if let Some(cache) = &*(self.cache.read().await) {
            if let Some(found_key) = cache.iter().find(|item| item.epoch == epoch) {
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
                            name: found_key.key.clone()
                        })
                    }
                }
            } else {
                bail!("Failed to find epoch {} in keys retrieved from S3", epoch);
            }
        } else {
            bail!("Object keys first need to be enumerated from S3 before we can retrieve an epoch");
        }
    }
}
