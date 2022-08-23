// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module comprises S3 bucket READ ONLY access to download and process
//! Audit Proofs

use anyhow::{bail, Result};
use aws_config::RetryConfig;
use aws_sdk_s3 as s3;
use log::error;
use std::marker::{Send, Sync};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct S3Interaction {
    /// The bucket where the audit proofs are stored
    bucket: String,
    /// An authentication token to utilize
    authentication: Option<String>,
    /// The configuration, cached for subsequent accesses
    config: Arc<RwLock<Option<aws_config::SdkConfig>>>,
}

impl S3Interaction {
    /// Construct a new S3 interactor
    pub fn new(bucket: String) -> Self {
        Self {
            bucket,
            authentication: None,
            config: Arc::new(RwLock::new(None)),
        }
    }

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

    // ************************** Blob Operations API ************************** //

    /// Retrieve the blob keys in the folder
    pub async fn list_blob_keys(&self) -> Result<Vec<String>> {
        use tokio_stream::StreamExt;

        let mut results = vec![];
        let client = self.list_objects_v2().await;
        let mut stream = client.page_size(500).send();
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
                                results.push(key.to_string());
                            }
                        }
                    }
                }
            }
        }
        Ok(results)
    }

    /// Verify a specific epoch given the collection of keys in the bucket
    pub async fn verify_epoch<H>(
        &self,
        epoch: u64,
        keys: &[String],
        generate_qr: bool,
    ) -> Result<()>
    where
        H: winter_crypto::Hasher + Clone + Send + Sync,
    {
        if let Some((_, found_key)) = keys
            .iter()
            .map(|key| (akd::proto::AuditBlob::decompose_name::<H>(key), key))
            .find(|(result, _key)| {
                if let Ok((_, _, e)) = result {
                    *e == epoch
                } else {
                    false
                }
            })
        {
            let client = self.get_object(found_key).await;
            match client.send().await {
                Err(some_err) => {
                    error!("Error executing get_object in S3 {}", some_err);
                    bail!("Error executing get_object in S3 {}", some_err);
                }
                Ok(result) => {
                    let bytes = result.body.collect().await?.into_bytes();
                    crate::auditor::audit::<H>(bytes, found_key, generate_qr).await?;
                }
            }

            Ok(())
        } else {
            bail!("Failed to find epoch {} in keyset from S3", epoch);
        }
    }
}
