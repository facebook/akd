// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A note to readers:
//!
//! We are marking most of the following tests as `#[ignored]` so they don't run automatically
//! with `cargo test`. These require a docker container running `minio` to be running which is
//! run in our CI pipeline when changes to this crate are made, but not otherwise since they
//! are relatively expensive integration test operations. See [s3.yml](.github/workflows/s3.yml)
//! for more information

use crate::{
    storage::{AuditProofStorage, EpochSummary},
    Digest, Hasher,
};

use super::*;
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::AkdLabel;
use akd::AkdValue;
use anyhow::Result;
use aws_config::SdkConfig;
use aws_sdk_s3::{
    config::Builder as S3ConfigBuilder,
    model::{Delete, ObjectIdentifier},
    Client,
};
use aws_smithy_http::byte_stream::ByteStream;

// These are constants that are matched in both this crate's `docker-compose.yml`
// and the s3.yml workflow pipeline
const ACCESS_KEY: &str = "test";
const SECRET_KEY: &str = "someLongAccessKey";
const TEST_REGION: &str = "us-east-2";
const TEST_ENDPOINT: &str = "http://127.0.0.1:9000";

macro_rules! bucket_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        name[..name.len() - 3]
            .trim_end_matches("::{{closure}}")
            .split("::")
            .last()
            .unwrap()
            .replace("_", "")
    }};
}

struct AuditInformation {
    proof: akd::proof_structs::AppendOnlyProof<Hasher>,
    phash: Digest,
    chash: Digest,
}

/// Generate N audit proofs from a new tree
async fn generate_audit_proofs(n: usize) -> Result<Vec<AuditInformation>, akd::errors::AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Hasher>(&db, &vrf, false).await?;
    let mut proofs = vec![];
    // gather the hash + azks for epoch "0" (init)
    let mut azks = akd.retrieve_current_azks().await?;
    let mut phash = akd.get_root_hash::<Hasher>(&azks).await?;

    for _epoch in 1..=n {
        // generate (n) epochs of updates on the same user
        let t_value = format!("certificate{}", _epoch);
        akd.publish::<Hasher>(vec![(
            AkdLabel::from_utf8_str("user"),
            AkdValue::from_utf8_str(&t_value),
        )])
        .await?;
        // generate the append-only proof
        let proof = akd
            .audit::<Hasher>((_epoch - 1) as u64, _epoch as u64)
            .await?;
        // update the azks + retrieve the updated hash
        azks = akd.retrieve_current_azks().await?;
        let chash = akd.get_root_hash::<Hasher>(&azks).await?;

        // we have everything we need, pass it along
        let info = AuditInformation {
            phash,
            chash,
            proof,
        };
        proofs.push(info);

        // reset the "previous" hash for the next iteration
        phash = chash;
    }
    Ok(proofs)
}

/// Flush the storage bucket of all blobs + delete the bucket (if it exists)
async fn maybe_flush_storage(shared_config: &SdkConfig, bucket_name: &str) -> Result<()> {
    // Build the S3 config from the shared SdkConfig
    let config = S3ConfigBuilder::from(shared_config)
        .retry_config(RetryConfig::disabled())
        .build();
    // get the S3 client
    let client = Client::from_conf(config);
    // check if the bucket exists
    let buckets = client.list_buckets().send().await?;

    if let Some(bucket_names) = buckets.buckets() {
        log::info!("Found {} buckets in the test storage", bucket_names.len());

        if let Some(_) = bucket_names.iter().find(|bucket| {
            if let Some(maybe_bucket) = bucket.name() {
                return maybe_bucket == bucket_name;
            }
            false
        }) {
            log::info!("Found target bucket {}, deleting.", bucket_name);

            // From: https://docs.aws.amazon.com/sdk-for-rust/latest/dg/rust_s3_code_examples.html
            let objects = client.list_objects_v2().bucket(bucket_name).send().await?;
            // let mut delete_objects: Vec<ObjectIdentifier> = vec![];
            let delete_objects = objects
                .contents()
                .unwrap_or_default()
                .iter()
                .map(|obj| {
                    ObjectIdentifier::builder()
                        .set_key(Some(obj.key().unwrap().to_string()))
                        .build()
                })
                .collect::<Vec<_>>();

            if !delete_objects.is_empty() {
                log::info!(
                    "Bucket {} has {} objects in it which must be delete first",
                    bucket_name,
                    delete_objects.len()
                );
                client
                    .delete_objects()
                    .bucket(bucket_name)
                    .delete(Delete::builder().set_objects(Some(delete_objects)).build())
                    .send()
                    .await?;
            }
            client.delete_bucket().bucket(bucket_name).send().await?;
        }
    }
    Ok(())
}

/// Populate a test bucket with `n` audit proofs
async fn populate_test_storage(
    shared_config: &SdkConfig,
    bucket: &str,
    n_blobs: usize,
) -> Result<()> {
    maybe_flush_storage(shared_config, bucket).await?;

    // Build the S3 config from the shared SdkConfig
    let config = S3ConfigBuilder::from(shared_config)
        .retry_config(RetryConfig::disabled())
        .build();
    // get the S3 client
    let client = Client::from_conf(config);
    // create the bucket
    client
        .create_bucket()
        .bucket(bucket.to_string())
        .send()
        .await?;
    // Generate a block of real, verifiable audit proofs
    let proofs = generate_audit_proofs(n_blobs)
        .await
        .map_err(|akd_err| anyhow::anyhow!("AKD Error generating proofs: {}", akd_err))?;

    // upload each proof blob into S3
    for AuditInformation {
        chash,
        phash,
        proof,
    } in proofs
    {
        // Generate the s3 compat format
        let blobs = akd::proto::generate_audit_blobs(vec![phash, chash], proof)
            .map_err(|err| anyhow::anyhow!("Error generating audit blob {}", err))?;
        // Grab the blob + upload it
        if let Some(blob) = blobs.first() {
            let byte_stream = ByteStream::from(blob.data.clone());
            let name = blob.name.to_string();
            client
                .put_object()
                .bucket(bucket.to_string())
                .key(name)
                .body(byte_stream)
                .send()
                .await?;
        } else {
            assert!(
                false,
                "We should never generate an empty blob array, but if we do crash hard & fast!"
            );
        }
    }
    Ok(())
}

fn get_s3_storage(bucket: &str) -> S3AuditStorage {
    let clap_args = S3ClapSettings {
        bucket: bucket.to_string(),
        region: TEST_REGION.to_string(),
        endpoint: Some(TEST_ENDPOINT.to_string()),
        access_key: Some(ACCESS_KEY.to_string()),
        secret_key: Some(SECRET_KEY.to_string()),
    };
    (&clap_args).into()
}

// =========================== Test Cases =========================== //

#[tokio::test]
#[ignore]
async fn integration_test_bucket_listing() -> Result<()> {
    // make sure we have a valid bucket name, that's "somewhat" unique
    let bucket = bucket_name!();
    log::debug!("Test bucket name is {}", bucket);
    assert!(matches!(validate_bucket_name(&bucket), Ok(_)));

    // Get the storage reader
    let storage = get_s3_storage(&bucket);
    let shared_config = storage.get_shared_config().await;

    // Populate the test storage
    populate_test_storage(&shared_config, &bucket, 10).await?;

    // List the epochs found in the storage layer
    let mut epoch_summaries: Vec<EpochSummary> = storage.list_proofs().await?;
    epoch_summaries.sort_by(|a, b| a.name.epoch.cmp(&b.name.epoch));

    // There should be 10 proofs in the storage layer
    log::info!(
        "There are {} epochs in the storage layer",
        epoch_summaries.len()
    );
    assert_eq!(10, epoch_summaries.len());

    // check the linear history of the proofs
    log::info!("Checking linear history of audit proofs");
    for (i, summary) in epoch_summaries.into_iter().enumerate() {
        assert_eq!(i as u64, summary.name.epoch);
    }

    // if the test is successful, try a cleanup of the storage now
    maybe_flush_storage(&shared_config, &bucket).await?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn integration_test_audit_verification() -> Result<()> {
    // make sure we have a valid bucket name, that's "somewhat" unique
    let bucket = bucket_name!();
    log::debug!("Test bucket name is {}", bucket);
    assert!(matches!(validate_bucket_name(&bucket), Ok(_)));

    // Get the storage reader
    let storage = get_s3_storage(&bucket);
    let shared_config = storage.get_shared_config().await;

    // Populate the test storage
    populate_test_storage(&shared_config, &bucket, 3).await?;

    // List the epochs found in the storage layer
    let mut epoch_summaries: Vec<EpochSummary> = storage.list_proofs().await?;
    epoch_summaries.sort_by(|a, b| a.name.epoch.cmp(&b.name.epoch));

    // There should be 3 proofs in the storage layer
    log::info!(
        "There are {} epochs in the storage layer",
        epoch_summaries.len()
    );
    assert_eq!(3, epoch_summaries.len());

    // verify all fo the audit proofs
    for epoch in 0..=2 {
        let proof_blob = storage.get_proof(epoch).await?;
        log::info!("Verification epoch {} -> {}", epoch, epoch + 1);
        crate::auditor::audit_epoch::<Hasher>(proof_blob.clone(), false).await?;
        crate::auditor::audit_epoch::<Hasher>(proof_blob, true).await?;
    }

    // if the test is successful, try a cleanup of the storage now
    maybe_flush_storage(&shared_config, &bucket).await?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn populate_test_bucket() -> Result<()> {
    // Populates the test bucket for use with the command-line REPL via the command
    // cargo run -p akd_local_auditor -- s3 --bucket populatetestbucket --region us-east-2 --endpoint http://127.0.0.1:9000 --access-key test --secret-key someLongAccessKey

    // make sure we have a valid bucket name, that's "somewhat" unique
    let bucket = bucket_name!();
    log::debug!("Test bucket name is {}", bucket);
    assert!(matches!(validate_bucket_name(&bucket), Ok(_)));

    // Get the storage reader
    let storage = get_s3_storage(&bucket);
    let shared_config = storage.get_shared_config().await;

    // Populate the test storage
    populate_test_storage(&shared_config, &bucket, 50).await?;

    Ok(())
}

#[test]
fn test_bucket_name_parsing() -> Result<()> {
    let too_short = "a";
    assert!(matches!(super::validate_bucket_name(too_short), Err(_)));

    let too_long = "1234567890123456789012345678901234567890123456789012345678901234567890";
    assert!(matches!(super::validate_bucket_name(too_long), Err(_)));

    let bad_chars = "!@#$%^&*()_+";
    assert!(matches!(super::validate_bucket_name(bad_chars), Err(_)));

    let ok_1 = "12345";
    let ok_2 = "some-bucket-name";
    let ok_3 = "some.bucket.name";

    assert!(matches!(super::validate_bucket_name(ok_1), Ok(_)));
    assert!(matches!(super::validate_bucket_name(ok_2), Ok(_)));
    assert!(matches!(super::validate_bucket_name(ok_3), Ok(_)));

    Ok(())
}

#[test]
fn test_uri_parsing() -> Result<()> {
    let non_uri = "hasdf!@#";
    let bad_port = "http://localhost:1234%567891230";

    assert!(matches!(super::validate_uri(non_uri), Err(_)));
    assert!(matches!(super::validate_uri(bad_port), Err(_)));
    assert!(matches!(super::validate_uri("/test/uri"), Err(_)));

    assert!(matches!(super::validate_uri("www.ok.com"), Ok(_)));
    assert!(matches!(super::validate_uri("http://ok.com"), Ok(_)));
    assert!(matches!(
        super::validate_uri("http://127.0.0.1:9000"),
        Ok(_)
    ));
    assert!(matches!(
        super::validate_uri("http://east-us-2.aws.com:123"),
        Ok(_)
    ));

    Ok(())
}
