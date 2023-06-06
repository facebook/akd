// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! A note to readers:
//!
//! We are marking most of the following tests as `#[ignored]` so they don't run automatically
//! with `cargo test`. These require a docker container running `minio` to be running which is
//! run in our CI pipeline when changes to this crate are made, but not otherwise since they
//! are relatively expensive integration test operations. See [s3.yml](.github/workflows/s3.yml)
//! for more information

use super::*;
use crate::common_test::AuditInformation;
use crate::storage::s3;
use crate::storage::AuditProofStorage;
use akd::configuration::WhatsAppV1Configuration;
use anyhow::Result;
use aws_sdk_dynamodb::types::Blob;
use aws_smithy_http::byte_stream::ByteStream;

// These are constants that are matched in both this crate's `docker-compose.yml`
// and the aws.yml workflow pipeline
const ACCESS_KEY: &str = "test";
const SECRET_KEY: &str = "someLongAccessKey";
const TEST_REGION: &str = "us-east-2";
const TEST_DYNAMO_ENDPOINT: &str = "http://127.0.0.1:9002";
const TEST_S3_ENDPOINT: &str = "http://127.0.0.1:9000";

#[test]
fn test_dynamo_table_naming() {
    let too_short = "a";
    assert!(matches!(super::validate_table_name(too_short), Err(_)));

    // take a-z until we reach 260 char's, then gen the string
    let too_long = ('a'..='z').cycle().take(260).collect::<String>();
    assert!(matches!(super::validate_table_name(&too_long), Err(_)));

    let bad_chars = "!@#$%^&*()_+";
    assert!(matches!(super::validate_table_name(bad_chars), Err(_)));

    // Ok matches
    assert!(matches!(super::validate_table_name("table123"), Ok(_)));
    assert!(matches!(
        super::validate_table_name("some-table-name"),
        Ok(_)
    ));
    assert!(matches!(
        super::validate_table_name("some.table.name"),
        Ok(_)
    ));
    assert!(matches!(
        super::validate_table_name("some_table_name"),
        Ok(_)
    ));
}

#[tokio::test]
#[ignore]
async fn integration_test_dynamo_listing() {
    // make sure we have a valid bucket name, that's "somewhat" unique
    let table = crate::common_test::alphanumeric_function_name!();
    log::debug!("Test bucket and table name is {}", table);
    assert!(matches!(s3::validate_bucket_name(&table), Ok(_)));
    assert!(matches!(validate_table_name(&table), Ok(_)));

    // Get the storage reader
    let storage = get_dynamo_storage(&table);
    let s3_storage: s3::S3AuditStorage = (&storage).into();

    // Note: We have 2 shared configs, because we have 2 different endpoints here which
    // we need to differentiate between. We could gin up our own endpoint resolver, but
    // this is much easier to work with
    let dynamo_shared_config = storage.get_shared_config().await;
    let s3_shared_config = s3_storage.get_shared_test_config().await;

    // Populate the test storage
    populate_test_storage(&dynamo_shared_config, &s3_shared_config, &table, 10, false)
        .await
        .expect("Failed to populate test storage");

    // List the epochs found in the storage layer
    let mut epoch_summaries: Vec<EpochSummary> = storage
        .list_proofs(ProofIndexCacheOption::NoCache)
        .await
        .expect("Failed to list proofs");
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
    maybe_flush_storage(&dynamo_shared_config, &s3_shared_config, &table)
        .await
        .expect("Failed to flush storage");
}

#[tokio::test]
#[ignore]
async fn integration_test_dynamo_audit_verification() {
    // make sure we have a valid bucket name, that's "somewhat" unique
    let table = crate::common_test::alphanumeric_function_name!();
    log::debug!("Test bucket and table name is {}", table);
    assert!(matches!(s3::validate_bucket_name(&table), Ok(_)));
    assert!(matches!(validate_table_name(&table), Ok(_)));

    // Get the storage reader
    let storage = get_dynamo_storage(&table);
    let s3_storage: s3::S3AuditStorage = (&storage).into();

    // Note: We have 2 shared configs, because we have 2 different endpoints here which
    // we need to differentiate between. We could gin up our own endpoint resolver, but
    // this is much easier to work with
    let dynamo_shared_config = storage.get_shared_config().await;
    let s3_shared_config = s3_storage.get_shared_test_config().await;

    // Populate the test storage
    populate_test_storage(&dynamo_shared_config, &s3_shared_config, &table, 3, false)
        .await
        .expect("Failed to populate test storage");

    // List the epochs found in the storage layer
    let mut epoch_summaries: Vec<EpochSummary> = storage
        .list_proofs(ProofIndexCacheOption::NoCache)
        .await
        .unwrap();
    epoch_summaries.sort_by(|a, b| a.name.epoch.cmp(&b.name.epoch));

    // There should be 3 proofs in the storage layer
    log::info!(
        "There are {} epochs in the storage layer",
        epoch_summaries.len()
    );
    assert_eq!(3, epoch_summaries.len());

    // verify all fo the audit proofs
    for epoch in epoch_summaries.iter() {
        let proof_blob = storage.get_proof(epoch).await.unwrap();
        log::info!(
            "Verification epoch {} -> {}",
            epoch.name.epoch,
            epoch.name.epoch + 1
        );
        crate::auditor::audit_epoch::<WhatsAppV1Configuration>(proof_blob.clone(), false)
            .await
            .unwrap();
        crate::auditor::audit_epoch::<WhatsAppV1Configuration>(proof_blob, true)
            .await
            .unwrap();
    }

    // if the test is successful, try a cleanup of the storage now
    maybe_flush_storage(&dynamo_shared_config, &s3_shared_config, &table)
        .await
        .expect("Failed to flush storage");
}

#[tokio::test]
#[ignore]
async fn populate_test_dynamo() {
    // Populates the test bucket for use with the command-line REPL via the command
    // cargo run -p akd_local_auditor -- dynamo-db --table populatetestdynamo --bucket populatetestdynamo --region us-east-2 --s3-endpoint http://127.0.0.1:9000 --dynamo-endpoint http://127.0.0.1:9002 --access-key test --secret-key someLongAccessKey

    // make sure we have a valid bucket name, that's "somewhat" unique
    let table = crate::common_test::alphanumeric_function_name!();
    log::debug!("Test bucket and table name is {}", table);
    assert!(matches!(s3::validate_bucket_name(&table), Ok(_)));
    assert!(matches!(validate_table_name(&table), Ok(_)));

    // Get the storage reader
    let storage = get_dynamo_storage(&table);
    let s3_storage: s3::S3AuditStorage = (&storage).into();

    // Note: We have 2 shared configs, because we have 2 different endpoints here which
    // we need to differentiate between. We could gin up our own endpoint resolver, but
    // this is much easier to work with
    let dynamo_shared_config = storage.get_shared_config().await;
    let s3_shared_config = s3_storage.get_shared_test_config().await;

    // Populate the test storage
    populate_test_storage(&dynamo_shared_config, &s3_shared_config, &table, 50, false)
        .await
        .expect("Failed to populate test storage");
}

fn build_dynamo_table_properties(
    query: dynamo::client::fluent_builders::CreateTable,
) -> dynamo::client::fluent_builders::CreateTable {
    use aws_sdk_dynamodb::model::{
        AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
    };

    let primary_key = "epoch".to_string();

    let ad = AttributeDefinition::builder()
        .attribute_name(&primary_key)
        .attribute_type(ScalarAttributeType::N)
        .build();

    let ks = KeySchemaElement::builder()
        .attribute_name(&primary_key)
        .key_type(KeyType::Hash)
        .build();

    let pt = ProvisionedThroughput::builder()
        .read_capacity_units(100)
        .write_capacity_units(5)
        .build();

    query
        .key_schema(ks)
        .attribute_definitions(ad)
        .provisioned_throughput(pt)
}

/// Populate a test bucket with `n` audit proofs
async fn populate_test_storage(
    dynamo_shared_config: &aws_config::SdkConfig,
    s3_shared_config: &aws_config::SdkConfig,
    table: &str,
    n_blobs: usize,
    expensive: bool,
) -> Result<()> {
    // flush all the storage, so we're starting fresh
    maybe_flush_storage(dynamo_shared_config, s3_shared_config, table).await?;

    // Build the S3 config from the shared SdkConfig
    let config = aws_sdk_s3::config::Builder::from(s3_shared_config)
        .retry_config(aws_sdk_s3::RetryConfig::disabled())
        .build();
    // get the S3 & dynamo clients
    let s3_client = aws_sdk_s3::Client::from_conf(config);
    let dynamo_client = aws_sdk_dynamodb::Client::new(dynamo_shared_config);

    // create the bucket
    log::debug!("Creating S3 bucket {}", table);
    s3_client
        .create_bucket()
        .bucket(table.to_string())
        .send()
        .await?;
    log::debug!("Creating DynamoDb table {}", table);
    // create the table
    build_dynamo_table_properties(dynamo_client.create_table().table_name(table.to_string()))
        .send()
        .await?;

    log::debug!("Generating {} proofs", n_blobs);
    // Generate a block of real, verifiable audit proofs
    let proofs = crate::common_test::generate_audit_proofs(n_blobs, expensive)
        .await
        .map_err(|akd_err| anyhow::anyhow!("AKD Error generating proofs: {}", akd_err))?;

    log::info!("Uploading proofs to S3 and DynamoDb...");
    // upload each proof blob into S3 and the dynamo index
    for AuditInformation {
        chash,
        phash,
        proof,
    } in proofs
    {
        // Generate the s3 compat format
        let blobs = akd::local_auditing::generate_audit_blobs(vec![phash, chash], proof)
            .map_err(|err| anyhow::anyhow!("Error generating audit blob {:?}", err))?;
        // Grab the blob + upload it
        if let Some(blob) = blobs.first() {
            let byte_stream = ByteStream::from(blob.data.clone());
            let name = blob.name.to_string();
            s3_client
                .put_object()
                .bucket(table.to_string())
                .key(name)
                .body(byte_stream)
                .send()
                .await?;

            let request = dynamo_client
                .put_item()
                .table_name(table.to_string())
                .item("epoch", AttributeValue::N(blob.name.epoch.to_string()))
                .item(
                    "previous_hash",
                    AttributeValue::B(Blob::new(blob.name.previous_hash.to_vec())),
                )
                .item(
                    "current_hash",
                    AttributeValue::B(Blob::new(blob.name.current_hash.to_vec())),
                )
                .item("blob", AttributeValue::S(blob.name.to_string()));

            request.send().await?;
        } else {
            panic!("We should never generate an empty blob array, but if we do crash hard & fast!");
        }
    }
    Ok(())
}

async fn maybe_flush_storage(
    dynamo_shared_config: &aws_config::SdkConfig,
    s3_shared_config: &aws_config::SdkConfig,
    table: &str,
) -> Result<()> {
    // flush S3
    s3::test::maybe_flush_storage(s3_shared_config, table).await?;
    log::info!("S3 bucket {} flushed", table);

    // flush dynamo
    let client = aws_sdk_dynamodb::Client::new(dynamo_shared_config);
    // describe the table
    let table_exists = client
        .list_tables()
        .send()
        .await?
        .table_names()
        .as_ref()
        .unwrap()
        .contains(&table.into());
    if table_exists {
        // if exists, delete it
        client
            .delete_table()
            .table_name(table.to_string())
            .send()
            .await?;
    }
    log::info!("Dynamo table {} flushed", table);

    Ok(())
}

fn get_dynamo_storage(table_and_bucket_name: &str) -> DynamoDbAuditStorage {
    let clap_args = DynamoDbClapSettings {
        bucket: table_and_bucket_name.to_string(),
        region: TEST_REGION.to_string(),
        dynamo_endpoint: Some(TEST_DYNAMO_ENDPOINT.to_string()),
        table: table_and_bucket_name.to_string(),
        s3_endpoint: Some(TEST_S3_ENDPOINT.to_string()),
        access_key: Some(ACCESS_KEY.to_string()),
        secret_key: Some(SECRET_KEY.to_string()),
    };
    (&clap_args).into()
}
