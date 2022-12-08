// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use akd::ecvrf::VRFKeyStorage;
use akd::errors::AkdError;
use akd::storage::types::*;
use akd::storage::{Database, StorageManager};
use akd::HistoryParams;
use akd::{AkdLabel, AkdValue, Digest};
use akd::{Directory, EpochHash};
use log::{debug, error, info};
use std::marker::{Send, Sync};
use tokio::sync::mpsc::*;
use tokio::time::Instant;

pub(crate) struct Rpc(
    pub(crate) DirectoryCommand,
    pub(crate) Option<tokio::sync::oneshot::Sender<Result<String, String>>>,
);

#[derive(Debug)]
pub enum DirectoryCommand {
    Publish(String, String),
    PublishBatch(Vec<(String, String)>),
    Lookup(String),
    KeyHistory(String),
    Audit(u64, u64),
    RootHash,
    Terminate,
}

async fn get_root_hash<S, V>(directory: &mut Directory<S, V>) -> Option<Result<Digest, AkdError>>
where
    S: Database + Sync + Send,
    V: VRFKeyStorage,
{
    if let Ok(azks) = directory.retrieve_current_azks().await {
        Some(directory.get_root_hash(&azks).await)
    } else {
        None
    }
}

pub(crate) async fn init_host<S, V>(rx: &mut Receiver<Rpc>, directory: &mut Directory<S, V>)
where
    S: Database + Sync + Send,
    V: VRFKeyStorage,
{
    info!("Starting the verifiable directory host");

    while let Some(Rpc(message, channel)) = rx.recv().await {
        match (message, channel) {
            (DirectoryCommand::Terminate, _) => {
                break;
            }
            (DirectoryCommand::Publish(a, b), Some(response)) => {
                let tic = Instant::now();
                match directory
                    .publish(vec![(
                        AkdLabel::from_utf8_str(&a),
                        AkdValue::from_utf8_str(&b),
                    )])
                    .await
                {
                    Ok(EpochHash(epoch, hash)) => {
                        let toc = Instant::now() - tic;
                        let msg = format!(
                            "PUBLISHED '{}' = '{}' in {} s (epoch: {}, root hash: {})",
                            a,
                            b,
                            toc.as_secs_f64(),
                            epoch,
                            hex::encode(hash)
                        );
                        response.send(Ok(msg)).unwrap()
                    }
                    Err(error) => {
                        let msg = format!("Failed to publish with error: {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::PublishBatch(batches), Some(response)) => {
                let tic = Instant::now();
                let len = batches.len();
                match directory
                    .publish(
                        batches
                            .into_iter()
                            .map(|(key, value)| {
                                (
                                    AkdLabel::from_utf8_str(&key),
                                    AkdValue::from_utf8_str(&value),
                                )
                            })
                            .collect(),
                    )
                    .await
                {
                    Ok(_) => {
                        let toc = Instant::now() - tic;
                        let msg = format!("PUBLISHED {} records in {} s", len, toc.as_secs_f64());
                        response.send(Ok(msg)).unwrap()
                    }
                    Err(error) => {
                        let msg = format!("Failed to publish with error: {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::Lookup(a), Some(response)) => {
                match directory.lookup(AkdLabel::from_utf8_str(&a)).await {
                    Ok((proof, root_hash)) => {
                        let hash = get_root_hash::<_, V>(directory).await;
                        let vrf_pk = directory.get_public_key().await.unwrap();
                        let verification = akd::client::lookup_verify(
                            vrf_pk.as_bytes(),
                            root_hash.hash(),
                            AkdLabel::from_utf8_str(&a),
                            proof,
                        );
                        if verification.is_err() {
                            let msg = format!("WARN: Lookup proof failed verification for '{}'", a);
                            response.send(Err(msg)).unwrap();
                        } else {
                            let msg = format!("Lookup proof verified for user '{}'", a);
                            response.send(Ok(msg)).unwrap();
                        }
                    }
                    Err(error) => {
                        let msg = format!("Failed to lookup with error {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::KeyHistory(a), Some(response)) => {
                match directory
                    .key_history(&AkdLabel::from_utf8_str(&a), HistoryParams::default())
                    .await
                {
                    Ok(_proof) => {
                        let msg = format!("GOT KEY HISTORY FOR '{}'", a);
                        response.send(Ok(msg)).unwrap();
                    }
                    Err(error) => {
                        let msg = format!("Failed to lookup with error {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::Audit(start, end), Some(response)) => {
                match directory.audit(start, end).await {
                    Ok(_proof) => {
                        let msg = format!("GOT AUDIT PROOF BETWEEN ({}, {})", start, end);
                        response.send(Ok(msg)).unwrap();
                    }
                    Err(error) => {
                        let msg = format!("Failed to get audit proof with error {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::RootHash, Some(response)) => {
                let hash = get_root_hash::<_, V>(directory).await;
                match hash {
                    Some(Ok(hash)) => {
                        let msg = format!("Retrieved root hash {}", hex::encode(hash));
                        response.send(Ok(msg)).unwrap();
                    }
                    Some(Err(error)) => {
                        let msg = format!("Failed to retrieve root hash with error {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                    None => {
                        let msg = "Failed to retrieve current AZKS structure".to_string();
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (_, None) => {
                error!("A channel was not provided to the directory server to process a command!");
            }
        }
    }

    info!("AKD host shutting down");
}
