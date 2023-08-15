// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

use akd::configuration::Configuration;
use akd::ecvrf::VRFKeyStorage;
use akd::storage::Database;
use akd::HistoryParams;
use akd::{AkdLabel, AkdValue};
use akd::{Directory, EpochHash};
use log::{error, info};
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

pub(crate) async fn init_host<TC, S, V>(rx: &mut Receiver<Rpc>, directory: &mut Directory<TC, S, V>)
where
    TC: Configuration,
    S: Database + 'static,
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
                    .publish(vec![(AkdLabel::from(&a), AkdValue::from(&b))])
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
                        let msg = format!("Failed to publish with error: {error:?}");
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
                            .map(|(key, value)| (AkdLabel::from(&key), AkdValue::from(&value)))
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
                        let msg = format!("Failed to publish with error: {error:?}");
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::Lookup(a), Some(response)) => {
                match directory.lookup(AkdLabel::from(&a)).await {
                    Ok((proof, root_hash)) => {
                        let vrf_pk = directory.get_public_key().await.unwrap();
                        let verification = akd::client::lookup_verify::<TC>(
                            vrf_pk.as_bytes(),
                            root_hash.hash(),
                            root_hash.epoch(),
                            AkdLabel::from(&a),
                            proof,
                        );
                        if verification.is_err() {
                            let msg = format!("WARN: Lookup proof failed verification for '{a}'");
                            response.send(Err(msg)).unwrap();
                        } else {
                            let msg = format!("Lookup proof verified for user '{a}'");
                            response.send(Ok(msg)).unwrap();
                        }
                    }
                    Err(error) => {
                        let msg = format!("Failed to lookup with error {error:?}");
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::KeyHistory(a), Some(response)) => {
                match directory
                    .key_history(&AkdLabel::from(&a), HistoryParams::default())
                    .await
                {
                    Ok(_proof) => {
                        let msg = format!("GOT KEY HISTORY FOR '{a}'");
                        response.send(Ok(msg)).unwrap();
                    }
                    Err(error) => {
                        let msg = format!("Failed to lookup with error {error:?}");
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::Audit(start, end), Some(response)) => {
                match directory.audit(start, end).await {
                    Ok(_proof) => {
                        let msg = format!("GOT AUDIT PROOF BETWEEN ({start}, {end})");
                        response.send(Ok(msg)).unwrap();
                    }
                    Err(error) => {
                        let msg = format!("Failed to get audit proof with error {error:?}");
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::RootHash, Some(response)) => {
                let hash = directory.get_epoch_hash().await;
                match hash {
                    Ok(EpochHash(_, hash)) => {
                        let msg = format!("Retrieved root hash {}", hex::encode(hash));
                        response.send(Ok(msg)).unwrap();
                    }
                    Err(error) => {
                        let msg = format!("Failed to retrieve root hash with error {error:?}");
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
