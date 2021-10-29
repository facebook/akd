// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use seemless::seemless_directory::SeemlessDirectory;
use seemless::storage::types::*;
use seemless::storage::Storage;
use seemless::SeemlessError;
use tokio::sync::mpsc::*;
use winter_crypto::Hasher;

pub(crate) struct Rpc(
    pub(crate) DirectoryCommand,
    pub(crate) Option<tokio::sync::oneshot::Sender<Result<String, String>>>,
);

#[derive(Debug)]
pub enum DirectoryCommand {
    Publish(String, String),
    Lookup(String),
    KeyHistory(String),
    Audit(u64, u64),
    RootHash(Option<u64>),
    Terminate,
}

async fn get_root_hash<S, H>(directory: &mut SeemlessDirectory<S, H>, o_epoch: Option<u64>)
-> Option<Result<H::Digest, SeemlessError>>
where
    S: Storage + Sync + Send,
    H: Hasher + Send,
{
    if let Ok(azks) = directory.retrieve_current_azks().await {
        match o_epoch {
            Some(epoch) => Some(directory.get_root_hash_at_epoch(&azks, epoch).await),
            None => Some(directory.get_root_hash(&azks).await),
        }
    } else {
        None
    }
}

pub(crate) async fn init_host<S, H>(rx: &mut Receiver<Rpc>, directory: &mut SeemlessDirectory<S, H>)
where
    S: Storage + Sync + Send,
    H: Hasher + Send,
{
    println!("INFO: Starting the verifiable directory host");

    while let Some(Rpc(message, channel)) = rx.recv().await {
        match (message, channel) {
            (DirectoryCommand::Terminate, _) => {
                break;
            }
            (DirectoryCommand::Publish(a, b), Some(response)) => {
                match directory
                    .publish(vec![(Username(a.clone()), Values(b.clone()))])
                    .await
                {
                    Ok(_) => {
                        let msg = format!("PUBLISHED '{}' = '{}'", a, b);
                        response.send(Ok(msg)).unwrap()
                    }
                    Err(error) => {
                        let msg = format!("Failed to publish with error: {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::Lookup(a), Some(response)) => {
                match directory.lookup(Username(a.clone())).await {
                    Ok(proof) => {
                        let hash = get_root_hash(directory, None).await;
                        match hash {
                            Some(Ok(root_hash)) => {
                                let verification = seemless::seemless_client::lookup_verify(root_hash, Username(a.clone()), proof);
                                if verification.is_err() {
                                    let msg = format!("WARN: Lookup proof failed verification for '{}'", a);
                                    response.send(Ok(msg)).unwrap();
                                } else {
                                    let msg = format!("Lookup proof verified for user '{}'", a);
                                    response.send(Ok(msg)).unwrap();
                                }
                            },
                            _ => {
                                let msg = format!("GOT lookup proof for '{}', but unable to verify proof due to missing root hash", a);
                                response.send(Ok(msg)).unwrap();
                            }
                        }
                    }
                    Err(error) => {
                        let msg = format!("Failed to lookup with error {:?}", error);
                        response.send(Err(msg)).unwrap();
                    }
                }
            }
            (DirectoryCommand::KeyHistory(a), Some(response)) => {
                match directory.key_history(&Username(a.clone())).await {
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
            (DirectoryCommand::RootHash(o_epoch), Some(response)) => {
                let hash = get_root_hash(directory, o_epoch).await;
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
                println!("ERROR: A channel was not provided to the directory server to process a command!");
            }
        }
    }

    println!("INFO: VKD host shutting down");
}
