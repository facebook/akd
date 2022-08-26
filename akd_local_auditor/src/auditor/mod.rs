// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module holds the auditor operations based on binary-encoded AuditProof blobs

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use log::{debug, error, info, warn};
use std::marker::{Send, Sync};

use rustyline::error::ReadlineError;
use rustyline::Editor;

const HISTORY_FILE: &str = ".akd_local_auditor_history";

fn format_qr_record<H>(p_hash: H::Digest, c_hash: H::Digest, epoch: u64) -> Vec<u8>
where
    H: winter_crypto::Hasher,
{
    let p_bytes = akd::serialization::from_digest::<H>(p_hash);
    let c_bytes = akd::serialization::from_digest::<H>(c_hash);
    let epoch_bytes = epoch.to_le_bytes();
    let header = "WA_AKD_VERIFY".as_bytes();

    let mut result = vec![];
    result.extend(header);
    result.extend(epoch_bytes);
    result.extend(p_bytes);
    result.extend(c_bytes);
    result
}

pub async fn audit_epoch<H>(blob: akd::proto::AuditBlob, qr: bool) -> Result<()>
where
    H: winter_crypto::Hasher + Sync + Send,
{
    // decode the proof
    let (epoch, p_hash, c_hash, proof) = blob.decode().map_err(|err| anyhow!("{}", err))?;

    // verify it
    if let Err(akd_error) = akd::auditor::audit_verify(
        vec![p_hash, c_hash],
        akd::proof_structs::AppendOnlyProof::<crate::Hasher> {
            proofs: vec![proof],
            epochs: vec![epoch],
        },
    )
    .await
    {
        warn!(
            "Audit proof for epoch {} failed to verify with error {}",
            epoch, akd_error
        );
    } else {
        // verification passed, generate the appropriate QR code
        info!("Audit proof for epoch {} has verified!", epoch);
        if qr {
            info!("Generating scan-able QR code for the verification on device");
            let qr_code_data = format_qr_record::<crate::Hasher>(p_hash, c_hash, epoch);
            if let Err(error) = qr2term::print_qr(&qr_code_data) {
                error!("Error generating QR code {}", error);
                bail!("Error generating QR code {}", error);
            }
        }
    }
    Ok(())
}

/// Storage options for retrieving audit proofs
#[derive(Subcommand, Clone, Debug)]
pub enum AuditCommand {
    /// Audit a specific epoch
    Audit {
        /// The epoch to audit
        #[clap(long)]
        epoch: u64,
        /// Show a QR code of the audit
        #[clap(long)]
        qr: bool,
    },
    /// Show the available epochs to audit
    ShowEpochs,
}

/// Audit opertions supported by the client
#[derive(Parser, Clone, Debug)]
pub struct AuditArgs {
    #[clap(subcommand)]
    command: AuditCommand,
}

fn display_audit_proofs_info(info: &mut Vec<crate::storage::EpochSummary>) -> Result<()> {
    info.sort_by(|a, b| a.name.epoch.cmp(&b.name.epoch));
    if info.is_empty() {
        bail!("There are no epochs present in the storage repository");
    }

    let min = info.first().unwrap().clone();
    let max = info.last().unwrap().clone();
    let (maybe_broken_epoch, is_contiguous) =
        info.iter()
            .skip(1)
            .fold((min.clone(), true), |(previous_item, cont), item| {
                if !cont {
                    (previous_item, cont)
                } else {
                    (
                        item.clone(),
                        item.name.epoch == previous_item.name.epoch + 1,
                    )
                }
            });

    if !is_contiguous {
        bail!("The audit proofs appear to not be continguous. There's a break in the linear history at epoch {}", maybe_broken_epoch.name.epoch);
    }

    info!(
        "Audit history is available between epochs ({}) and ({}), inclusively.",
        min.name.epoch, max.name.epoch
    );

    Ok(())
}

async fn process_command(
    storage: &dyn crate::storage::AuditProofStorage,
    cmd: &AuditArgs,
) -> Result<()> {
    match &cmd.command {
        AuditCommand::Audit { epoch, qr } => {
            let proof = storage.get_proof(*epoch).await?;
            audit_epoch::<crate::Hasher>(proof, *qr).await?;
        }
        AuditCommand::ShowEpochs => {
            let mut proofs = storage.list_proofs().await?;
            display_audit_proofs_info(&mut proofs)?;
        }
    }
    Ok(())
}

pub async fn auditor_repl(storage: &dyn crate::storage::AuditProofStorage) -> Result<()> {
    info!("Starting auditing REPL. Enter [exit] or [x] to exit.");
    let history_file = dirs::home_dir().map(|mut home_dir| {
        home_dir.push(HISTORY_FILE);
        home_dir
    });

    let mut rl = Editor::<()>::new()?;
    if let Some(history) = &history_file {
        if rl.load_history(history).is_ok() {
            debug!("Command history loaded");
        }
    }

    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                // process command
                let parts: Vec<&str> = line.split(' ').collect();
                let mut command = String::new();
                if let Some(head) = parts.first() {
                    command = String::from(*head);
                }
                match command.to_lowercase().as_ref() {
                    "exit" | "x" => break,
                    "" => {} // just loop, someone hit enter with no input
                    _ => {
                        // the first part of the iterator _must_ be the binary name, the rest are args
                        let mut cmd_parts: Vec<&str> = vec!["auditor"];
                        cmd_parts.extend(parts.iter().copied());
                        match AuditArgs::try_parse_from(cmd_parts.into_iter()) {
                            Ok(cli) => {
                                // We're only appending valid commands to the history trail
                                rl.add_history_entry(line.as_str());

                                warn!("Received input {}", line);

                                if let Err(err) = process_command(storage, &cli).await {
                                    error!("Error processing command '{}'", err);
                                }
                            }
                            Err(clap_err) => match clap::Error::kind(&clap_err) {
                                clap::ErrorKind::DisplayHelp | clap::ErrorKind::DisplayVersion => {
                                    info!("{}", clap_err);
                                }
                                _ => {
                                    warn!(
                                        "Invalid command (type 'help' for the help menu)\r\n{}",
                                        clap_err
                                    );
                                }
                            },
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted) => break,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    println!("Terminating the Soteria client REPL");
    if let Some(history) = &history_file {
        if let Err(save_err) = rl.save_history(history) {
            error!("Failed to save command history: {:?}", save_err);
        }
    }
    Ok(())
}
