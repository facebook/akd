// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module holds the auditor operations based on binary-encoded AuditProof blobs

use super::storage::{EpochSummary, ProofIndexCacheOption};

use akd::Digest;
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use rustyrepl::ReplCommandProcessor;
use std::sync::Arc;

pub(crate) const HISTORY_FILE: &str = ".akd_local_auditor_history";

fn format_qr_record(p_hash: Digest, c_hash: Digest, epoch: u64) -> Vec<u8> {
    let epoch_bytes = epoch.to_le_bytes();
    let header = "WA_AKD_VERIFY".as_bytes();

    let mut result = vec![];
    result.extend(header);
    result.extend(epoch_bytes);
    result.extend(p_hash);
    result.extend(c_hash);
    result
}

pub async fn audit_epoch(blob: akd::local_auditing::AuditBlob, qr: bool) -> Result<()> {
    // decode the proof
    let (epoch, p_hash, c_hash, proof) = blob.decode().map_err(|err| anyhow!("{:?}", err))?;

    // verify it
    if let Err(akd_error) = akd::auditor::audit_verify(
        vec![p_hash, c_hash],
        akd::AppendOnlyProof {
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
            let qr_code_data = format_qr_record(p_hash, c_hash, epoch);
            if let Err(error) = qr2term::print_qr(qr_code_data) {
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
        /// Force refreshing the index of proofs (i.e. don't use the cache)
        #[clap(long)]
        force_refresh: bool,
    },
    /// Show the available epochs to audit
    ShowEpochs {
        /// Force refreshing the index of proofs (i.e. don't use the cache)
        #[clap(long)]
        force_refresh: bool,
    },
}

/// Audit opertions supported by the client
#[derive(Parser, Clone, Debug)]
pub struct AuditArgs {
    #[clap(subcommand)]
    command: AuditCommand,
}

/// Audit processing crate
#[derive(Debug)]
pub struct AuditProcessor {
    pub storage: Box<dyn crate::storage::AuditProofStorage>,
    pub last_summaries: Arc<tokio::sync::RwLock<Option<Vec<EpochSummary>>>>,
}

impl AuditProcessor {
    pub fn new_repl_processor(
        storage: Box<dyn crate::storage::AuditProofStorage>,
    ) -> Box<dyn rustyrepl::ReplCommandProcessor<AuditArgs>> {
        Box::new(crate::auditor::AuditProcessor {
            storage,
            last_summaries: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }
}

#[async_trait::async_trait]
impl ReplCommandProcessor<AuditArgs> for AuditProcessor {
    fn is_quit(&self, command: &str) -> bool {
        matches!(command, "quit" | "exit")
    }

    async fn process_command(&self, cmd: AuditArgs) -> Result<()> {
        let default_cache_control = self.storage.default_cache_control();

        match &cmd.command {
            AuditCommand::Audit {
                epoch,
                qr,
                force_refresh,
            } => {
                let cache_control = if *force_refresh {
                    ProofIndexCacheOption::NoCache
                } else {
                    default_cache_control
                };

                // did they already call show-epochs below? If so, can we utilize the cached result to save
                // another scan operation?
                let proofs = if cache_control == ProofIndexCacheOption::UseCache {
                    let summaries = &*(self.last_summaries.read().await);
                    if let Some(cached_result) = summaries {
                        cached_result.clone()
                    } else {
                        self.storage.list_proofs(cache_control).await?
                    }
                } else {
                    self.storage.list_proofs(cache_control).await?
                };

                let maybe_proof = proofs.iter().find(|proof| proof.name.epoch == *epoch);
                if let Some(epoch_summary) = maybe_proof {
                    let proof = self.storage.get_proof(epoch_summary).await?;
                    audit_epoch(proof, *qr).await?;
                }
            }
            AuditCommand::ShowEpochs { force_refresh } => {
                let cache_control = if *force_refresh {
                    ProofIndexCacheOption::NoCache
                } else {
                    default_cache_control
                };

                let mut proofs = self.storage.list_proofs(cache_control).await?;
                *self.last_summaries.write().await = Some(proofs.clone());
                display_audit_proofs_info(&mut proofs)?;
            }
        }
        Ok(())
    }
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

    println!(
        "Audit history is available between epochs ({}) and ({}), inclusively.",
        min.name.epoch, max.name.epoch
    );

    Ok(())
}
