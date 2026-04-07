// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! A tool for verifying audit proofs published from WhatsApp's key transparency implementation

mod auditor;

use akd::local_auditing::AuditBlobName;
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::convert::TryFrom;
use std::time::Duration;

// Default domain for WhatsApp's key transparency audit proofs
const WHATSAPP_KT_V1_DOMAIN: &str = "https://d1tfr3x7n136ak.cloudfront.net";
const WHATSAPP_KT_V2_DOMAIN: &str = "https://d4ttn6vhp3mg0.cloudfront.net";

#[derive(Clone, Debug, Default, clap::ValueEnum)]
pub(crate) enum LogVersion {
    /// The legacy WhatsApp KT log
    V1,
    /// The current WhatsApp KT log
    #[default]
    V2,
}

impl LogVersion {
    fn url(&self) -> &'static str {
        match self {
            LogVersion::V1 => WHATSAPP_KT_V1_DOMAIN,
            LogVersion::V2 => WHATSAPP_KT_V2_DOMAIN,
        }
    }
}

type TC = akd::WhatsAppV1Configuration;

/// Represents the summary of an epoch, and a unique key referring to the raw object in native storage (if needed)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct EpochSummary {
    /// The name of the audit-blob decomposed into parts
    pub name: AuditBlobName,
    /// Unique idenfier for the blob in question
    pub key: String,
}

impl TryFrom<&str> for EpochSummary {
    type Error = anyhow::Error;

    fn try_from(potential_key: &str) -> Result<Self, Self::Error> {
        let name = AuditBlobName::try_from(potential_key).map_err(|err| anyhow!("{:?}", err))?;

        Ok(Self {
            name,
            key: potential_key.to_string(),
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(author, about, long_about = None)]
pub(crate) struct CliArgs {
    /// Which log version to audit (v1 = legacy, v2 = current)
    #[clap(long, default_value = "v2")]
    log: LogVersion,

    /// The type of command to run
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Audit a specific epoch
    #[clap(short_flag = 'e')]
    Epoch { epoch: u64 },
    /// Load all epochs and choose which to audit interactively
    #[clap(short_flag = 'i')]
    Interactive,
    /// Audit only the latest epoch
    #[clap(short_flag = 'l')]
    AuditLatest,
}

#[derive(Debug)]
enum CliType {
    Audit,
    Quit,
}

struct CliOption {
    cli_type: CliType,
    text: String,
}

pub(crate) async fn render_cli(args: CliArgs) -> Result<()> {
    let url = args.log.url();
    match args.command {
        Command::AuditLatest => {
            // Just audit the latest epoch and exit
            let proofs = load_all_proofs(url).await?;
            let latest_epoch_summary = proofs.last().expect("No epochs found");
            do_epoch_audit(url, latest_epoch_summary).await?;
            return Ok(());
        }
        Command::Epoch { epoch } => {
            let epoch_summary = auditor::get_proof_from_epoch(url, epoch).await?;
            do_epoch_audit(url, &epoch_summary).await?;
            return Ok(());
        }
        Command::Interactive => {
            let proofs = load_all_proofs(url).await?;
            let items: Vec<CliOption> = vec![
                CliOption {
                    cli_type: CliType::Audit,
                    text: "Audit".to_string(),
                },
                CliOption {
                    cli_type: CliType::Quit,
                    text: "Quit".to_string(),
                },
            ];

            loop {
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .items(
                        &items
                            .iter()
                            .map(|item| item.text.clone())
                            .collect::<Vec<String>>(),
                    )
                    .default(0)
                    .interact_opt()?;

                match selection {
                    Some(index) => match items[index].cli_type {
                        CliType::Audit => {
                            let epoch_input: String = Input::new()
                                .with_prompt("Audit which epoch?".to_string())
                                .validate_with(|input: &String| -> Result<(), &str> {
                                    let int =
                                        input.parse::<usize>().map_err(|_| "Not a valid epoch")?;
                                    if 1 <= int && int <= proofs.len() {
                                        Ok(())
                                    } else {
                                        Err("Epoch is out of available range")
                                    }
                                })
                                .interact_text()?;
                            let epoch = epoch_input.parse::<u64>()?;
                            let maybe_proof = proofs.iter().find(|proof| proof.name.epoch == epoch);
                            let Some(epoch_summary) = maybe_proof else {
                                bail!("Could not find epoch {epoch}");
                            };
                            do_epoch_audit(url, epoch_summary).await?;
                        }
                        CliType::Quit => {
                            break;
                        }
                    },
                    None => {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn load_all_proofs(url: &str) -> Result<Vec<EpochSummary>> {
    let pb = start_progress_bar("Loading epochs...");
    let mut proofs = auditor::list_proofs(url).await?;
    finish_progress_bar(pb, auditor::display_audit_proofs_info(&mut proofs)?);
    Ok(proofs)
}

pub(crate) async fn do_epoch_audit(url: &str, epoch_summary: &EpochSummary) -> Result<()> {
    let pb1 = start_progress_bar("Downloading proof...");
    let proof = auditor::get_proof(url, epoch_summary).await?;
    finish_progress_bar(
        pb1,
        format!(
            "Successfully downloaded proof for epoch {}. ({})",
            epoch_summary.name.epoch,
            bytesize::ByteSize::b(proof.data.len() as u64)
        ),
    );

    let pb2 = start_progress_bar("Auditing...");
    let result = auditor::audit_epoch(proof).await?;
    finish_progress_bar(pb2, result);

    Ok(())
}

pub(crate) fn start_progress_bar(input_msg: &'static str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(input_msg);
    let waiting_style = ProgressStyle::default_spinner()
        .template("[{elapsed_precise}] {spinner:.cyan/blue} {msg:.yellow}")
        .unwrap()
        .tick_strings(&[
            "[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]",
            "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]",
        ]);

    pb.set_style(waiting_style);
    pb
}

pub(crate) fn finish_progress_bar(pb: ProgressBar, message: String) {
    let done_style = ProgressStyle::default_spinner()
        .template("[{elapsed_precise}] {msg:.bold.green}")
        .unwrap();
    pb.set_style(done_style);
    pb.finish_with_message(message);
}
