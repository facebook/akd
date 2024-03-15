// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module holds the auditor operations based on binary-encoded AuditProof blobs

use super::EpochSummary;

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use std::convert::TryFrom;
use xml::reader::XmlEvent;
use xml::EventReader;

// Constant strings specific to the XML returned from the Cloudfront bucket query
const KEY_STR: &str = "Key";
const IS_TRUNCATED_STR: &str = "IsTruncated";
const TRUE_STR: &str = "true";

/// Storage options for retrieving audit proofs
#[derive(Subcommand, Clone, Debug)]
pub enum AuditCommand {
    /// Audit a specific epoch
    Audit {
        /// The epoch to audit
        #[clap(long)]
        epoch: u64,
    },
    /// Load the available epochs to audit
    LoadEpochs,
}

/// Audit operations supported by the client
#[derive(Parser, Clone, Debug)]
pub struct AuditArgs {
    #[clap(subcommand)]
    command: AuditCommand,
}

pub(crate) async fn audit_epoch(blob: akd::local_auditing::AuditBlob) -> Result<String> {
    // decode the proof
    let (end_epoch, p_hash, c_hash, proof) = blob.decode().map_err(|err| anyhow!("{:?}", err))?;

    // verify it
    if let Err(akd_error) = akd::auditor::audit_verify::<super::TC>(
        vec![p_hash, c_hash],
        akd::AppendOnlyProof {
            proofs: vec![proof],
            epochs: vec![end_epoch - 1], // Note that the AppendOnlyProof struct expects epochs to begin with the starting epoch, not the ending epoch
        },
    )
    .await
    {
        bail!(
            "Audit proof for epoch {} failed to verify with error: {}",
            end_epoch,
            akd_error
        )
    } else {
        // verification passed, generate the appropriate QR code
        Ok(format!(
            "Audit proof for epoch {} has verified successfully!",
            end_epoch
        ))
    }
}

pub(crate) fn display_audit_proofs_info(info: &mut [EpochSummary]) -> Result<String> {
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
        bail!("The audit proofs appear to not be contiguous. There's a break in the linear history at epoch {}", maybe_broken_epoch.name.epoch);
    }

    Ok(format!(
        "Loaded epochs between ({}) and ({}), inclusively.",
        min.name.epoch, max.name.epoch
    ))
}

pub(crate) async fn list_proofs(url: &str) -> Result<Vec<EpochSummary>> {
    let mut results = vec![];
    let mut is_truncated = true;
    let mut start_after = "".to_string();

    while is_truncated {
        let params: Vec<(String, String)> = if start_after == *"" {
            vec![("list-type".to_string(), "2".to_string())]
        } else {
            vec![
                ("list-type".to_string(), "2".to_string()),
                ("start-after".to_string(), start_after.clone()),
            ]
        };

        let (keys, truncated_result) = get_xml(url, &params).await.unwrap();
        is_truncated = truncated_result;
        if is_truncated {
            let last = keys[keys.len() - 1].clone();
            start_after = last.key.clone();
        }
        results.extend_from_slice(&keys);
    }

    Ok(results)
}

pub(crate) async fn get_proof(
    url: &str,
    epoch: &EpochSummary,
) -> Result<akd::local_auditing::AuditBlob> {
    let url = format!("{}/{}", url, epoch.key);
    let resp = reqwest::get(url).await?.bytes().await?;
    let data = resp.to_vec();

    Ok(akd::local_auditing::AuditBlob {
        data,
        name: epoch.name,
    })
}

/// Returns the list of keys in the bucket, and whether or not there are more to fetch
async fn get_xml(url: &str, params: &[(String, String)]) -> Result<(Vec<EpochSummary>, bool)> {
    let url = reqwest::Url::parse_with_params(url, params)?;
    let resp = reqwest::get(url).await?.text().await?;

    let mut results = vec![];

    let mut is_truncated = false;
    let mut should_push = false;
    let mut should_check_truncated = false;

    let parser = EventReader::from_str(&resp);
    for event in parser {
        match event {
            Ok(XmlEvent::StartElement { name, .. }) => {
                if name.local_name == KEY_STR {
                    should_push = true;
                } else if name.local_name == IS_TRUNCATED_STR {
                    should_check_truncated = true;
                }
            }
            Ok(XmlEvent::Characters(text)) => {
                if should_push {
                    results.push(EpochSummary::try_from(text.as_str())?);
                    should_push = false;
                } else if should_check_truncated {
                    is_truncated = text == TRUE_STR;
                    should_check_truncated = false;
                }
            }
            Err(e) => println!("Error with parsing XML: {}", e),
            _ => (),
        }
    }

    Ok((results, is_truncated))
}
