// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module holds the auditor operations based on binary-encoded AuditProof blobs

use anyhow::{anyhow, bail, Result};
use log::{error, info, warn};
use std::marker::{Send, Sync};

fn format_qr_record<H>(p_hash: H::Digest, c_hash: H::Digest, epoch: u64) -> Vec<u8>
where
    H: winter_crypto::Hasher,
{
    let p_bytes = akd::serialization::from_digest::<H>(p_hash);
    let c_bytes = akd::serialization::from_digest::<H>(c_hash);
    let epoch_bytes = epoch.to_ne_bytes();
    let header = "WA_AKD_VERIFY".as_bytes();

    let mut result = vec![];
    result.extend(header);
    result.extend(epoch_bytes);
    result.extend(p_bytes);
    result.extend(c_bytes);
    result
}

pub async fn audit<H>(bytes: bytes::Bytes, key: &str, qr: bool) -> Result<()>
where
    H: winter_crypto::Hasher + Clone + Sync + Send,
{
    let (p_hash, c_hash, epoch, proof) = akd::proto::AuditBlob {
        data: bytes.into_iter().collect::<Vec<u8>>(),
        name: key.to_string(),
    }
    .decode::<H>()
    .map_err(|err| anyhow!("{}", err))?;

    // DO THE FREAKING VERIFICATION ALREADY
    if let Err(akd_error) = akd::auditor::audit_verify(
        vec![p_hash, c_hash],
        akd::proof_structs::AppendOnlyProof::<H> {
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
        info!("Audit proof for epoch {} has verified!", epoch);
        if qr {
            info!("Generating scan-able QR code for the verification on device");
            let qr_code_data = format_qr_record::<H>(p_hash, c_hash, epoch);
            if let Err(error) = qr2term::print_qr(&qr_code_data) {
                error!("Error generating QR code {}", error);
                bail!("Error generating QR code {}", error);
            }
        }
    }
    Ok(())
}
