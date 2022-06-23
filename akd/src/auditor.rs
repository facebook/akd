// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Code for an auditor of a authenticated key directory

use std::marker::{Send, Sync};

use winter_crypto::Hasher;

use crate::{
    errors::{AkdError, AuditorError, AzksError},
    proof_structs::{AppendOnlyProof, SingleAppendOnlyProof},
    storage::memory::AsyncInMemoryDatabase,
    Azks,
};

/// Verifies an audit proof, given start and end hashes for a merkle patricia tree.
pub async fn audit_verify<H: Hasher + Send + Sync>(
    hashes: Vec<H::Digest>,
    proof: AppendOnlyProof<H>,
) -> Result<(), AkdError> {
    if proof.epochs.len() + 1 != hashes.len() {
        return Err(AkdError::AuditErr(AuditorError::VerifyAuditProof(format!(
            "The proof has a different number of epochs than needed for hashes. 
            The number of hashes you provide should be one more than the number of epochs! 
            Number of epochs = {}, number of hashes = {}",
            proof.epochs.len(),
            hashes.len()
        ))));
    }
    if proof.epochs.len() != proof.proofs.len() {
        return Err(AkdError::AuditErr(AuditorError::VerifyAuditProof(format!(
            "The proof has {} epochs and {} proofs. These should be equal!",
            proof.epochs.len(),
            proof.proofs.len()
        ))));
    }
    for i in 0..hashes.len() - 1 {
        let start_hash = hashes[i];
        let end_hash = hashes[i + 1];
        verify_consecutive_append_only::<H>(
            &proof.proofs[i],
            start_hash,
            end_hash,
            proof.epochs[i] + 1,
        )
        .await?;
    }
    Ok(())
}

/// Helper for audit, verifies an append-only proof
pub async fn verify_consecutive_append_only<H: Hasher + Send + Sync>(
    proof: &SingleAppendOnlyProof<H>,
    start_hash: H::Digest,
    end_hash: H::Digest,
    epoch: u64,
) -> Result<(), AkdError> {
    // FIXME: Need to get rid of the clone here. Will need modifications to the functions called here.
    let unchanged_nodes = proof.unchanged_nodes.clone();
    let inserted = proof.inserted.clone();

    let db = AsyncInMemoryDatabase::new();
    let mut azks = Azks::new::<_, H>(&db).await?;
    azks.batch_insert_leaves_helper::<_, H>(&db, unchanged_nodes, true)
        .await?;
    let computed_start_root_hash: H::Digest = azks.get_root_hash::<_, H>(&db).await?;
    let mut verified = computed_start_root_hash == start_hash;
    azks.latest_epoch = epoch - 1;
    let updated_inserted = inserted
        .iter()
        .map(|x| {
            let mut y = *x;
            y.hash = H::merge_with_int(x.hash, epoch);
            y
        })
        .collect();
    azks.batch_insert_leaves_helper::<_, H>(&db, updated_inserted, true)
        .await?;
    let computed_end_root_hash: H::Digest = azks.get_root_hash::<_, H>(&db).await?;
    verified = verified && (computed_end_root_hash == end_hash);
    if !verified {
        return Err(AkdError::AzksErr(AzksError::VerifyAppendOnlyProof));
    }
    Ok(())
}
