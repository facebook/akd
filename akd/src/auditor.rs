// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Code for an auditor of a authenticated key directory

use crate::{
    errors::{AkdError, AuditorError, AzksError},
    storage::{manager::StorageManager, memory::AsyncInMemoryDatabase},
    AppendOnlyProof, Azks, AzksInsertMode, Digest, SingleAppendOnlyProof,
};

/// Verifies an audit proof, given start and end hashes for a merkle patricia tree.
pub async fn audit_verify(hashes: Vec<Digest>, proof: AppendOnlyProof) -> Result<(), AkdError> {
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
        verify_consecutive_append_only(&proof.proofs[i], start_hash, end_hash, proof.epochs[i] + 1)
            .await?;
    }
    Ok(())
}

/// Helper for audit, verifies an append-only proof
pub async fn verify_consecutive_append_only(
    proof: &SingleAppendOnlyProof,
    start_hash: Digest,
    end_hash: Digest,
    epoch: u64,
) -> Result<(), AkdError> {
    // FIXME: Need to get rid of the clone here. Will need modifications to the functions called here.
    let unchanged_nodes = proof.unchanged_nodes.clone();
    let inserted = proof.inserted.clone();

    let db = AsyncInMemoryDatabase::new();
    let manager = StorageManager::new_no_cache(&db);

    let mut azks = Azks::new::<_>(&manager).await?;
    azks.batch_insert_leaves::<_>(&manager, unchanged_nodes, AzksInsertMode::Auditor)
        .await?;
    let computed_start_root_hash: Digest = azks.get_root_hash::<_>(&manager).await?;
    let mut verified = computed_start_root_hash == start_hash;
    azks.latest_epoch = epoch - 1;
    let updated_inserted = inserted
        .iter()
        .map(|x| {
            let mut y = *x;
            y.hash = akd_core::hash::merge_with_int(x.hash, epoch);
            y
        })
        .collect();
    azks.batch_insert_leaves::<_>(&manager, updated_inserted, AzksInsertMode::Auditor)
        .await?;
    let computed_end_root_hash: Digest = azks.get_root_hash::<_>(&manager).await?;
    verified = verified && (computed_end_root_hash == end_hash);
    if !verified {
        return Err(AkdError::AzksErr(AzksError::VerifyAppendOnlyProof));
    }
    Ok(())
}
