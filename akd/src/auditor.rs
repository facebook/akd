// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Code for an auditor of a authenticated key directory

use akd_core::configuration::Configuration;

use crate::append_only_zks::AzksParallelismConfig;
use crate::AzksValue;
use crate::{
    append_only_zks::InsertMode,
    errors::{AkdError, AuditorError, AzksError},
    storage::{manager::StorageManager, memory::AsyncInMemoryDatabase},
    AppendOnlyProof, Azks, Digest, SingleAppendOnlyProof,
};

/// Verifies an audit proof, given start and end hashes for a merkle patricia tree.
#[cfg_attr(feature = "tracing_instrument", tracing::instrument(skip_all))]
pub async fn audit_verify<TC: Configuration>(
    hashes: Vec<Digest>,
    proof: AppendOnlyProof,
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
        verify_consecutive_append_only::<TC>(
            &proof.proofs[i],
            start_hash,
            end_hash,
            proof.epochs[i] + 1,
        )
        .await?;
    }
    Ok(())
}

/// Helper for audit, verifies an append-only proof.
///
/// This function first creates a new AZKS instance with the unchanged nodes from the proof,
/// then it verifies the start hash against the root hash of this AZKS instance.
/// Next, it creates another AZKS instance with the unchanged nodes and inserted nodes,
/// and verifies the end hash against the root hash of this second AZKS instance.
#[cfg_attr(feature = "tracing_instrument", tracing::instrument(skip_all))]
pub async fn verify_consecutive_append_only<TC: Configuration>(
    proof: &SingleAppendOnlyProof,
    start_hash: Digest,
    end_hash: Digest,
    end_epoch: u64,
) -> Result<(), AkdError> {
    let manager1 = StorageManager::new_no_cache(
        AsyncInMemoryDatabase::new_with_remove_child_nodes_on_insertion(),
    );
    let mut azks1 = Azks::new::<TC, _>(&manager1).await?;
    azks1
        .batch_insert_nodes::<TC, _>(
            &manager1,
            proof.unchanged_nodes.clone(),
            InsertMode::Auditor,
            AzksParallelismConfig::default(),
        )
        .await?;
    let computed_start_root_hash: Digest = azks1.get_root_hash::<TC, _>(&manager1).await?;
    if computed_start_root_hash != start_hash {
        return Err(AkdError::AzksErr(AzksError::VerifyAppendOnlyProof(
            format!(
                "Start hash {} does not match computed root hash {}",
                hex::encode(start_hash),
                hex::encode(computed_start_root_hash)
            ),
        )));
    }

    let manager2 = StorageManager::new_no_cache(
        AsyncInMemoryDatabase::new_with_remove_child_nodes_on_insertion(),
    );
    let mut azks2 = Azks::new::<TC, _>(&manager2).await?;
    azks2.latest_epoch = end_epoch - 1;
    let mut unchanged_with_inserted_nodes = proof.unchanged_nodes.clone();
    unchanged_with_inserted_nodes.extend(proof.inserted.iter().map(|x| {
        let mut y = *x;
        y.value = AzksValue(TC::hash_leaf_with_commitment(x.value, end_epoch).0);
        y
    }));

    azks2
        .batch_insert_nodes::<TC, _>(
            &manager2,
            unchanged_with_inserted_nodes,
            InsertMode::Auditor,
            AzksParallelismConfig::default(),
        )
        .await?;
    let computed_end_root_hash: Digest = azks2.get_root_hash::<TC, _>(&manager2).await?;
    if computed_end_root_hash != end_hash {
        return Err(AkdError::AzksErr(AzksError::VerifyAppendOnlyProof(
            format!(
                "End hash {} does not match computed root hash {}",
                hex::encode(end_hash),
                hex::encode(computed_end_root_hash)
            ),
        )));
    }
    Ok(())
}
