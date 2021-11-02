// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Code for an auditor of a verifiable key directory

use rand::rngs::OsRng;
use winter_crypto::Hasher;

use crate::{
    append_only_zks::Azks,
    errors::{AzksError, VkdError},
    proof_structs::AppendOnlyProof,
    storage::memory::AsyncInMemoryDatabase,
};

/// Verifies an audit proof, given start and end hashes for a merkle patricia tree.
pub async fn audit_verify<H: Hasher + std::marker::Send>(
    start_hash: H::Digest,
    end_hash: H::Digest,
    proof: AppendOnlyProof<H>,
) -> Result<(), VkdError> {
    verify_append_only::<H>(proof, start_hash, end_hash).await
}

/// Helper for audit, verifies an append-only proof
pub(crate) async fn verify_append_only<H: Hasher + std::marker::Send>(
    proof: AppendOnlyProof<H>,
    start_hash: H::Digest,
    end_hash: H::Digest,
) -> Result<(), VkdError> {
    let unchanged_nodes = proof.unchanged_nodes;
    let inserted = proof.inserted;
    let mut rng = OsRng;

    let db = AsyncInMemoryDatabase::new();
    let mut azks = Azks::<H, AsyncInMemoryDatabase>::new(&db, &mut rng).await?;
    azks.batch_insert_leaves_helper(&db, unchanged_nodes, true)
        .await?;
    let computed_start_root_hash: H::Digest = azks.get_root_hash(&db).await?;
    let mut verified = computed_start_root_hash == start_hash;
    azks.batch_insert_leaves_helper(&db, inserted, true).await?;
    let computed_end_root_hash: H::Digest = azks.get_root_hash(&db).await?;
    verified = verified && (computed_end_root_hash == end_hash);
    if !verified {
        return Err(VkdError::AzksErr(AzksError::AppendOnlyProofDidNotVerify));
    }
    Ok(())
}
