// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Code for an auditor of a authenticated key directory

use akd_core::configuration::Configuration;
use akd_core::AzksElement;

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
    verify_append_only_hash::<TC>(proof.unchanged_nodes.clone(), start_hash, None).await?;

    let mut unchanged_with_inserted_nodes = proof.unchanged_nodes.clone();
    unchanged_with_inserted_nodes.extend(proof.inserted.iter().map(|x| {
        let mut y = *x;
        y.value = AzksValue(TC::hash_leaf_with_commitment(x.value, end_epoch).0);
        y
    }));

    verify_append_only_hash::<TC>(unchanged_with_inserted_nodes, end_hash, Some(end_epoch - 1))
        .await?;
    Ok(())
}

/// This function verifies the root hash of an AZKS instance against an expected hash.
/// It creates an AZKS instance from a set of nodes, and checks if the computed root
/// hash matches the expected hash. The optional latest_epoch parameter allows for
/// specifying the latest epoch for the AZKS instance.
async fn verify_append_only_hash<TC: Configuration>(
    nodes: Vec<AzksElement>,
    expected_hash: Digest,
    latest_epoch: Option<u64>,
) -> Result<(), AkdError> {
    let manager = StorageManager::new_no_cache(
        AsyncInMemoryDatabase::new_with_remove_child_nodes_on_insertion(),
    );
    let mut azks = Azks::new::<TC, _>(&manager).await?;
    if let Some(epoch) = latest_epoch {
        azks.latest_epoch = epoch;
    }
    azks.batch_insert_nodes::<TC, _>(
        &manager,
        nodes,
        InsertMode::Auditor,
        AzksParallelismConfig::default(),
    )
    .await?;
    let computed_hash: Digest = azks.get_root_hash::<TC, _>(&manager).await?;
    if computed_hash != expected_hash {
        return Err(AkdError::AzksErr(AzksError::VerifyAppendOnlyProof(
            format!(
                "Expected hash {} does not match computed root hash {}",
                hex::encode(expected_hash),
                hex::encode(computed_hash)
            ),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::verify_membership_for_tests_only;
    use crate::test_config;
    use crate::{
        AzksValue, Direction, MembershipProof, NodeLabel, SiblingProof, SingleAppendOnlyProof,
    };

    // Regression test for the auditor append-only bypass: when an unchanged
    // interior node's label is a strict prefix of an inserted leaf's label,
    // `partition` used to silently drop the unchanged node, letting a malicious
    // server rewrite a label's value (`val1` -> `val2`) while still producing a
    // valid append-only proof. `audit_verify` must now reject the transition.
    test_config!(test_auditor_rejects_prefix_collision_value_rewrite);
    #[allow(non_snake_case)]
    async fn test_auditor_rejects_prefix_collision_value_rewrite<TC: Configuration>(
    ) -> Result<(), AkdError> {
        const AUDIT_EPOCH: u64 = 2;
        const START_EPOCH: u64 = AUDIT_EPOCH - 1;

        // `shell_label` (1 bit) is a strict prefix of `label` (256 bits). This
        // is what triggers the drop in `partition` when both are inserted.
        let shell_label = NodeLabel::new([0u8; 32], 1);
        let label = NodeLabel::new([0u8; 32], 256);

        let empty_child = AzksElement {
            label: TC::empty_label(),
            value: TC::empty_node_hash(),
        };
        // Value of a node whose only (left) child is `(child_label, child_val)`.
        let parent_hash = |child_label: NodeLabel, child_val: AzksValue| {
            TC::compute_parent_hash_from_children(
                &child_val,
                &child_label.value::<TC>(),
                &empty_child.value,
                &empty_child.label.value::<TC>(),
            )
        };

        let val1 = AzksValue(TC::hash(b"val1"));
        let val2 = AzksValue(TC::hash(b"val2"));
        // The auditor re-commits leaves with their corresponding epoch.
        let leaf_val1 = AzksValue(TC::hash_leaf_with_commitment(val1, START_EPOCH).0);
        let leaf_val2 = AzksValue(TC::hash_leaf_with_commitment(val2, AUDIT_EPOCH).0);

        // root ->[left] Leaf(shell_label, shell_val), where shell_val commits to
        // the subtree Interior(shell_label) ->[left] Leaf(label, val1).
        let shell_val = parent_hash(label, leaf_val1);
        let root_hash1 = TC::compute_root_hash_from_val(&parent_hash(shell_label, shell_val));
        // root ->[left] Interior(shell_label) ->[left] Leaf(label, val2).
        let root_hash2 = TC::compute_root_hash_from_val(&parent_hash(
            shell_label,
            parent_hash(label, leaf_val2),
        ));

        let update_proof = SingleAppendOnlyProof {
            unchanged_nodes: vec![AzksElement {
                label: shell_label,
                value: shell_val,
            }],
            inserted: vec![AzksElement { label, value: val2 }],
        };

        // Sanity: the two membership proofs genuinely disagree on `label`'s
        // value, so accepting this transition would break append-only-ness.
        let sibling_path = vec![
            SiblingProof {
                label: NodeLabel::root(),
                siblings: [empty_child],
                direction: Direction::Left,
            },
            SiblingProof {
                label: shell_label,
                siblings: [empty_child],
                direction: Direction::Left,
            },
        ];
        let membership = |hash_val| MembershipProof {
            label,
            hash_val,
            sibling_proofs: sibling_path.clone(),
        };
        verify_membership_for_tests_only::<TC>(root_hash1, &membership(leaf_val1)).unwrap();
        verify_membership_for_tests_only::<TC>(root_hash2, &membership(leaf_val2)).unwrap();
        assert_ne!(leaf_val1, leaf_val2);

        // The core assertion: the auditor must reject the crafted transition.
        let result = audit_verify::<TC>(
            vec![root_hash1, root_hash2],
            AppendOnlyProof {
                proofs: vec![update_proof],
                epochs: vec![START_EPOCH],
            },
        )
        .await;
        assert!(
            matches!(
                result,
                Err(AkdError::AzksErr(AzksError::BatchInsertDroppedNode(_)))
            ),
            "auditor must reject the value-rewrite transition, got {result:?}"
        );

        Ok(())
    }
}
