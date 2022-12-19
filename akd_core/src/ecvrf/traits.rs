// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements traits for managing ECVRF, mainly pertaining to storage
//! of public and private keys
use super::{Proof, VRFPrivateKey, VRFPublicKey, VrfError};
use crate::{AkdLabel, NodeLabel};

#[cfg(feature = "nostd")]
use alloc::boxed::Box;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;
use async_trait::async_trait;
use core::convert::TryInto;

/// Represents a secure storage of the VRF private key. Since the VRF private key
/// should change never (if it does, the entire tree is no longer a consistent mapping
/// of user -> node label), it is highly recommended to back this implementation with a
/// static cache of the private key bytes which lives for the life of the process.
///
/// I.e. retrieve the byte vector 1 time, and simply keep serving it up without doing
/// network access calls
#[async_trait]
pub trait VRFKeyStorage: Clone + Sync + Send {
    /* ======= To be implemented ====== */

    /// Retrieve the VRF Private key as a vector of bytes
    async fn retrieve(&self) -> Result<Vec<u8>, VrfError>;

    /* ======= Common trait functionality ====== */

    /// Retrieve the properly constructed VRF Private key
    async fn get_vrf_private_key(&self) -> Result<VRFPrivateKey, VrfError> {
        match self.retrieve().await {
            Ok(bytes) => {
                let pk_ref: &[u8] = &bytes;
                pk_ref.try_into()
            }
            Err(other) => Err(other),
        }
    }

    /// Retrieve the VRF public key
    async fn get_vrf_public_key(&self) -> Result<VRFPublicKey, VrfError> {
        self.get_vrf_private_key().await.map(|key| (&key).into())
    }

    /// Returns the [NodeLabel] that corresponds to a version of the label argument.
    ///
    /// The stale boolean here is to indicate whether we are getting the [NodeLabel] for a fresh version,
    /// or a version that we are retiring.
    async fn get_node_label(
        &self,
        label: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<NodeLabel, VrfError> {
        let key = self.get_vrf_private_key().await?;
        Self::get_node_label_with_key(&key, label, stale, version)
    }

    /// Returns the [NodeLabel] that corresponds to a version of the label argument utilizing the provided
    /// private key.
    ///
    /// The stale boolean here is to indicate whether we are getting the [NodeLabel] for a fresh version,
    /// or a version that we are retiring.
    fn get_node_label_with_key(
        key: &VRFPrivateKey,
        label: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<NodeLabel, VrfError> {
        let proof = Self::get_label_proof_with_key(key, label, stale, version)?;
        Self::get_node_label_from_vrf_proof_static(proof)
    }

    /// Returns the tree nodelabel that corresponds to a vrf proof.
    async fn get_node_label_from_vrf_proof(&self, proof: Proof) -> Result<NodeLabel, VrfError> {
        Self::get_node_label_from_vrf_proof_static(proof)
    }

    /// Returns the tree nodelabel that corresponds to a vrf proof.
    fn get_node_label_from_vrf_proof_static(proof: Proof) -> Result<NodeLabel, VrfError> {
        let output: super::ecvrf_impl::Output = (&proof).into();
        Ok(NodeLabel::new(output.to_truncated_bytes(), 256))
    }

    /// Retrieve the proof for a specific label
    async fn get_label_proof(
        &self,
        label: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<Proof, VrfError> {
        let key = self.get_vrf_private_key().await?;
        Self::get_label_proof_with_key(&key, label, stale, version)
    }

    /// Retrieve the proof for a specific label
    fn get_label_proof_with_key(
        key: &VRFPrivateKey,
        label: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<Proof, VrfError> {
        let hashed_label = crate::utils::get_hash_from_label_input(label, stale, version);

        // VRF proof and hash output
        let proof = key.prove(&hashed_label);
        Ok(proof)
    }

    /// Returns the [NodeLabel]s that corresponds to a collection of (label, stale, version) arguments
    /// with only a single fetch to retrieve the VRF private key from storage.
    ///
    /// Note: The stale boolean here is to indicate whether we are getting the [NodeLabel] for a fresh version,
    /// or a version that we are retiring.
    async fn get_node_labels(
        &self,
        labels: &[(AkdLabel, bool, u64)],
    ) -> Result<Vec<(AkdLabel, NodeLabel)>, VrfError> {
        let key = self.get_vrf_private_key().await?;

        #[cfg(feature = "parallel_vrf")]
        {
            let mut join_set = tokio::task::JoinSet::new();
            let labels_vec = labels.to_vec();
            for (label, stale, version) in labels_vec.into_iter() {
                let key_ref = key.clone();

                let future = {
                    async move {
                        Self::get_node_label_with_key(&key_ref, &label, stale, version)
                            .map(|ok_result| (label, ok_result))
                    }
                };
                join_set.spawn(future);
            }

            let mut results = Vec::new();
            while let Some(res) = join_set.join_next().await {
                match res {
                    Err(_) => {
                        return Err(VrfError::SigningKey(
                            "Failed to generate signatures joining parallel tasks".to_string(),
                        ))
                    }
                    Ok(Err(some_vrf_err)) => return Err(some_vrf_err),
                    Ok(Ok(label_and_node_label)) => {
                        results.push(label_and_node_label);
                    }
                }
            }
            Ok(results)
        }
        #[cfg(not(feature = "parallel_vrf"))]
        {
            let mut results = Vec::new();
            for (label, stale, version) in labels {
                let node_label = Self::get_node_label_with_key(&key, label, *stale, *version)?;
                results.push((label.clone(), node_label));
            }
            Ok(results)
        }
    }
}
