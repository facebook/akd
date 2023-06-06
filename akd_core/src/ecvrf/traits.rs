// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module implements traits for managing ECVRF, mainly pertaining to storage
//! of public and private keys
use super::{Output, Proof, VRFExpandedPrivateKey, VRFPrivateKey, VRFPublicKey, VrfError};
use crate::configuration::Configuration;
use crate::{AkdLabel, AkdValue, NodeLabel, VersionFreshness};

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
    async fn get_node_label<TC: Configuration>(
        &self,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Result<NodeLabel, VrfError> {
        let key = self.get_vrf_private_key().await?;
        let expanded_key = VRFExpandedPrivateKey::from(&key);
        let pk = VRFPublicKey::from(&key);
        Ok(Self::get_node_label_with_expanded_key::<TC>(
            &expanded_key,
            &pk,
            label,
            freshness,
            version,
        ))
    }

    /// Returns the [NodeLabel] that corresponds to a version of the label argument utilizing the provided
    /// private key.
    ///
    /// The stale boolean here is to indicate whether we are getting the [NodeLabel] for a fresh version,
    /// or a version that we are retiring.
    fn get_node_label_with_expanded_key<TC: Configuration>(
        expanded_private_key: &VRFExpandedPrivateKey,
        pk: &VRFPublicKey,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> NodeLabel {
        let output = Self::get_label_with_key_helper::<TC>(
            expanded_private_key,
            pk,
            label,
            freshness,
            version,
        );
        NodeLabel::new(output.to_truncated_bytes(), 256)
    }

    /// Returns the tree nodelabel that corresponds to a vrf proof.
    async fn get_node_label_from_vrf_proof(&self, proof: Proof) -> NodeLabel {
        let output: super::ecvrf_impl::Output = (&proof).into();
        NodeLabel::new(output.to_truncated_bytes(), 256)
    }

    /// Retrieve the proof for a specific label
    async fn get_label_proof<TC: Configuration>(
        &self,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Result<Proof, VrfError> {
        let key = self.get_vrf_private_key().await?;
        Ok(Self::get_label_proof_with_key::<TC>(
            &key, label, freshness, version,
        ))
    }

    /// Retrieve the proof for a specific label, with a supplied private key
    fn get_label_proof_with_key<TC: Configuration>(
        key: &VRFPrivateKey,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Proof {
        let hashed_label = TC::get_hash_from_label_input(label, freshness, version);
        key.prove(&hashed_label)
    }

    /// Retrieve the output for a specific label, with a supplied private key
    fn get_label_with_key_helper<TC: Configuration>(
        expanded_private_key: &VRFExpandedPrivateKey,
        pk: &VRFPublicKey,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Output {
        let hashed_label = TC::get_hash_from_label_input(label, freshness, version);
        expanded_private_key.evaluate(pk, &hashed_label)
    }

    /// Returns the [NodeLabel]s that corresponds to a collection of (label, freshness, version) arguments
    /// with only a single fetch to retrieve the VRF private key from storage.
    ///
    /// Note: The freshness enum here is to indicate whether we are getting the [NodeLabel] for a fresh version,
    /// or a version that we are retiring.
    async fn get_node_labels<TC: Configuration>(
        &self,
        labels: &[(AkdLabel, VersionFreshness, u64, AkdValue)],
    ) -> Result<Vec<((AkdLabel, VersionFreshness, u64, AkdValue), NodeLabel)>, VrfError> {
        let key = self.get_vrf_private_key().await?;
        let expanded_key = VRFExpandedPrivateKey::from(&key);
        let pk = VRFPublicKey::from(&key);

        #[cfg(feature = "parallel_vrf")]
        {
            #[cfg(feature = "nostd")]
            use alloc::format;

            let mut join_set = tokio::task::JoinSet::new();
            let labels_vec = labels.to_vec();
            for (label, freshness, version, value) in labels_vec.into_iter() {
                let expanded_key_ref = expanded_key.clone();
                let pk_ref = pk.clone();

                let future = {
                    async move {
                        (
                            Self::get_node_label_with_expanded_key::<TC>(
                                &expanded_key_ref,
                                &pk_ref,
                                &label,
                                freshness,
                                version,
                            ),
                            (label, freshness, version, value),
                        )
                    }
                };
                join_set.spawn(future);
            }

            let mut results = Vec::new();
            while let Some(res) = join_set.join_next().await {
                match res {
                    Err(join_err) => {
                        return Err(VrfError::SigningKey(format!(
                            "Parallel VRF join error {join_err}"
                        )))
                    }
                    Ok((node_label, (label, freshness, version, value))) => {
                        results.push(((label, freshness, version, value), node_label));
                    }
                }
            }
            Ok(results)
        }
        #[cfg(not(feature = "parallel_vrf"))]
        {
            let mut results = Vec::new();
            for (label, freshness, version, value) in labels {
                let node_label = Self::get_node_label_with_expanded_key::<TC>(
                    &expanded_key,
                    &pk,
                    label,
                    *freshness,
                    *version,
                );
                results.push((
                    (label.clone(), *freshness, *version, value.clone()),
                    node_label,
                ));
            }
            Ok(results)
        }
    }
}
