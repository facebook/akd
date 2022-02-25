// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements traits for managing ECVRF, mainly pertaining to storage
//! of public and private keys
use super::VRFPublicKey;
use super::{ecvrf_impl::Output, Proof, VRFPrivateKey};
use crate::serialization::from_digest;
use crate::{errors::VRFStorageError, node_state::NodeLabel, storage::types::AkdLabel};

use async_trait::async_trait;
use std::convert::TryInto;
use winter_crypto::Hasher;

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
    async fn retrieve(&self) -> Result<Vec<u8>, VRFStorageError>;

    /* ======= Common trait functionality ====== */

    /// Retrieve the properly constructed VRF Private key
    async fn get_vrf_private_key(&self) -> Result<VRFPrivateKey, VRFStorageError> {
        match self.retrieve().await {
            Ok(bytes) => {
                let pk_ref: &[u8] = &bytes;
                pk_ref.try_into()
            }
            Err(other) => Err(other),
        }
    }

    /// Retrieve the VRF public key
    async fn get_vrf_public_key(&self) -> Result<VRFPublicKey, VRFStorageError> {
        self.get_vrf_private_key().await.map(|key| (&key).into())
    }

    /// Generate a proof for the given input data (message/alpha)
    async fn generate_proof(&self, message: &[u8]) -> Result<[u8; 80], VRFStorageError> {
        self.get_vrf_private_key()
            .await
            .map(|result| result.prove(message).to_bytes())
    }

    /// Returns the tree nodelabel that corresponds to a version of the uname argument.
    /// The stale boolean here is to indicate whether we are getting the nodelabel for a fresh version,
    /// or a version that we are retiring.
    async fn get_node_label<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<NodeLabel, VRFStorageError> {
        let proof = self.get_label_proof::<H>(uname, stale, version).await?;
        let output: Output = (&proof).into();

        let mut truncated_hash: [u8; 32] = [0u8; 32];
        truncated_hash.copy_from_slice(&output.to_bytes()[..32]);

        Ok(NodeLabel::new(truncated_hash, 256u32))
    }

    /// Retrieve the proof for a specific label
    async fn get_label_proof<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<Proof, VRFStorageError> {
        let key = self.get_vrf_private_key().await?;
        let name_hash_bytes = H::hash(uname.0.as_bytes());
        let mut stale_bytes = &[1u8];
        if stale {
            stale_bytes = &[0u8];
        }

        let hashed_label = H::merge(&[
            name_hash_bytes,
            H::merge_with_int(H::hash(stale_bytes), version),
        ]);
        let message_vec = from_digest::<H>(hashed_label).unwrap();
        let message: &[u8] = message_vec.as_slice();

        // VRF proof and hash output
        let proof = key.prove(message);
        Ok(proof)
    }

    /// This function is called to verify that a given NodeLabel is indeed
    /// the VRF for a given version (fresh or stale) for a username.
    async fn verify_node_label<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
        proof: &[u8],
        label: NodeLabel,
    ) -> Result<(), VRFStorageError> {
        match self.get_vrf_public_key().await {
            Ok(pk) => pk.verify_label::<H>(uname, stale, version, proof, label),
            Err(other) => Err(other),
        }
    }
}
