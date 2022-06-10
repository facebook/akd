// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements traits for managing ECVRF, mainly pertaining to storage
//! of public and private keys
use super::{Proof, VRFPrivateKey, VRFPublicKey};
use crate::serialization::from_digest;
use crate::{errors::VrfError, node_state::NodeLabel, storage::types::AkdLabel};

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

    /// Returns the tree nodelabel that corresponds to a version of the uname argument.
    /// The stale boolean here is to indicate whether we are getting the nodelabel for a fresh version,
    /// or a version that we are retiring.
    async fn get_node_label<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<NodeLabel, VrfError> {
        let proof = self.get_label_proof::<H>(uname, stale, version).await?;
        let output: super::ecvrf_impl::Output = (&proof).into();
        Ok(NodeLabel::new(output.to_truncated_bytes(), 256u32))
    }

    /// Returns the tree nodelabel that corresponds to a vrf proof.
    async fn get_node_label_from_vrf_pf<H: Hasher>(
        &self,
        proof: Proof,
    ) -> Result<NodeLabel, VrfError> {
        let output: super::ecvrf_impl::Output = (&proof).into();
        Ok(NodeLabel::new(output.to_truncated_bytes(), 256u32))
    }

    /// Retrieve the proof for a specific label
    async fn get_label_proof<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<Proof, VrfError> {
        let key = self.get_vrf_private_key().await?;
        let name_hash_bytes = H::hash(uname);
        let stale_bytes = if stale { &[0u8] } else { &[1u8] };

        let hashed_label = H::merge(&[
            name_hash_bytes,
            H::merge_with_int(H::hash(stale_bytes), version),
        ]);
        let message_vec = from_digest::<H>(hashed_label);
        let message: &[u8] = message_vec.as_slice();

        // VRF proof and hash output
        let proof = key.prove(message);
        Ok(proof)
    }
}
