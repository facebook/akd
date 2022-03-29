// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains mock usage of the VRF functionality should someone choose they
//! don't want the overhead of VRF computation. It is not designed for testing, but to
//! provide full functionality of the prod library but WITHOUT VRFs.

use crate::{errors::VRFStorageError, node_state::NodeLabel, storage::types::AkdLabel};
use async_trait::async_trait;
use winter_crypto::Digest;
use winter_crypto::Hasher;

/// A mock VRF public key
#[derive(Clone)]
pub struct VRFPublicKey;

impl VRFPublicKey {
    /// This function is called to verify that a given NodeLabel is indeed
    /// the VRF for a given version (fresh or stale) for a username.
    /// Hence, it also takes as input the server's public key.
    pub fn verify_label<H: Hasher>(
        &self,
        _uname: &AkdLabel,
        _stale: bool,
        _version: u64,
        _proof: &[u8],
        _label: NodeLabel,
    ) -> Result<(), VRFStorageError> {
        Ok(())
    }
}

/// A mock VRF private key
#[derive(Clone)]
pub struct VRFPrivateKey;

/// A mock VRF proof
pub struct Proof;

impl Proof {
    /// Converts a Proof into bytes
    pub fn to_bytes(&self) -> [u8; 80] {
        [0u8; 80]
    }
}

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
        Ok(VRFPrivateKey {})
    }

    /// Retrieve the VRF public key
    async fn get_vrf_public_key(&self) -> Result<VRFPublicKey, VRFStorageError> {
        Ok(VRFPublicKey {})
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
        // this function will need to read the VRF key using some function
        let name_hash_bytes = H::hash(uname);
        let mut stale_bytes = &[1u8];
        if stale {
            stale_bytes = &[0u8];
        }

        let hashed_label = H::merge(&[
            name_hash_bytes,
            H::merge_with_int(H::hash(stale_bytes), version),
        ]);
        let label_slice = hashed_label.as_bytes();
        let hashed_label_bytes = convert_byte_slice_to_array(&label_slice);
        Ok(NodeLabel::new(hashed_label_bytes, 64u32))
    }

    /// Retrieve the proof for a specific label
    async fn get_label_proof<H: Hasher>(
        &self,
        _uname: &AkdLabel,
        _stale: bool,
        _version: u64,
    ) -> Result<Proof, VRFStorageError> {
        Ok(Proof {})
    }
}

/// Converts a slice of u8 to an array of length 8. If the
/// slice is not long enough, just pads with zeros.
fn convert_byte_slice_to_array(slice: &[u8]) -> [u8; 32] {
    let mut out_arr = [0u8; 32];
    for (count, elt) in slice.iter().enumerate() {
        if count < 32 {
            out_arr[count] = *elt;
        } else {
            break;
        }
    }
    out_arr
}
