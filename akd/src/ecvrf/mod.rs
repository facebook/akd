// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//!
//! This module implements the ECVRF functionality for use in the AKD crate

mod ecvrf_impl;
mod traits;

// export the functionality we want visible
pub use crate::ecvrf::ecvrf_impl::{Proof, VRFPrivateKey, VRFPublicKey};
pub use crate::ecvrf::traits::VRFKeyStorage;

#[cfg(test)]
mod tests;

/// This is a version of VRFKeyStorage for testing purposes, which uses the example from the VRF crate.
///
/// const KEY_MATERIAL: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
#[derive(Clone)]
pub struct HardCodedAkdVRF;

unsafe impl Sync for HardCodedAkdVRF {}
unsafe impl Send for HardCodedAkdVRF {}

#[async_trait::async_trait]
impl VRFKeyStorage for HardCodedAkdVRF {
    async fn retrieve(&self) -> Result<Vec<u8>, crate::errors::VRFStorageError> {
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .map_err(|hex_err| crate::errors::VRFStorageError::GetPK(hex_err.to_string()))
    }
}
