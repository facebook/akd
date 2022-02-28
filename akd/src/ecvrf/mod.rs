// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains implementations of a
//! [verifiable random function](https://en.wikipedia.org/wiki/Verifiable_random_function)
//! (currently only ECVRF). VRFs can be used in the consensus protocol for leader election
//! and in the case of this crate is used to anonymize the user id <-> node label mapping.
//!
//! VRFs allow us to have the server generate a constant mapping from a user id to a node label
//! but the client cannot themselves generate the mapping, only verify it. They can confirm
//! a user id matches the label, but don't have the ability to determine the labels of other
//! users in the directory.
//!
//! This module implements an instantiation of a verifiable random function known as
//! [ECVRF-ED25519-SHA512-TAI](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-04).
//!

#[cfg(feature = "vrf")]
mod ecvrf_impl;
#[cfg(feature = "vrf")]
mod traits;
// export the functionality we want visible
#[cfg(feature = "vrf")]
pub use crate::ecvrf::ecvrf_impl::{Proof, VRFPrivateKey, VRFPublicKey};
#[cfg(feature = "vrf")]
pub use crate::ecvrf::traits::VRFKeyStorage;

#[cfg(not(feature = "vrf"))]
mod no_vrf;
#[cfg(not(feature = "vrf"))]
pub use crate::ecvrf::no_vrf::{Proof, VRFKeyStorage, VRFPrivateKey, VRFPublicKey};

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
