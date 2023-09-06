// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains implementations of a
//! [verifiable random function](https://en.wikipedia.org/wiki/Verifiable_random_function)
//! (currently only ECVRF). VRFs are used, in the case of this crate, to anonymize the
//! user id <-> node label mapping into a 1-way hash, which is verifyable without being
//! regeneratable without the secret key.
//!
//! VRFs allow us to have the server generate a constant mapping from a user id to a node label
//! but the client cannot themselves generate the mapping, only verify it. They can confirm
//! a user id matches the label, but don't have the ability to determine the labels of other
//! users in the directory.
//!
//! This module implements an instantiation of a verifiable random function known as
//! [ECVRF-EDWARDS25519-SHA512-TAI from RFC9381](https://www.ietf.org/rfc/rfc9381.html).
//!
//!
//! Adapted from Diem's NextGen Crypto module available [here](https://github.com/diem/diem/blob/502936fbd59e35276e2cf455532b143796d68a16/crypto/nextgen_crypto/src/vrf/ecvrf.rs)

mod ecvrf_impl;
mod traits;
// export the functionality we want visible
pub use crate::ecvrf::ecvrf_impl::{
    Output, Proof, VRFExpandedPrivateKey, VRFPrivateKey, VRFPublicKey,
};
pub use crate::ecvrf::traits::VRFKeyStorage;
#[cfg(feature = "nostd")]
use alloc::boxed::Box;
#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::String;
#[cfg(feature = "nostd")]
use alloc::string::ToString;
#[cfg(feature = "nostd")]
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

/// A error related to verifiable random functions
#[derive(Debug, Eq, PartialEq)]
pub enum VrfError {
    /// A problem retrieving or decoding the VRF public key
    PublicKey(String),
    /// A problem retrieving or decoding the VRF signing key
    SigningKey(String),
    /// A problem verifying the VRF proof
    Verification(String),
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            VrfError::PublicKey(msg) => format!("(Public Key) - {msg}"),
            VrfError::SigningKey(msg) => format!("(Signing Key) - {msg}"),
            VrfError::Verification(msg) => format!("(Verification) - {msg}"),
        };
        write!(f, "Verifiable random function error {code}")
    }
}

/// This is a version of VRFKeyStorage for testing purposes, which uses the example from the VRF crate.
///
/// const KEY_MATERIAL: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
#[derive(Clone)]
pub struct HardCodedAkdVRF;

unsafe impl Sync for HardCodedAkdVRF {}
unsafe impl Send for HardCodedAkdVRF {}

#[async_trait::async_trait]
impl VRFKeyStorage for HardCodedAkdVRF {
    async fn retrieve(&self) -> Result<Vec<u8>, VrfError> {
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .map_err(|hex_err| VrfError::PublicKey(hex_err.to_string()))
    }
}
