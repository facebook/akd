// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes the trait and an implementation of it to access secure data for the VRF.

use crate::errors::VRFStorageError;
use vrf::openssl::{CipherSuite, Error};
use vrf::{openssl::ECVRF, VRF};

/// A trait to get public and secret key for the VRF
pub trait ClientVRF {
    /// The type of the public key
    type PK: Clone;
    /// The type of the secret key
    type SK: Clone;
    /// Type of the VRF
    type VRF: VRF<Self::PK, Self::SK>;

    /// Gets the public key for the VRF
    fn get_public_key() -> Result<Self::PK, VRFStorageError>;

    /// Generates the VRF proof
    fn verify(y: Self::PK, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError>;

    /// Generates hash for a VRF
    fn vrf_to_hash(pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError>;
}

/// Wrapper around the vrf crate implementation for ECVRF
/// to prevent the need for lifetimes in testing.
/// Other implementatoins may require saving vrf state to storage.
pub struct NoLifetimeECVRF {
    pub(crate) vrf: ECVRF,
}

impl NoLifetimeECVRF {

    pub(crate) fn new() -> Result<Self, vrf::openssl::Error> {
        let vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)?;
        Ok(Self { vrf })
    }

    pub(crate) fn derive_public_key(&mut self, secret_key: Vec<u8>) -> Result<Vec<u8>, vrf::openssl::Error> {
        self.vrf.derive_public_key(&secret_key)
    }

    pub(crate) fn proof_to_hash(&mut self, pi: &[u8]) -> Result<Vec<u8>, Error> {
        self.vrf.proof_to_hash(pi)
    }
}


/// This is a version of VRFKeyStorage for testing purposes, which uses the example from the VRF crate.
pub struct HardCodedClientVRF;

impl HardCodedClientVRF {
    fn get_secret_key_helper() -> Result<Vec<u8>, VRFStorageError> {
        Ok(hex::decode(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ).map_err(|hex_err| VRFStorageError::GetPK(hex_err.to_string()))?)
    }

    fn get_public_key_helper() -> Result<Vec<u8>, VRFStorageError> {
        let mut vrf = NoLifetimeECVRF::new()?;
        let sk = Self::get_secret_key_helper()?;
        Ok(vrf.derive_public_key(sk)?)
    }
}

impl ClientVRF for HardCodedClientVRF {
    type PK = Vec<u8>;
    type SK = Vec<u8>;
    type VRF = NoLifetimeECVRF;

    fn get_public_key() -> Result<Vec<u8>, VRFStorageError> {
        Ok(Self::get_public_key_helper()?)
    }

    fn verify(pk: Self::PK, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError> {
        let mut vrf = NoLifetimeECVRF::new()?;
        Ok(vrf.verify(pk, pi, alpha)?)
    }

    fn vrf_to_hash(pi: &[u8], _alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError> {
        let mut vrf = NoLifetimeECVRF::new()?;
        Ok(vrf.proof_to_hash(pi)?)
    }
}
