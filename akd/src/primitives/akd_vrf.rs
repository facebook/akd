// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes the trait and an implementation of it to access secure data for the VRF.
use crate::errors::VRFStorageError;
use crate::primitives::client_vrf::{ClientVRF, NoLifetimeECVRF};

use vrf::openssl::Error;
use vrf::VRF;
/// A trait to get public and secret key for the VRF
pub trait AkdVRF: ClientVRF {
    /// Gets the secret key for the VRF
    fn get_secret_key(&self) -> Result<Self::SK, VRFStorageError>;

    /// Generates the VRF proof
    fn prove(sk: Self::SK, alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError>;
}

impl VRF<Vec<u8>, Vec<u8>> for NoLifetimeECVRF {
    type Error = Error;

    fn prove(&mut self, x: Vec<u8>, alpha: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.vrf.prove(x.as_slice(), alpha)
    }

    fn verify(&mut self, y: Vec<u8>, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.vrf.verify(y.as_slice(), pi, alpha)
    }
}

/// This is a version of VRFKeyStorage for testing purposes, which uses the example from the VRF crate.
#[derive(Clone)]
pub struct HardCodedAkdVRF {
    //const KEY_MATERIAL: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
}

impl HardCodedAkdVRF {
    fn get_secret_key_helper() -> Result<Vec<u8>, VRFStorageError> {
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .map_err(|hex_err| VRFStorageError::GetPK(hex_err.to_string()))
    }

    fn get_public_key_helper() -> Result<Vec<u8>, VRFStorageError> {
        let mut vrf = NoLifetimeECVRF::new()?;
        let sk = Self::get_secret_key_helper()?;
        Ok(vrf.derive_public_key(sk)?)
    }
}

impl ClientVRF for HardCodedAkdVRF {
    type PK = Vec<u8>;
    type SK = Vec<u8>;
    type VRF = NoLifetimeECVRF;

    fn verify(pk: Self::PK, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError> {
        let mut vrf = NoLifetimeECVRF::new()?;
        Ok(vrf.verify(pk, pi, alpha)?)
    }

    fn vrf_to_hash(pi: &[u8], _alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError> {
        let mut vrf = NoLifetimeECVRF::new()?;
        Ok(vrf.proof_to_hash(pi)?)
    }

    fn get_public_key(&self) -> Result<Vec<u8>, VRFStorageError> {
        Self::get_public_key_helper()
    }
}

impl AkdVRF for HardCodedAkdVRF {
    fn get_secret_key(&self) -> Result<Vec<u8>, VRFStorageError> {
        Self::get_secret_key_helper()
    }

    fn prove(sk: Self::SK, alpha: &[u8]) -> Result<Vec<u8>, VRFStorageError> {
        let mut vrf = NoLifetimeECVRF::new()?;
        Ok(vrf.prove(sk, alpha)?)
    }
}
