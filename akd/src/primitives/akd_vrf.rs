// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes the trait and an implementation of it to access secure data for the VRF.
use vrf::openssl::ECVRF;

/// A trait to get public and secret key for the VRF
pub trait VRFKeyStorage {
    /// The type of the public key
    type PK;
    /// The type of the secret key
    type SK;

    /// Gets the public key for the VRF
    fn get_public_key(&mut self) -> Self::PK;

    /// Gets the secret key for the VRF
    fn get_secret_key(&self) -> Self::SK;
}

pub(crate) struct HardCodedVRFKeyStorage {
    vrf: ECVRF,
    //const KEY_MATERIAL: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
}

impl VRFKeyStorage for HardCodedVRFKeyStorage {
    type PK = Vec<u8>;
    type SK = Vec<u8>;

    fn get_secret_key(&self) -> Self::SK {
        // unimplemented!()
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap()
    }

    fn get_public_key(&mut self) -> Self::PK {
        self.vrf.derive_public_key(&self.get_secret_key()).unwrap()
    }
}
