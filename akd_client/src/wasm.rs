// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Exposes the wasm specific verification operations that a client can perform
//!
//! You can compile and pack the WASM output with
//! ```bash
//! cd akd_client # optional
//! wasm-pack build --features wasm
//! ```
//! which currently has a resultant WASM file size of ~191KB with VRF verification enabled
//!
//! #### WASM Compilation and Deployment
//!
//! For WASM deployment of the AKD client, you'll want to read the [wasm_bindgen](https://rustwasm.github.io/wasm-bindgen/reference/deployment.html)
//! documentation which has reference material dependent on your environment.

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use core::convert::TryInto;

use protobuf::Message;
use wasm_bindgen::prelude::*;

use akd_core::configuration::Configuration;
use akd_core::proto::specs::types::LookupProof;
use akd_core::verify::VerificationError;

/// The result of a lookup proof validation. The value is hexadecimal encoded
/// binary
#[wasm_bindgen]
pub struct LookupResult {
    /// The epoch of this record
    epoch: u64,
    /// Version at this update
    version: u64,
    /// The verified value returned
    value: String,
}

#[wasm_bindgen]
impl LookupResult {
    /// Construct a new LookupResult object
    #[wasm_bindgen(constructor)]
    pub fn new(epoch: u64, version: u64, value: String) -> Self {
        Self {
            epoch,
            version,
            value,
        }
    }

    /// Get the value field for a LookupResult
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> String {
        self.value.clone()
    }

    /// Set the value field for a LookupResult
    #[wasm_bindgen(setter)]
    pub fn set_value(&mut self, value: String) {
        self.value = value;
    }

    /// Get the epoch field for a LookupResult
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Set the epoch field for a LookupResult
    #[wasm_bindgen(setter)]
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Get the version for a LookupResult
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Set the version field for a LookupResult
    #[wasm_bindgen(setter)]
    pub fn set_version(&mut self, version: u64) {
        self.version = version;
    }
}

#[allow(unused)]
fn fallible_lookup_verify<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash_ref: &[u8],
    akd_key: crate::AkdLabel,
    // protobuf encoded proof
    lookup_proof: &[u8],
) -> Result<akd_core::VerifyResult, VerificationError> {
    let root_hash =
        crate::hash::try_parse_digest(root_hash_ref).map_err(VerificationError::LookupProof)?;

    let proto_proof = LookupProof::parse_from_bytes(lookup_proof)?;
    crate::verify::lookup_verify::<TC>(
        vrf_public_key,
        root_hash,
        akd_key,
        (&proto_proof).try_into()?,
    )
}

/// Verify a lookup proof in WebAssembly, utilizing serde serialized structure for the proof
#[allow(unused)]
fn lookup_verify<TC: Configuration>(
    vrf_public_key: &[u8],
    root_hash_ref: &[u8],
    label: &[u8],
    // protobuf encoded proof
    lookup_proof: &[u8],
) -> Result<LookupResult, String> {
    match fallible_lookup_verify::<TC>(
        vrf_public_key,
        root_hash_ref,
        crate::AkdLabel(label.to_vec()),
        lookup_proof,
    ) {
        Ok(verification) => Ok(LookupResult::new(
            verification.epoch,
            verification.version,
            hex::encode(verification.value.0),
        )),
        Err(error) => Err(error.to_string()),
    }
}

/// NOTE(new_config): Add a new configuration here

/// Verify a lookup proof in WebAssembly for WhatsAppV1Configuration,
/// utilizing serde serialized structure for the proof
#[cfg(feature = "whatsapp_v1")]
#[wasm_bindgen]
pub fn lookup_verify_whatsapp_v1(
    vrf_public_key: &[u8],
    root_hash_ref: &[u8],
    label: &[u8],
    // protobuf encoded proof
    lookup_proof: &[u8],
) -> Result<LookupResult, String> {
    lookup_verify::<akd_core::configuration::WhatsAppV1Configuration>(
        vrf_public_key,
        root_hash_ref,
        label,
        lookup_proof,
    )
}

/// Verify a lookup proof in WebAssembly for ExperimentalConfiguration,
/// utilizing serde serialized structure for the proof
#[cfg(feature = "experimental")]
#[wasm_bindgen]
pub fn lookup_verify_experimental(
    vrf_public_key: &[u8],
    root_hash_ref: &[u8],
    label: &[u8],
    // protobuf encoded proof
    lookup_proof: &[u8],
) -> Result<LookupResult, String> {
    lookup_verify::<akd_core::configuration::ExperimentalConfiguration>(
        vrf_public_key,
        root_hash_ref,
        label,
        lookup_proof,
    )
}

#[cfg(test)]
pub mod tests {
    extern crate wasm_bindgen_test;

    use akd::errors::AkdError;
    use akd::storage::memory::AsyncInMemoryDatabase;
    use akd::storage::StorageManager;
    use akd::{AkdLabel, AkdValue, Directory};
    use protobuf::Message;
    use wasm_bindgen_test::*;

    use super::*;
    use crate::ecvrf::HardCodedAkdVRF;

    /// NOTE(new_config): Add a new configuration here
    macro_rules! test_config {
        ( $x:ident ) => {
            paste::paste! {
                #[cfg(feature = "whatsapp_v1")]
                #[wasm_bindgen_test]
                async fn [<$x _ whatsapp_v1_config>]() -> Result<(), AkdError> {
                    $x::<akd_core::configuration::WhatsAppV1Configuration>().await
                }

                #[cfg(feature = "experimental")]
                #[wasm_bindgen_test]
                async fn [<$x _ experimental_config>]() -> Result<(), AkdError> {
                    $x::<akd_core::configuration::ExperimentalConfiguration>().await
                }
            }
        };
    }

    test_config!(test_simple_wasm_lookup);
    async fn test_simple_wasm_lookup<TC: Configuration>() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let storage = StorageManager::new_no_cache(db);
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<TC, _, _>::new(storage, vrf)
            .await
            .expect("Failed to construct directory");

        let target_label = AkdLabel::from("hello");

        // Add two labels and corresponding values to the akd
        akd.publish(vec![
            (target_label.clone(), AkdValue::from("world")),
            (AkdLabel::from("hello2"), AkdValue::from("world2")),
        ])
        .await
        .expect("Failed to publish test data");
        // Get the lookup proof
        let (lookup_proof, root_hash) = akd
            .lookup(target_label.clone())
            .await
            .expect("Failed to lookup target");
        // Get the VRF public key
        let vrf_pk = akd
            .get_public_key()
            .await
            .expect("Failed to get VRF public key");

        let encoded_proof_bytes = crate::proto::specs::types::LookupProof::from(&lookup_proof)
            .write_to_bytes()
            .expect("Failed to encode lookup proof");

        // Verify the lookup proof
        let result = lookup_verify::<TC>(
            vrf_pk.as_bytes(),
            &root_hash.hash(),
            &target_label,
            &encoded_proof_bytes,
        );
        assert!(result.is_ok());
        Ok(())
    }
}
