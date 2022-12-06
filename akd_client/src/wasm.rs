// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

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

fn fallable_lookup_verify(
    vrf_public_key: &[u8],
    root_hash_ref: &[u8],
    akd_key: crate::AkdLabel,
    // protobuf encoded proof
    lookup_proof: &[u8],
) -> Result<akd_core::VerifyResult, VerificationError> {
    let root_hash = if root_hash_ref.len() == akd_core::hash::DIGEST_BYTES {
        let mut h = [0u8; akd_core::hash::DIGEST_BYTES];
        h.copy_from_slice(root_hash_ref);
        Ok(h)
    } else {
        Err(VerificationError::LookupProof(format!(
            "Root hash is of incorrect length! (expected {} != got {})",
            akd_core::hash::DIGEST_BYTES,
            root_hash_ref.len()
        )))
    }?;

    let proto_proof = LookupProof::parse_from_bytes(lookup_proof)?;
    crate::verify::lookup_verify(
        vrf_public_key,
        root_hash,
        akd_key,
        (&proto_proof).try_into()?,
    )
}

#[wasm_bindgen]
/// Verify a lookup proof in WebAssembly, utilizing serde serialized structure for the proof
pub fn lookup_verify(
    vrf_public_key: &[u8],
    root_hash_ref: &[u8],
    label: &[u8],
    // protobuf encoded proof
    lookup_proof: &[u8],
) -> Result<LookupResult, String> {
    match fallable_lookup_verify(
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
