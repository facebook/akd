// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A WASM compiled auditor which can be executed from Javascript
//!
//! You can compile and pack the WASM output with
//! ```bash
//! cd akd # optional
//! wasm-pack build --features wasm
//! ```
//! which currently has a resultant WASM file size of ~191KB with VRF verification enabled
//!
//! #### WASM Compilation and Deployment
//!
//! For WASM deployment of the AKD client, you'll want to read the [wasm_bindgen](https://rustwasm.github.io/wasm-bindgen/reference/deployment.html)
//! documentation which has reference material dependent on your environment.

use crate::{AppendOnlyProof, Digest, SingleAppendOnlyProof};
use akd_core::verify::VerificationError;
use core::convert::TryInto;
use protobuf::Message;
use wasm_bindgen::prelude::*;

fn get_digest(candidate: &[u8]) -> Result<Digest, akd_core::proto::ConversionError> {
    if candidate.len() == crate::DIGEST_BYTES {
        let mut v = [0u8; crate::DIGEST_BYTES];
        v.copy_from_slice(candidate);
        Ok(v)
    } else {
        Err(akd_core::proto::ConversionError::Deserialization(format!(
            "Failed to deserialize hash (expected {} bytes != got {} bytes)",
            crate::DIGEST_BYTES,
            candidate.len()
        )))
    }
}

async fn fallable_audit_verify(
    current_hash: &[u8],
    previous_hash: &[u8],
    single_proof_ref: &[u8],
    epoch: u64,
) -> Result<(), crate::errors::AkdError> {
    let proof =
        akd_core::proto::specs::types::SingleAppendOnlyProof::parse_from_bytes(single_proof_ref)
            .map_err(|protobuf_err| {
                let verif_err: VerificationError = protobuf_err.into();
                verif_err
            })?;
    let proof: SingleAppendOnlyProof = (&proof).try_into()?;

    let hashes = vec![get_digest(previous_hash)?, get_digest(current_hash)?];
    let append_only_proof = AppendOnlyProof {
        proofs: vec![proof],
        epochs: vec![epoch],
    };

    crate::auditor::audit_verify(hashes, append_only_proof).await
}

/// Verify a single audit proof for epoch to epoch+1
/// 
/// Due to lifetime management complaints from wasm_bindgen,
/// we need to take ownership of the passed byte arrays even though
/// we aren't mutating them so that their lifetime is guaranteed for the 
/// life of the JS Promise that's returned
#[wasm_bindgen]
pub async fn single_audit_verify(
    current_hash: &mut [u8],
    previous_hash: &mut [u8],
    single_proof_ref: &mut [u8],
    epoch: u64,
) -> Result<JsValue, JsValue> {
    match fallable_audit_verify(current_hash, previous_hash, single_proof_ref, epoch).await {
        Ok(_) => Ok(JsValue::NULL),
        Err(err) => Err(JsValue::from_str(&err.to_string())),
    }
}

