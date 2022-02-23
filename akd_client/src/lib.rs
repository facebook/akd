// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! # Overview
//!
//! This crate contains a "lean" client to verify AKD proofs which doesn't depend on any
//! dependencies other than the native hashing implementation. This makes it suitable
//! for embedded applications, e.g. inside limited clients (Android, iPhone, WebAssembly, etc)
//! which may not have a large dependency library they can pull upon.
//!
//! ## Present proof validation
//!
//! At the time of this documentation authoring, we presently support LookupProof verification
//! without depending on the full AKD library.
//!
//! ## Planned future support
//!
//! Going forward this crate will re-implement the client verifications of the base crate, but with
//! this "lean" mentality in mind. Should you not be running in a constrained environment then feel free to simply
//! use the base AKD library crate.
//!
//! ## Features
//!
//! The features of this library are
//!
//! 1. **default** blake3: Blake3 256-bit hashing
//! 2. sha256: SHA2 256-bit hashing
//! 3. sha512: SHA3 512-bit hashing
//! 4. sha3_256: SHA3 256-bit hashing
//! 5. sha3_512: SHA3 512-bit hashing
//!
//! which dictate which hashing function is used by the verification components. Blake3 256-bit hashing is the default
//! implementation and utilizes the [`blake3`] crate. Features sha256 and sha512 both utilize SHA2 cryptographic functions
//! from the [`sha2`] crate. Lastly sha3_256 and sha3_512 features utilize the [`sha3`] crate for their hashing implementations.
//! To utilize a hash implementation other than blake3, you should compile with
//!
//! ```bash
//! //          [disable blake3]      [enable other hash]
//! cargo build --no-default-features --features sha3_256
//! ```
//!
//! ### Additional features
//!
//! Additionally there are some features **not** related to the underlying hash function utilization
//!
//! 1. wasm: Compile with web-assembly support for WASM compilation
//! 2. wee_alloc: Utilize the WEE allocator, which is roughly 1KB instead of 10KB as a allocator but slower. This
//! is helpful in cases of constrained binary footprint size to help minimize
//! 3. nostd: Disable use of the std library
//! 4. vrf: Enable verification of VRFs (not compatible with [`nostd`]) client-side. Requires addition
//! of the [`vrf`] crate as dependency.
//!
//! You can compile and pack the WASM output with
//! ```bash
//! cd akd_client # optional
//! wasm-pack build --features wasm
//! ```
//! which currently has a resultant WASM file size of ~142KB and enabling wee_alloc yields roughly ~137KB binary size
//!
//! # Client Types
//!
//! A small note about the types in this library. They are specifically independent of the main AKD crate because
//! it's assumed that to perform a verification at the edge, the client will have had to receive some over-the-air
//! message which contains the data inside the proof. Therefore they'd need to be deserialized and handled independently
//! of the AKD crate which wouldn't be a dependency anyways. This is why the types are independent and specified separately
//! from the core AKD types.
#![cfg_attr(feature = "nostd", no_std)]
extern crate alloc;
#[cfg(feature = "nostd")]
use alloc::string::String;

pub mod types;
pub mod verify;

pub(crate) mod hash;
pub(crate) mod utils;
/// The arity of the tree. Should EXACTLY match the ARITY within
/// the AKD crate (i.e. akd::ARITY)
pub(crate) const ARITY: usize = 2;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(test)]
mod tests;

// =================================
// Error Definitions
// =================================

/// Client verification error codes
#[derive(Debug)]
pub enum VerificationErrorType {
    /// There was no direction when there should have been
    NoDirection,

    /// A membership proof failed to verify
    MembershipProof,

    /// An error occurred verifying the lookup proof
    LookupProof,

    /// An error occurred verifying a VRF label
    Vrf,

    /// An unknown verification error occurred
    Unknown,
}

/// AKD client verification error
#[derive(Debug)]
pub struct VerificationError {
    pub error_message: String,
    pub error_type: VerificationErrorType,
}

impl VerificationError {
    pub(crate) fn build<T>(ty: Option<VerificationErrorType>, msg: Option<String>) -> Self {
        Self {
            error_message: msg.unwrap_or_default(),
            error_type: ty.unwrap_or(VerificationErrorType::Unknown),
        }
    }
}

macro_rules! verify_error {
    ($x:ident, $ty:ty, $msg:expr) => {{
        let etype = crate::VerificationErrorType::$x;
        crate::VerificationError::build::<$ty>(Some(etype), Some($msg))
    }};
}
// export the macro for use in other modules
pub(crate) use verify_error;

// =================================
// Type re-exports for usability
// =================================

// type re-exports for public library
pub type AkdLabel = types::AkdLabel;
pub type AkdValue = types::AkdValue;

pub type Direction = types::Direction;
pub type Digest = types::Digest;
pub type NodeLabel = types::NodeLabel;
pub type Node = types::Node;
pub type LayerProof = types::LayerProof;
pub type MembershipProof = types::MembershipProof;
pub type NonMembershipProof = types::NonMembershipProof;
pub type LookupProof = types::LookupProof;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
/// Verify a lookup proof in WebAssembly, utilizing serde serialized structure for the proof
pub fn lookup_verify(
    vrf_public_key_slice: &[u8],
    root_hash_slice: &[u8],
    label_slice: &[u8],
    lookup_proof_ref: JsValue,
) -> bool {
    // TODO: https://rustwasm.github.io/wasm-bindgen/reference/types/result.html
    // (return a Result rather than panic the code)

    let vrf_public_key: Vec<u8> = vrf_public_key_slice.to_vec();
    let label: AkdLabel = label_slice.to_vec();

    let mut root_hash: [u8; 32] = [0u8; 32];
    root_hash.copy_from_slice(root_hash_slice);

    let proof: LookupProof = lookup_proof_ref.into_serde().unwrap();

    crate::verify::lookup_verify(&vrf_public_key, root_hash, label, proof).is_ok()
}
