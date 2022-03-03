// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! [verifiable random function](https://en.wikipedia.org/wiki/Verifiable_random_function)
//! (currently only ECVRF). VRFs are used, in the case of this crate, to anonymize the
//! user id <-> node label mapping into a 1-way hash, which is verifyable without being
//! regeneratable without the secret key.
//!
//! This module implements an instantiation of a verifiable random function known as
//! [ECVRF-ED25519-SHA512-TAI](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-04).
//!
//! Adapted from Diem's NextGen Crypto module available [here](https://github.com/diem/diem/blob/502936fbd59e35276e2cf455532b143796d68a16/crypto/nextgen_crypto/src/vrf/ecvrf.rs)

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::ToString;

use crate::hash::*;
use crate::{AkdLabel, NodeLabel, VerificationError, VerificationErrorType};
use core::convert::TryFrom;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar as ed25519_Scalar,
};

/*
 * NOTE: rust-analyzer gives an "unresolved import" error for the following since the entire
 * ed25519-dalek crate utilized !#[cfg(not(test))] and rust-analyzer utlizes the test profile
 * to scan code. Therefore we have a custom settings.json in the .vscode folder which adds a unsetTest
 * flag to this specific crate. See: https://github.com/rust-analyzer/rust-analyzer/issues/7243
 *
 * If you still see the error, you can simply ignore. It's harmless.
*/
use ed25519_dalek::Digest;
use ed25519_dalek::PublicKey as ed25519_PublicKey;
use ed25519_dalek::Sha512;

const SUITE: u8 = 0x03;
const ONE: u8 = 0x01;
const TWO: u8 = 0x02;
const THREE: u8 = 0x03;

/// The number of bytes of [`Output`]
pub const OUTPUT_LENGTH: usize = 64;

/// The length of a node-label's value field in bytes.
/// This is used for truncation of the hash to this many bytes
pub(crate) const NODE_LABEL_LEN: usize = 32;

/// An ECVRF public key
pub struct VRFPublicKey(ed25519_PublicKey);

impl TryFrom<&[u8]> for VRFPublicKey {
    type Error = VerificationError;

    fn try_from(bytes: &[u8]) -> Result<VRFPublicKey, Self::Error> {
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(VerificationError::build(
                Some(VerificationErrorType::Vrf),
                Some("Wrong length".to_string()),
            ));
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
        let point = compressed.decompress().ok_or_else(|| {
            VerificationError::build(
                Some(VerificationErrorType::Vrf),
                Some("Deserialization failed".to_string()),
            )
        })?;

        // Check if the point lies on a small subgroup. This is required
        // when using curves with a small cofactor (in ed25519, cofactor = 8).
        if point.is_small_order() {
            return Err(crate::VerificationError::build(
                Some(VerificationErrorType::Vrf),
                Some("Small subgroup".to_string()),
            ));
        }

        match ed25519_PublicKey::from_bytes(bytes) {
            Ok(result) => Ok(VRFPublicKey(result)),
            Err(sig_err) => Err(VerificationError::build(
                Some(VerificationErrorType::Vrf),
                Some(format!("Signature error {}", sig_err)),
            )),
        }
    }
}

impl VRFPublicKey {
    /// Given a [`Proof`] and an input, returns whether or not the proof is valid for the input
    /// and public key
    fn verify(&self, proof: &Proof, alpha: &[u8]) -> Result<(), VerificationError> {
        let h_point = self.hash_to_curve(alpha);
        let pk_point = match CompressedEdwardsY::from_slice(self.0.as_bytes()).decompress() {
            Some(pt) => pt,
            None => {
                return Err(VerificationError::build(
                    Some(VerificationErrorType::Vrf),
                    Some("Failed to decompress public key into Edwards point".to_string()),
                ))
            }
        };
        let cprime = hash_points(&[
            h_point,
            proof.gamma,
            ED25519_BASEPOINT_POINT * proof.s - pk_point * proof.c,
            h_point * proof.s - proof.gamma * proof.c,
        ]);

        if proof.c == cprime {
            Ok(())
        } else {
            Err(VerificationError::build(
                Some(VerificationErrorType::Vrf),
                Some("The proof failed to verify for this public key".to_string()),
            ))
        }
    }

    fn hash_to_curve(&self, alpha: &[u8]) -> EdwardsPoint {
        let mut result = [0u8; 32];
        let mut counter = 0;
        let mut wrapped_point: Option<EdwardsPoint> = None;

        while wrapped_point.is_none() {
            let hash = Sha512::new()
                .chain(&[SUITE, ONE])
                .chain(self.0.as_bytes())
                .chain(&alpha)
                .chain(&[counter])
                .finalize();
            result.copy_from_slice(&hash[..32]);
            wrapped_point = CompressedEdwardsY::from_slice(&result).decompress();
            counter += 1;
        }

        wrapped_point.unwrap().mul_by_cofactor()
    }

    /// This function is called to verify that a given NodeLabel is indeed
    /// the VRF for a given version (fresh or stale) for a username.
    /// Hence, it also takes as input the server's public key.
    pub(crate) fn verify_label(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
        proof: &[u8],
        label: NodeLabel,
    ) -> Result<(), VerificationError> {
        // Initialization of VRF context by providing a curve

        let name_hash_bytes = hash(uname);
        let stale_bytes = if stale { &[0u8] } else { &[1u8] };

        let message = merge(&[name_hash_bytes, merge_with_int(hash(stale_bytes), version)]);

        // VRF proof verification (returns VRF hash output)
        let proof = Proof::try_from(proof)?;
        self.verify(&proof, &message)?;

        let output: Output = (&proof).into();
        let expected_label = NodeLabel {
            val: output.to_truncated_bytes(),
            len: 256u32,
        };
        if expected_label == label {
            Ok(())
        } else {
            Err(VerificationError::build(
                Some(VerificationErrorType::Vrf),
                Some(format!(
                    "Expected first {} bytes of the proof output did NOT match the supplied label",
                    NODE_LABEL_LEN
                )),
            ))
        }
    }
}

/// A VRF proof that can be used to validate an input with a public key
pub struct Proof {
    gamma: EdwardsPoint,
    c: ed25519_Scalar,
    s: ed25519_Scalar,
}

impl TryFrom<&[u8]> for Proof {
    type Error = VerificationError;

    fn try_from(bytes: &[u8]) -> Result<Proof, Self::Error> {
        let mut c_buf = [0u8; 32];
        c_buf[..16].copy_from_slice(&bytes[32..48]);
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&bytes[48..]);

        let pk_point = match CompressedEdwardsY::from_slice(&bytes[..32]).decompress() {
            Some(pt) => pt,
            None => {
                return Err(VerificationError::build(
                    Some(VerificationErrorType::Vrf),
                    Some("Failed to decompress public key into Edwards point".to_string()),
                ))
            }
        };

        Ok(Proof {
            gamma: pk_point,
            c: ed25519_Scalar::from_bits(c_buf),
            s: ed25519_Scalar::from_bits(s_buf),
        })
    }
}

/// The ECVRF output produced from the proof
pub struct Output([u8; OUTPUT_LENGTH]);

impl Output {
    /// Retrieve a truncated version of the hash output. Truncated
    /// to 32 bytes (NODE_LABEL_LEN). Truncation is for future-guarding
    /// should we change the hash function to a smaller (e.g. BLAKE3) search
    /// space. Presently it's SHA512, however for this purpose truncation is safe
    /// since we're just comparing the first 32 bytes rather than the full 64
    pub(super) fn to_truncated_bytes(&self) -> [u8; NODE_LABEL_LEN] {
        let mut truncated_hash: [u8; NODE_LABEL_LEN] = [0u8; NODE_LABEL_LEN];
        truncated_hash.copy_from_slice(&self.0[..NODE_LABEL_LEN]);
        truncated_hash
    }
}

impl<'a> From<&'a Proof> for Output {
    fn from(proof: &'a Proof) -> Output {
        let mut output = [0u8; OUTPUT_LENGTH];
        output.copy_from_slice(
            &Sha512::new()
                .chain(&[SUITE, THREE])
                .chain(&proof.gamma.mul_by_cofactor().compress().to_bytes()[..])
                .finalize()[..],
        );
        Output(output)
    }
}

fn hash_points(points: &[EdwardsPoint]) -> ed25519_Scalar {
    let mut result = [0u8; 32];
    let mut hash = Sha512::new().chain(&[SUITE, TWO]);
    for point in points.iter() {
        hash = hash.chain(point.compress().to_bytes());
    }
    result[..16].copy_from_slice(&hash.finalize()[..16]);
    ed25519_Scalar::from_bits(result)
}
