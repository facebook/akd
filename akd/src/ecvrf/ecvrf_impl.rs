// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the raw implementation implements the ECVRF functionality for use in the AKD crate

use crate::{errors::VrfError, node_state::NodeLabel, storage::types::AkdLabel};
use core::convert::TryFrom;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar as ed25519_Scalar,
};
use winter_crypto::Hasher;

/// The length of a node-label's value field in bytes.
/// This is used for truncation of the hash to this many bytes
const NODE_LABEL_LEN: usize = 32;

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
use ed25519_dalek::SecretKey as ed25519_PrivateKey;
use ed25519_dalek::Sha512;

const SUITE: u8 = 0x03;
const ONE: u8 = 0x01;
const TWO: u8 = 0x02;
const THREE: u8 = 0x03;

/// The number of bytes of [`Output`]
pub const OUTPUT_LENGTH: usize = 64;
/// The number of bytes of [`Proof`]
pub const PROOF_LENGTH: usize = 80;

/// An ECVRF private key
#[derive(Debug)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct VRFPrivateKey(pub(crate) ed25519_PrivateKey);

impl core::ops::Deref for VRFPrivateKey {
    type Target = ed25519_PrivateKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::clone::Clone for VRFPrivateKey {
    fn clone(&self) -> Self {
        // In theory, creating a key from bytes could be a DecodingError, except
        // we just copied these bytes out of the source key, so ...
        Self(ed25519_PrivateKey::from_bytes(self.0.as_bytes()).unwrap())
    }
}

/// An ECVRF public key
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct VRFPublicKey(ed25519_PublicKey);

impl core::ops::Deref for VRFPublicKey {
    type Target = ed25519_PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A longer private key which is slightly optimized for proof generation.
///
/// This is similar in structure to ed25519_dalek::ExpandedSecretKey. It can be produced from
/// a VRFPrivateKey.
pub struct VRFExpandedPrivateKey {
    pub(super) key: ed25519_Scalar,
    pub(super) nonce: [u8; 32],
}

impl VRFPrivateKey {
    /// Produces a proof for an input (using the private key)
    pub fn prove(&self, alpha: &[u8]) -> Proof {
        VRFExpandedPrivateKey::from(self).prove(&VRFPublicKey((&self.0).into()), alpha)
    }
}

impl VRFExpandedPrivateKey {
    /// Produces a proof for an input (using the expanded private key)
    pub fn prove(&self, pk: &VRFPublicKey, alpha: &[u8]) -> Proof {
        let h_point = pk.hash_to_curve(alpha);
        let k_scalar =
            ed25519_Scalar::from_bytes_mod_order_wide(&nonce_generation_bytes(self.nonce, h_point));
        let gamma = h_point * self.key;
        let c_scalar = hash_points(&[
            h_point,
            gamma,
            ED25519_BASEPOINT_POINT * k_scalar,
            h_point * k_scalar,
        ]);

        Proof {
            gamma,
            c: c_scalar,
            s: k_scalar + c_scalar * self.key,
        }
    }
}

impl TryFrom<&[u8]> for VRFPrivateKey {
    type Error = VrfError;

    fn try_from(bytes: &[u8]) -> std::result::Result<VRFPrivateKey, VrfError> {
        match ed25519_PrivateKey::from_bytes(bytes) {
            Ok(result) => Ok(VRFPrivateKey(result)),
            Err(sig_err) => Err(VrfError::SigningKey(format!("Signature error {}", sig_err))),
        }
    }
}

impl TryFrom<&[u8]> for VRFPublicKey {
    type Error = VrfError;

    fn try_from(bytes: &[u8]) -> std::result::Result<VRFPublicKey, Self::Error> {
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(VrfError::PublicKey("Wrong length".to_string()));
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or_else(|| VrfError::PublicKey("Deserialization failed".to_string()))?;

        // Check if the point lies on a small subgroup. This is required
        // when using curves with a small cofactor (in ed25519, cofactor = 8).
        if point.is_small_order() {
            return Err(VrfError::PublicKey("Small subgroup".to_string()));
        }

        match ed25519_PublicKey::from_bytes(bytes) {
            Ok(result) => Ok(VRFPublicKey(result)),
            Err(sig_err) => Err(VrfError::PublicKey(format!("Signature error {}", sig_err))),
        }
    }
}

impl VRFPublicKey {
    /// Given a [`Proof`] and an input, returns whether or not the proof is valid for the input
    /// and public key
    pub fn verify(&self, proof: &Proof, alpha: &[u8]) -> Result<(), VrfError> {
        let h_point = self.hash_to_curve(alpha);
        let pk_point = match CompressedEdwardsY::from_slice(self.as_bytes()).decompress() {
            Some(pt) => pt,
            None => {
                return Err(VrfError::Verification(
                    "Failed to decompress public key into Edwards point".to_string(),
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
            Err(VrfError::Verification(
                "The proof failed to verify for this public key".to_string(),
            ))
        }
    }

    pub(super) fn hash_to_curve(&self, alpha: &[u8]) -> EdwardsPoint {
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
    pub fn verify_label<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
        proof: &[u8],
        label: NodeLabel,
    ) -> Result<(), VrfError> {
        // Initialization of VRF context by providing a curve

        let name_hash_bytes = H::hash(uname);
        let stale_bytes = if stale { &[0u8] } else { &[1u8] };

        let hashed_label = H::merge(&[
            name_hash_bytes,
            H::merge_with_int(H::hash(stale_bytes), version),
        ]);
        let message_vec = crate::serialization::from_digest::<H>(hashed_label);
        let message: &[u8] = message_vec.as_slice();

        // VRF proof verification (returns VRF hash output)
        let proof = Proof::try_from(proof)?;
        self.verify(&proof, message)?;

        let output: Output = (&proof).into();
        if NodeLabel::new(output.to_truncated_bytes(), 256u32) == label {
            Ok(())
        } else {
            Err(VrfError::Verification(
                "Expected first 32 bytes of the proof output did NOT match the supplied label"
                    .to_string(),
            ))
        }
    }
}

impl<'a> From<&'a VRFPrivateKey> for VRFPublicKey {
    fn from(private_key: &'a VRFPrivateKey) -> Self {
        let secret: &ed25519_PrivateKey = &private_key.0;
        let public: ed25519_PublicKey = secret.into();
        VRFPublicKey(public)
    }
}

impl<'a> From<&'a VRFPrivateKey> for VRFExpandedPrivateKey {
    fn from(private_key: &'a VRFPrivateKey) -> Self {
        let mut h: Sha512 = Sha512::default();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.update(private_key.0.to_bytes());
        hash.copy_from_slice(h.finalize().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        VRFExpandedPrivateKey {
            key: ed25519_Scalar::from_bits(lower),
            nonce: upper,
        }
    }
}

/// A VRF proof that can be used to validate an input with a public key
#[derive(Copy, Clone)]
pub struct Proof {
    gamma: EdwardsPoint,
    c: ed25519_Scalar,
    s: ed25519_Scalar,
}

impl Proof {
    /// Produces a new Proof struct from its fields
    pub fn new(gamma: EdwardsPoint, c: ed25519_Scalar, s: ed25519_Scalar) -> Proof {
        Proof { gamma, c, s }
    }

    /// Converts a Proof into bytes
    pub fn to_bytes(&self) -> [u8; PROOF_LENGTH] {
        let mut ret = [0u8; PROOF_LENGTH];
        ret[..32].copy_from_slice(&self.gamma.compress().to_bytes()[..]);
        ret[32..48].copy_from_slice(&self.c.to_bytes()[..16]);
        ret[48..].copy_from_slice(&self.s.to_bytes()[..]);
        ret
    }
}

impl TryFrom<&[u8]> for Proof {
    type Error = VrfError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Proof, VrfError> {
        let mut c_buf = [0u8; 32];
        c_buf[..16].copy_from_slice(&bytes[32..48]);
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&bytes[48..]);

        let pk_point = match CompressedEdwardsY::from_slice(&bytes[..32]).decompress() {
            Some(pt) => pt,
            None => {
                return Err(VrfError::PublicKey(
                    "Failed to decompress public key into Edwards Point".to_string(),
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
    /// Converts an Output into bytes
    #[inline]
    #[cfg(test)]
    pub fn to_bytes(&self) -> [u8; OUTPUT_LENGTH] {
        self.0
    }

    /// Retrieve a truncated version of the hash output. Truncated
    /// to 32 bytes (NODE_LABEL_LEN). Truncation is for future-guarding
    /// should we change the hash function to a smaller (e.g. BLAKE3) search
    /// space. Presently it's SHA512, however for this purpose truncation is safe
    /// since we're just comparing the first 32 bytes rather than the full 64
    pub(crate) fn to_truncated_bytes(&self) -> [u8; NODE_LABEL_LEN] {
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

pub(super) fn nonce_generation_bytes(nonce: [u8; 32], h_point: EdwardsPoint) -> [u8; 64] {
    let mut k_buf = [0u8; 64];
    k_buf.copy_from_slice(
        &Sha512::new()
            .chain(nonce)
            .chain(h_point.compress().as_bytes())
            .finalize()[..],
    );
    k_buf
}

pub(super) fn hash_points(points: &[EdwardsPoint]) -> ed25519_Scalar {
    let mut result = [0u8; 32];
    let mut hash = Sha512::new().chain(&[SUITE, TWO]);
    for point in points.iter() {
        hash = hash.chain(point.compress().to_bytes());
    }
    result[..16].copy_from_slice(&hash.finalize()[..16]);
    ed25519_Scalar::from_bits(result)
}
