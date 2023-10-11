// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains the raw implementation implements the ECVRF functionality for use in the AKD crate
use super::VrfError;

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::ToString;
use core::convert::TryFrom;
use curve25519_dalek::digest::Update;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar as ed25519_Scalar,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
use ed25519_dalek::SecretKey as ed25519_PrivateKey;
use ed25519_dalek::Sha512;
use ed25519_dalek::SigningKey as ed25519_SigningKey;
use ed25519_dalek::VerifyingKey as ed25519_PublicKey;
use ed25519_dalek::SECRET_KEY_LENGTH;
use ed25519_dalek::{Digest, PUBLIC_KEY_LENGTH};

const SUITE: u8 = 0x03;
const ZERO: u8 = 0x00;
const ONE: u8 = 0x01;
const TWO: u8 = 0x02;
const THREE: u8 = 0x03;

/// The number of bytes of [`Output`]
pub const OUTPUT_LENGTH: usize = 64;
/// The number of bytes of [`Proof`]
pub const PROOF_LENGTH: usize = 80;

/// An ECVRF private key
#[derive(Debug, Clone)]
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
#[derive(Clone)]
pub struct VRFExpandedPrivateKey {
    pub(super) key: ed25519_Scalar,
    pub(super) nonce: [u8; 32],
}

impl Drop for VRFExpandedPrivateKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

impl ZeroizeOnDrop for VRFExpandedPrivateKey {}

impl VRFPrivateKey {
    /// Produces a proof for an input (using the private key)
    pub fn prove(&self, alpha: &[u8]) -> Proof {
        VRFExpandedPrivateKey::from(self).prove(&VRFPublicKey::from(self), alpha)
    }

    /// Directly evaluate the VRF for an input, without producing a proof (using the private key)
    pub fn evaluate(&self, alpha: &[u8]) -> Output {
        VRFExpandedPrivateKey::from(self).evaluate(&VRFPublicKey::from(self), alpha)
    }
}

impl VRFExpandedPrivateKey {
    /// Produces a proof for an input (using the expanded private key)
    pub fn prove(&self, pk: &VRFPublicKey, alpha: &[u8]) -> Proof {
        let h_point = pk.encode_to_curve(alpha);
        let h_point_bytes = h_point.compress().to_bytes();
        let k_scalar = ed25519_Scalar::from_bytes_mod_order_wide(&nonce_generation_bytes(
            self.nonce,
            &h_point_bytes,
        ));
        let gamma = h_point * self.key;
        let c_scalar = hash_points(
            pk.0,
            &h_point_bytes,
            &[
                gamma,
                curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &k_scalar,
                h_point * k_scalar,
            ],
        );

        Proof {
            gamma,
            c: c_scalar,
            s: k_scalar + c_scalar * self.key,
        }
    }

    /// Directly evaluate the VRF for an input, without producing a proof (using the expanded private key)
    pub fn evaluate(&self, pk: &VRFPublicKey, alpha: &[u8]) -> Output {
        let h_point = pk.encode_to_curve(alpha);
        let gamma = h_point * self.key;
        gamma_to_output(&gamma)
    }
}

impl TryFrom<&[u8]> for VRFPrivateKey {
    type Error = VrfError;

    fn try_from(bytes: &[u8]) -> Result<VRFPrivateKey, VrfError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(VrfError::SigningKey(
                "Wrong length, expected 32 byte private key".to_string(),
            ));
        }

        let mut key = [0u8; SECRET_KEY_LENGTH];
        key.copy_from_slice(bytes);
        Ok(VRFPrivateKey(key))
    }
}

impl TryFrom<&[u8]> for VRFPublicKey {
    type Error = VrfError;

    fn try_from(bytes: &[u8]) -> Result<VRFPublicKey, Self::Error> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(VrfError::PublicKey("Wrong length".to_string()));
        }

        let mut bits: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        bits.copy_from_slice(&bytes[..PUBLIC_KEY_LENGTH]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or_else(|| VrfError::PublicKey("Deserialization failed".to_string()))?;

        // Check if the point lies on a small subgroup. This is required
        // when using curves with a small cofactor (in ed25519, cofactor = 8).
        if point.is_small_order() {
            return Err(VrfError::PublicKey("Small subgroup".to_string()));
        }

        match ed25519_PublicKey::from_bytes(&bits) {
            Ok(result) => Ok(VRFPublicKey(result)),
            Err(sig_err) => Err(VrfError::PublicKey(format!("Signature error {sig_err}"))),
        }
    }
}

impl VRFPublicKey {
    /// Given a [`Proof`] and an input, returns whether or not the proof is valid for the input
    /// and public key.
    ///
    /// Note that public key validation occurs in the [TryFrom] implementation for [VRFPublicKey],
    /// as well as the [From] implementation for [VRFPrivateKey] (implicitly in the ed25519_dalek library).
    /// Therefore, we do not perform public key validation in the verification function itself.
    pub fn verify(&self, proof: &Proof, alpha: &[u8]) -> Result<(), VrfError> {
        let h_point = self.encode_to_curve(alpha);
        let pk_point = match CompressedEdwardsY::from_slice(self.as_bytes())
            .map_err(|_| {
                VrfError::Verification(
                    "Failed to parse public key, incorrect byte string length".to_string(),
                )
            })?
            .decompress()
        {
            Some(pt) => pt,
            None => {
                return Err(VrfError::Verification(
                    "Failed to decompress public key into Edwards point".to_string(),
                ))
            }
        };
        let cprime = hash_points(
            self.0,
            &h_point.compress().to_bytes(),
            &[
                proof.gamma,
                ED25519_BASEPOINT_POINT * proof.s - pk_point * proof.c,
                h_point * proof.s - proof.gamma * proof.c,
            ],
        );

        if proof.c == cprime {
            Ok(())
        } else {
            Err(VrfError::Verification(
                "The proof failed to verify for this public key".to_string(),
            ))
        }
    }

    /// Implements the [ECVRF_encode_to_curve_try_and_increment](https://www.ietf.org/rfc/rfc9381.html#section-5.4.1.1) algorithm
    pub(super) fn encode_to_curve(&self, alpha: &[u8]) -> EdwardsPoint {
        let mut hash_result = [0u8; 32];
        let mut counter = 0;
        loop {
            let hash = Sha512::new()
                .chain([SUITE, ONE])
                .chain(self.0.as_bytes())
                .chain(alpha)
                .chain([counter, ZERO])
                .finalize();
            hash_result.copy_from_slice(&hash[..32]);
            let wrapped_point = interpret_hash_value_as_a_point(hash_result);
            counter += 1;
            if let Some(wp) = wrapped_point {
                let result = wp.mul_by_cofactor();

                // Ensure that what we are returning is not the identity point
                if !result.is_identity() {
                    return result;
                }
            }
        }
    }
}

/// As defined in [Section 5.1.3 of RFC8032](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3)
///
/// Will return Some(point) if the hash value can be interpreted as a point, and None otherwise.
fn interpret_hash_value_as_a_point(hash: [u8; 32]) -> Option<EdwardsPoint> {
    // If the input bytes are such that bytes 1 to 30 have value 255, byte 31 has value 255 or 127,
    // and byte 0 has value 256 - i for value i in the (1, 3, 4, 5, 9, 10, 13, 14, 15, 16) list, then
    // the encoding is invalid.
    let is_invalid = hash[1..=30].iter().all(|b| *b == 255)
        && (hash[31] == 255 || hash[31] == 127)
        && [1u8, 3, 4, 5, 9, 10, 13, 14, 15, 16].contains(&((256u16 - hash[0] as u16) as u8));
    if is_invalid {
        return None;
    }
    CompressedEdwardsY::from_slice(&hash)
        .expect("Result hash should have a length of 32, but it does not")
        .decompress()
}

impl<'a> From<&'a VRFPrivateKey> for VRFPublicKey {
    fn from(private_key: &'a VRFPrivateKey) -> Self {
        let signing_key = ed25519_SigningKey::from_bytes(private_key);
        VRFPublicKey(ed25519_PublicKey::from(&signing_key))
    }
}

impl<'a> From<&'a VRFPrivateKey> for VRFExpandedPrivateKey {
    fn from(private_key: &'a VRFPrivateKey) -> Self {
        let mut h: Sha512 = Sha512::default();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        Update::update(&mut h, &private_key.0);
        hash.copy_from_slice(h.finalize().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        VRFExpandedPrivateKey {
            #[allow(deprecated)]  // Using the legacy from_bits() function to avoid reducing the scalar
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

    fn try_from(bytes: &[u8]) -> Result<Proof, VrfError> {
        if bytes.len() != PROOF_LENGTH {
            return Err(VrfError::Verification(format!(
                "Invalid proof length, expected {PROOF_LENGTH} bytes"
            )));
        }
        let mut c_buf = [0u8; 32];
        c_buf[..16].copy_from_slice(&bytes[32..48]);
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&bytes[48..]);

        let pk_point = match CompressedEdwardsY::from_slice(&bytes[..32])
            .expect("Byte string should be of length 32, but it is not")
            .decompress()
        {
            Some(pt) => pt,
            None => {
                return Err(VrfError::PublicKey(
                    "Failed to decompress public key into Edwards Point".to_string(),
                ))
            }
        };

        Ok(Proof {
            gamma: pk_point,
            c: ed25519_Scalar::from_bytes_mod_order(c_buf),
            s: ed25519_Scalar::from_bytes_mod_order(s_buf),
        })
    }
}

/// The ECVRF output produced from the proof
pub struct Output([u8; OUTPUT_LENGTH]);

impl Output {
    /// Converts an Output into bytes
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn to_bytes(&self) -> [u8; OUTPUT_LENGTH] {
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
        gamma_to_output(&proof.gamma)
    }
}

/// Internal function used to produce an Output from the gamma field of a Proof
fn gamma_to_output(gamma: &EdwardsPoint) -> Output {
    let mut output = [0u8; OUTPUT_LENGTH];
    output.copy_from_slice(
        &Sha512::new()
            .chain([SUITE, THREE])
            .chain(gamma.mul_by_cofactor().compress().as_bytes())
            .chain([ZERO])
            .finalize()[..],
    );
    Output(output)
}

pub(super) fn nonce_generation_bytes(nonce: [u8; 32], h_point_bytes: &[u8]) -> [u8; 64] {
    let mut k_buf = [0u8; 64];
    k_buf.copy_from_slice(&Sha512::new().chain(nonce).chain(h_point_bytes).finalize()[..]);
    k_buf
}

pub(super) fn hash_points(
    pk: ed25519_PublicKey,
    h_point_bytes: &[u8],
    points: &[EdwardsPoint],
) -> ed25519_Scalar {
    let mut result = [0u8; 32];
    let mut hash = Sha512::new()
        .chain([SUITE, TWO])
        .chain(pk.to_bytes())
        .chain(h_point_bytes);
    for point in points.iter() {
        hash = hash.chain(point.compress().to_bytes());
    }
    result[..16].copy_from_slice(&hash.chain([ZERO]).finalize()[..16]);
    ed25519_Scalar::from_bytes_mod_order(result)
}
