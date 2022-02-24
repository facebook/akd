// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains implementations of a
//! [verifiable random function](https://en.wikipedia.org/wiki/Verifiable_random_function)
//! (currently only ECVRF). VRFs can be used in the consensus protocol for leader election.
//!
//! This module implements an instantiation of a verifiable random function known as
//! [ECVRF-ED25519-SHA512-TAI](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-04).
//!
//! # Examples
//!
//! ```text
//! use nextgen_crypto::{traits::Uniform, vrf::ecvrf::*};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! let message = b"Test message";
//! let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
//! let private_key = VRFPrivateKey::generate_for_testing(&mut rng);
//! let public_key: VRFPublicKey = (&private_key).into();
//! ```
//! **Note**: The above example generates a private key using a private function intended only for
//! testing purposes. Production code should find an alternate means for secure key generation.
//!
//! Produce a proof for a message from a `VRFPrivateKey`, and verify the proof and message
//! using a `VRFPublicKey`:
//!
//! ```text
//! # use nextgen_crypto::{traits::Uniform, vrf::ecvrf::*};
//! # use rand::{rngs::StdRng, SeedableRng};
//! # let message = b"Test message";
//! # let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
//! # let private_key = VRFPrivateKey::generate_for_testing(&mut rng);
//! # let public_key: VRFPublicKey = (&private_key).into();
//! let proof = private_key.prove(message);
//! assert!(public_key.verify(&proof, message).is_ok());
//! ```
//!
//! Produce a pseudorandom output from a `Proof`:
//!
//! ```text
//! # use nextgen_crypto::{traits::Uniform, vrf::ecvrf::*};
//! # use rand::{rngs::StdRng, SeedableRng};
//! # let message = b"Test message";
//! # let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
//! # let private_key = VRFPrivateKey::generate_for_testing(&mut rng);
//! # let public_key: VRFPublicKey = (&private_key).into();
//! # let proof = private_key.prove(message);
//! let output: Output = (&proof).into();
//! ```

#[cfg(test)]
mod tests;

use core::convert::TryFrom;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar as ed25519_Scalar,
};

/*
 * NOTE: rust-analyzer gives an "unresolved import" error for the following since they're
 * re-imported from inner-dependency crates. You can disable the warning in the preferences with
 *
 * ```json
 * "rust-analyzer.diagnostics.disabled": ["unresolved-import"]
 * ```
 *
 * This is a known problem with rust-analyzer and is documented in the issue
 * https://github.com/rust-analyzer/rust-analyzer/issues/6038
 * and
 * https://github.com/rust-analyzer/rust-analyzer/issues/7637
 *
 * You can also safely ignore it and move on with your day :)
*/
use ed25519_dalek::{
    self, Digest, PublicKey as ed25519_PublicKey, SecretKey as ed25519_PrivateKey, Sha512,
};

const SUITE: u8 = 0x03;
const ONE: u8 = 0x01;
const TWO: u8 = 0x02;
const THREE: u8 = 0x03;

/// The number of bytes of [`Output`]
pub const OUTPUT_LENGTH: usize = 64;
/// The number of bytes of [`Proof`]
pub const PROOF_LENGTH: usize = 80;

/// An ECVRF private key
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct VRFPrivateKey(ed25519_PrivateKey);

impl core::ops::Deref for VRFPrivateKey {
    type Target = ed25519_PrivateKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
/// An ECVRF public key
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    type Error = crate::errors::VRFStorageError;

    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<VRFPrivateKey, crate::errors::VRFStorageError> {
        Ok(VRFPrivateKey(
            ed25519_PrivateKey::from_bytes(bytes).unwrap(),
        ))
    }
}

impl TryFrom<&[u8]> for VRFPublicKey {
    type Error = crate::errors::VRFStorageError;

    fn try_from(bytes: &[u8]) -> std::result::Result<VRFPublicKey, crate::errors::VRFStorageError> {
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(crate::errors::VRFStorageError::VRFErr(
                "Wrong length".to_string(),
            ));
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or_else(|| crate::errors::VRFStorageError::VRFErr(
                "Deserialization failed".to_string(),
            ))?;

        // Check if the point lies on a small subgroup. This is required
        // when using curves with a small cofactor (in ed25519, cofactor = 8).
        if point.is_small_order() {
            return Err(crate::errors::VRFStorageError::VRFErr(
                "Small subgroup".to_string(),
            ));
        }

        Ok(VRFPublicKey(ed25519_PublicKey::from_bytes(bytes).unwrap()))
    }
}

impl VRFPublicKey {
    /// Given a [`Proof`] and an input, returns whether or not the proof is valid for the input
    /// and public key
    pub fn verify(
        &self,
        proof: &Proof,
        alpha: &[u8],
    ) -> Result<(), crate::errors::VRFStorageError> {
        let h_point = self.hash_to_curve(alpha);
        let pk_point = CompressedEdwardsY::from_slice(self.0.as_bytes())
            .decompress()
            .unwrap();
        let cprime = hash_points(&[
            h_point,
            proof.gamma,
            ED25519_BASEPOINT_POINT * proof.s - pk_point * proof.c,
            h_point * proof.s - proof.gamma * proof.c,
        ]);

        if proof.c == cprime {
            Ok(())
        } else {
            Err(crate::errors::VRFStorageError::VRFErr(
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
    type Error = crate::errors::VRFStorageError;

    fn try_from(bytes: &[u8]) -> std::result::Result<Proof, crate::errors::VRFStorageError> {
        let mut c_buf = [0u8; 32];
        c_buf[..16].copy_from_slice(&bytes[32..48]);
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&bytes[48..]);
        Ok(Proof {
            gamma: CompressedEdwardsY::from_slice(&bytes[..32])
                .decompress()
                .unwrap(),
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
    pub fn to_bytes(&self) -> [u8; OUTPUT_LENGTH] {
        self.0
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
