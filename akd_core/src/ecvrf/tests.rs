// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains tests on the Elliptic curve VRF implemented within the
//! AKD crate. Adapted from [here](https://github.com/diem/diem/blob/502936fbd59e35276e2cf455532b143796d68a16/crypto/nextgen_crypto/src/vrf/unit_tests/vrf_test.rs)

use crate::ecvrf::ecvrf_impl::*;

#[cfg(feature = "nostd")]
use alloc::format;
use bincode::serialize;
use core::convert::TryFrom;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY,
    scalar::Scalar as ed25519_Scalar,
};
use ed25519_dalek::{
    self, VerifyingKey as ed25519_PublicKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
#[cfg(feature = "serde_serialization")]
use proptest::prelude::*;
use proptest_derive::Arbitrary;
#[cfg(feature = "serde_serialization")]
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A type family for schemes which know how to generate key material from
/// a cryptographically-secure [`CryptoRng`][::rand::CryptoRng].
pub trait Uniform {
    /// Generate key material from an RNG for testing purposes.
    fn generate_for_testing<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore;
}

/// Output value of our hash function. Intentionally opaque for safety and modularity.
#[derive(
    Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize, PartialOrd, Ord, Arbitrary, Debug,
)]
pub struct HashValue {
    pub(crate) hash: [u8; 32],
}

impl Uniform for VRFPrivateKey {
    fn generate_for_testing<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        VRFPrivateKey(bytes)
    }
}

/// A keypair consisting of a private and public key
#[derive(Clone)]
pub struct KeyPair<S, P>
where
    for<'a> P: From<&'a S>,
{
    pub private_key: S,
    pub public_key: P,
}

impl<S, P> From<S> for KeyPair<S, P>
where
    for<'a> P: From<&'a S>,
{
    fn from(private_key: S) -> Self {
        KeyPair {
            public_key: (&private_key).into(),
            private_key,
        }
    }
}

impl<S, P> Uniform for KeyPair<S, P>
where
    S: Uniform,
    for<'a> P: From<&'a S>,
{
    fn generate_for_testing<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let private_key = S::generate_for_testing(rng);
        private_key.into()
    }
}

impl<Priv, Pub> core::fmt::Debug for KeyPair<Priv, Pub>
where
    Priv: Serialize,
    Pub: Serialize + for<'a> From<&'a Priv>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = serialize(&self.private_key).unwrap();
        v.extend(&serialize(&self.public_key).unwrap());
        write!(f, "{}", hex::encode(&v[..]))
    }
}

macro_rules! to_string {
    ($e:expr) => {
        format!("{}", ::hex::encode($e.to_bytes().as_ref()))
    };
}

macro_rules! from_string {
    (CompressedEdwardsY, $e:expr) => {
        CompressedEdwardsY::from_slice(&::hex::decode($e).unwrap())
            .expect("Slice should be of length 32, but it is not")
            .decompress()
            .unwrap()
    };
    (VRFPublicKey, $e:expr) => {{
        let v: &[u8] = &::hex::decode($e).unwrap();
        VRFPublicKey::try_from(v).unwrap()
    }};
    ($t:ty, $e:expr) => {
        <$t>::try_from(::hex::decode($e).unwrap().as_ref()).unwrap()
    };
}

#[allow(dead_code, non_snake_case)]
struct VRFTestVector {
    SK: &'static str,
    PK: &'static str,
    alpha: &'static [u8],
    x: &'static str,
    H: &'static str,
    k: &'static str,
    U: &'static str,
    V: &'static str,
    pi: &'static str,
    beta: &'static str,
}

/// These test vectors are taken from [RFC9381, Section B.3](https://www.ietf.org/rfc/rfc9381.html#name-ecvrf-edwards25519-sha512-t).
const TESTVECTORS : [VRFTestVector; 3] = [
    // Example 16
    VRFTestVector {
        SK : "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        PK : "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        alpha : b"",
        x : "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f",
        // try_and_increment succeeded on ctr = 0
        H : "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
        k : "7100f3d9eadb6dc4743b029736ff283f5be494128df128df2817106f345b8594b6d6da2d6fb0b4c0257eb337675d96eab49cf39e66cc2c9547c2bf8b2a6afae4",
        U : "aef27c725be964c6a9bf4c45ca8e35df258c1878b838f37d9975523f09034071",
        V : "5016572f71466c646c119443455d6cb9b952f07d060ec8286d678615d55f954f",
        pi : "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
        beta : "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
    },
    // Example 17
    VRFTestVector {
        SK : "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        PK : "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        alpha : b"\x72",
        x : "68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51",
        // try_and_increment succeeded on ctr = 1
        H : "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
        k : "42589bbf0c485c3c91c1621bb4bfe04aed7be76ee48f9b00793b2342acb9c167cab856f9f9d4febc311330c20b0a8afd3743d05433e8be8d32522ecdc16cc5ce",
        U : "1dcb0a4821a2c48bf53548228b7f170962988f6d12f5439f31987ef41f034ab3",
        V : "fd03c0bf498c752161bae4719105a074630a2aa5f200ff7b3995f7bfb1513423",
        pi : "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
        beta : "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
    },
    // Example 18
    VRFTestVector {
        SK : "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        PK : "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        alpha : b"\xaf\x82",
        x : "909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea95c",
        // try_and_increment succeeded on ctr = 0
        H : "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
        k : "38b868c335ccda94a088428cbf3ec8bc7955bfaffe1f3bd2aa2c59fc31a0febc59d0e1af3715773ce11b3bbdd7aba8e3505d4b9de6f7e4a96e67e0d6bb6d6c3a",
        U : "2bae73e15a64042fcebf062abe7e432b2eca6744f3e8265bc38e009cd577ecd5",
        V : "88cba1cb0d4f9b649d9a86026b69de076724a93a65c349c988954f0961c5d506",
        pi : "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
        beta : "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
    },
];

#[test]
fn test_expand_secret_key() {
    for tv in TESTVECTORS.iter() {
        let sk = from_string!(VRFPrivateKey, tv.SK);
        let esk = VRFExpandedPrivateKey::from(&sk);
        let pk = VRFPublicKey::try_from(&sk).unwrap();
        assert_eq!(tv.PK, to_string!(pk));
        assert_eq!(tv.x, to_string!(esk.key));
    }
}

#[test]
fn test_hash_to_curve() {
    for tv in TESTVECTORS.iter() {
        let pk = from_string!(VRFPublicKey, tv.PK);
        let h_point = pk.encode_to_curve(tv.alpha);
        assert_eq!(tv.H, to_string!(h_point.compress()));
    }
}

#[test]
fn test_nonce_generation() {
    for tv in TESTVECTORS.iter() {
        let sk = VRFExpandedPrivateKey::from(&from_string!(VRFPrivateKey, tv.SK));
        let h_point = from_string!(CompressedEdwardsY, tv.H);
        let k = nonce_generation_bytes(sk.nonce, &h_point.compress().to_bytes());
        assert_eq!(tv.k, ::hex::encode(&k[..]));
    }
}

#[test]
fn test_hash_points() {
    for tv in TESTVECTORS.iter() {
        let sk = VRFExpandedPrivateKey::from(&from_string!(VRFPrivateKey, tv.SK));
        let h_point = from_string!(CompressedEdwardsY, tv.H);
        let k_bytes = nonce_generation_bytes(sk.nonce, &h_point.compress().to_bytes());
        let k_scalar = ed25519_Scalar::from_bytes_mod_order_wide(&k_bytes);

        let gamma = h_point * sk.key;
        let u = ED25519_BASEPOINT_POINT * k_scalar;
        let v = h_point * k_scalar;

        assert_eq!(tv.U, to_string!(u.compress()));
        assert_eq!(tv.V, to_string!(v.compress()));

        let mut pk_bytes: [u8; 32] = [0u8; 32];
        pk_bytes.copy_from_slice(&hex::decode(tv.PK).unwrap());
        let pk = ed25519_PublicKey::from_bytes(&pk_bytes).unwrap();
        let c_scalar = hash_points(pk, &h_point.compress().to_bytes(), &[gamma, u, v]);

        let s_scalar = k_scalar + c_scalar * sk.key;

        let mut c_bytes = [0u8; 16];
        c_bytes.copy_from_slice(&c_scalar.to_bytes()[..16]);

        let pi = Proof::new(gamma, c_scalar, s_scalar);

        assert_eq!(tv.pi, to_string!(pi));
    }
}

#[test]
fn test_prove() {
    for tv in TESTVECTORS.iter() {
        let sk = from_string!(VRFPrivateKey, tv.SK);
        let pi = sk.prove(tv.alpha);

        assert_eq!(tv.pi, to_string!(pi));
    }
}

#[test]
fn test_verify() {
    for tv in TESTVECTORS.iter() {
        assert!(from_string!(VRFPublicKey, tv.PK)
            .verify(&from_string!(Proof, tv.pi), tv.alpha)
            .is_ok());
    }
}

#[test]
fn test_output_from_proof() {
    for tv in TESTVECTORS.iter() {
        assert_eq!(
            tv.beta,
            to_string!(Output::from(
                &from_string!(VRFPrivateKey, tv.SK).prove(tv.alpha)
            ))
        );

        // Also check that direct evaluation matches the same output
        assert_eq!(
            tv.beta,
            to_string!(&from_string!(VRFPrivateKey, tv.SK).evaluate(tv.alpha))
        );
    }
}

#[test]
fn test_publickey_clone() {
    // PublicKey has its own implementation of Clone
    for tv in TESTVECTORS.iter() {
        let orig = from_string!(VRFPublicKey, tv.PK);
        let clone = orig.clone();
        // the same bytes comprise both keys
        assert_eq!(orig.as_bytes(), clone.as_bytes());
    }
}

#[test]
fn test_privatekey_clone() {
    // PrivateKey (aka SecretKey) uses a custom implementation of clone wherein
    // the cloned key is created from the bytes of the original
    for tv in TESTVECTORS.iter() {
        let orig = from_string!(VRFPrivateKey, tv.SK);
        let clone = orig.clone();
        // the same bytes comprise both keys
        assert_eq!(orig.0, clone.0);
    }
}

#[cfg(feature = "serde_serialization")]
proptest! {
    #[test]
    fn test_prove_and_verify(
        hash1 in any::<HashValue>(),
        hash2 in any::<HashValue>(),
        keypair in uniform_keypair_strategy::<VRFPrivateKey, VRFPublicKey>()
    ) {
        let (pk, sk) = (&keypair.public_key, &keypair.private_key);
        let pk_test = VRFPublicKey::try_from(sk).unwrap();
        prop_assert_eq!(pk, &pk_test);
        let (input1, input2) = (hash1.hash.as_ref(), hash2.hash.as_ref());
        let proof1 = sk.prove(input1);
        prop_assert!(pk.verify(&proof1, input1).is_ok());
        prop_assert!(pk.verify(&proof1, input2).is_err());
    }
}

#[cfg(feature = "serde_serialization")]
/// Produces a uniformly random keypair from a seed
fn uniform_keypair_strategy<Priv, Pub>() -> impl Strategy<Value = KeyPair<Priv, Pub>>
where
    Pub: Serialize + for<'a> From<&'a Priv>,
    Priv: Serialize + Uniform,
{
    // The no_shrink is because keypairs should be fixed -- shrinking would cause a different
    // keypair to be generated, which appears to not be very useful.
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = <StdRng as rand::SeedableRng>::from_seed(seed);
            KeyPair::<Priv, Pub>::generate_for_testing(&mut rng)
        })
        .no_shrink()
}

#[test]
fn test_tryfrom_vrf_private_key() {
    let bytes = [0u8; SECRET_KEY_LENGTH - 1];
    assert!(VRFPrivateKey::try_from(&bytes[..]).is_err());
}

#[test]
fn test_tryfrom_vrf_public_key() {
    let bytes = [0u8; PUBLIC_KEY_LENGTH - 1];
    assert!(VRFPublicKey::try_from(&bytes[..]).is_err());
}

#[test]
fn test_tryfrom_vrf_proof() {
    let bytes = [0u8; PROOF_LENGTH - 1];
    assert!(Proof::try_from(&bytes[..]).is_err());
}
