// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of an authenticated key directory (AKD), also known as a verifiable registery or auditable key directory.
//!
//! ⚠️ **Warning**: This implementation has not been audited and is not ready for use in a real system. Use at your own risk!
//!
//! # Overview
//! An authenticated key directory (AKD) is an example of an authenticated
//! data structure. An AKD lets a server commit to a key-value store as it evolves over a
//! sequence of timesteps, also known as epochs.
//!
//! The security of this protocol relies on the following two assumptions for all parties:
//! * a small commitment is viewable by all users,
//! * at any given epoch transition, there exists at least one honest auditor,
//!   who audits the server's latest commitment, relative to the previous commitment.
//!
//!
//! ## Statelessness
//! This library is meant to be stateless, in that it runs without storing a majority of the data
//! locally, where the code is running, and instead, uses a [storage::Storable] trait for
//! each type to be stored in an external database.
//!
//! ## Setup
//! A [directory::Directory] represents an AKD. To setup a [directory::Directory], we first need to decide on
//! a database and a hash function. For this example, we use the [winter_crypto::hashers::Blake3_256] as the hash function,
//! [storage::memory::AsyncInMemoryDatabase] as storage and [ecvrf::HardCodedAkdVRF].
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//! type Blake3 = Blake3_256<BaseElement>;
//! use akd::directory::Directory;
//!
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//! };
//! ```
//!
//! ## Adding key-value pairs to the akd
//! To add key-value pairs to the akd, we assume that the types of keys and the corresponding values are String.
//! After adding key-value pairs to the akd's data structure, it also needs to be committed. To do this, after running the setup, as in the previous step,
//! we use the `publish` function of an akd. The argument of publish is a vector of tuples of type (AkdLabel::from_utf8_str(String), AkdValue::from_utf8_str(String)). See below for example usage.
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//! type Blake3 = Blake3_256<BaseElement>;
//! use akd::directory::Directory;
//!
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//!     // commit the latest changes
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello"), AkdValue::from_utf8_str("world")),
//!          (AkdLabel::from_utf8_str("hello2"), AkdValue::from_utf8_str("world2")),])
//!       .await;
//! };
//! ```
//!
//!
//! ## Responding to a client lookup
//! We can use the `lookup` API call of the [directory::Directory] to prove the correctness of a client lookup at a given epoch.
//! If
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::directory::Directory;
//! type Blake3 = Blake3_256<BaseElement>;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//!
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello"), AkdValue::from_utf8_str("world")),
//!         (AkdLabel::from_utf8_str("hello2"), AkdValue::from_utf8_str("world2")),])
//!          .await.unwrap();
//!     // Generate latest proof
//!     let lookup_proof = akd.lookup::<Blake3_256<BaseElement>>(AkdLabel::from_utf8_str("hello")).await;
//! };
//! ```
//! ## Verifying a lookup proof
//!  To verify the above proof, we call the client's verification algorithm, with respect to the latest commitment, as follows:
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::directory::Directory;
//! use akd::client;
//! type Blake3 = Blake3_256<BaseElement>;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//!
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello"), AkdValue::from_utf8_str("world")),
//!         (AkdLabel::from_utf8_str("hello2"), AkdValue::from_utf8_str("world2")),])
//!          .await.unwrap();
//!     // Generate latest proof
//!     let lookup_proof = akd.lookup::<Blake3_256<BaseElement>>(AkdLabel::from_utf8_str("hello")).await.unwrap();
//!     let current_azks = akd.retrieve_current_azks().await.unwrap();
//!     // Get the latest commitment, i.e. azks root hash
//!     let root_hash = akd.get_root_hash::<Blake3_256<BaseElement>>(&current_azks).await.unwrap();
//!     // Get the VRF public key of the server
//!     let vrf_pk = akd.get_public_key().await.unwrap();
//!     client::lookup_verify::<Blake3_256<BaseElement>>(
//!         &vrf_pk,
//!         root_hash,
//!         AkdLabel::from_utf8_str("hello"),
//!         lookup_proof,
//!     ).unwrap();
//! };
//! ```
//!
//! ## Responding to a client history query
//! As mentioned above, the security is defined by consistent views of the value for a key at any epoch.
//! To this end, a server running an AKD needs to provide a way to check the history of a key. Note that in this case,
//! the server is trusted for validating that a particular client is authorized to run a history check on a particular key.
//! We can use the `key_history` API call of the [directory::Directory] to prove the history of a key's values at a given epoch, as follows.
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::directory::Directory;
//! type Blake3 = Blake3_256<BaseElement>;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//!
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello"), AkdValue::from_utf8_str("world")),
//!         (AkdLabel::from_utf8_str("hello2"), AkdValue::from_utf8_str("world2")),])
//!          .await.unwrap();
//!     // Generate latest proof
//!     let history_proof = akd.key_history::<Blake3_256<BaseElement>>(&AkdLabel::from_utf8_str("hello")).await;
//! };
//! ```
//! ## Verifying a key history proof
//!  To verify the above proof, we again call the client's verification algorithm, defined in [client], with respect to the latest commitment, as follows:
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::client::key_history_verify;
//! use akd::directory::Directory;
//! type Blake3 = Blake3_256<BaseElement>;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello"), AkdValue::from_utf8_str("world")),
//!         (AkdLabel::from_utf8_str("hello2"), AkdValue::from_utf8_str("world2")),])
//!          .await.unwrap();
//!     // Generate latest proof
//!     let history_proof = akd.key_history::<Blake3_256<BaseElement>>(&AkdLabel::from_utf8_str("hello")).await.unwrap();
//!     let current_azks = akd.retrieve_current_azks().await.unwrap();
//!     // Get the azks root hashes at the required epochs
//!     let (root_hashes, previous_root_hashes) = akd::directory::get_key_history_hashes::<_, Blake3_256<BaseElement>, HardCodedAkdVRF>(&akd, &history_proof).await.unwrap();
//!     let current_azks = akd.retrieve_current_azks().await.unwrap();
//!     let current_epoch = current_azks.get_latest_epoch();
//!     let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await.unwrap();
//!     let vrf_pk = akd.get_public_key().await.unwrap();
//!     key_history_verify::<Blake3_256<BaseElement>>(
//!         &vrf_pk,
//!         root_hash,
//!         current_epoch,
//!         AkdLabel::from_utf8_str("hello"),
//!         history_proof,
//!         false,
//!         ).unwrap();
//!     };
//! ```
//!
//! ## Responding to an audit query
//! In addition to the client API calls, the AKD also provides proofs to auditors that its commitments evolved correctly.
//! Below we illustrate how the server responds to an audit query between two epochs.
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::directory::Directory;
//! type Blake3 = Blake3_256<BaseElement>;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//!
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//!     // Commit to the first epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello"), AkdValue::from_utf8_str("world")),
//!         (AkdLabel::from_utf8_str("hello2"), AkdValue::from_utf8_str("world2")),])
//!          .await.unwrap();
//!     // Commit to the second epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello3"), AkdValue::from_utf8_str("world3")),
//!         (AkdLabel::from_utf8_str("hello4"), AkdValue::from_utf8_str("world4")),])
//!          .await.unwrap();
//!     // Generate audit proof for the evolution from epoch 1 to epoch 2.
//!     let audit_proof = akd.audit::<Blake3_256<BaseElement>>(1u64, 2u64).await.unwrap();
//! };
//! ```
//! ## Verifying an audit proof
//!  The auditor verifies the above proof and the code for this is in [auditor].
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::auditor;
//! use akd::directory::Directory;
//! type Blake3 = Blake3_256<BaseElement>;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! use akd::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
//! use akd::storage::Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//!
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let vrf = HardCodedAkdVRF{};
//!     let mut akd = Directory::<_, HardCodedAkdVRF>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await.unwrap();
//!     // Commit to the first epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello"), AkdValue::from_utf8_str("world")),
//!         (AkdLabel::from_utf8_str("hello2"), AkdValue::from_utf8_str("world2")),])
//!          .await.unwrap();
//!     // Commit to the second epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdLabel::from_utf8_str("hello3"), AkdValue::from_utf8_str("world3")),
//!         (AkdLabel::from_utf8_str("hello4"), AkdValue::from_utf8_str("world4")),])
//!          .await.unwrap();
//!     // Generate audit proof for the evolution from epoch 1 to epoch 2.
//!     let audit_proof = akd.audit::<Blake3_256<BaseElement>>(1u64, 2u64).await.unwrap();
//!     let current_azks = akd.retrieve_current_azks().await.unwrap();
//!     // Get the latest commitment, i.e. azks root hash
//!     let start_root_hash = akd.get_root_hash_at_epoch::<Blake3_256<BaseElement>>(&current_azks, 1u64).await.unwrap();
//!     let end_root_hash = akd.get_root_hash_at_epoch::<Blake3_256<BaseElement>>(&current_azks, 2u64).await.unwrap();
//!     let hashes = vec![start_root_hash, end_root_hash];
//!     auditor::audit_verify::<Blake3_256<BaseElement>>(
//!         hashes,
//!         audit_proof,
//!     ).await.unwrap();
//! };
//! ```
//!
//! # Compilation Features
//!
//! The _akd_ crate supports multiple compilation features
//!
//! 1. _serde_: Will enable [`serde`] serialization support on all public structs used in storage & transmission operations. This is helpful
//! in the event you wish to directly serialize the structures to transmit between library <-> storage layer or library <-> clients. If you're
//! also utilizing VRFs (see (2.) below) it will additionally enable the _serde_ feature in the ed25519-dalek crate.
//!
//! 2. _vrf_ (on by-default): Will enable support of verifiable random function (VRF) usage within the library. See [ecvrf] for documentation
//! about the VRF functionality being utilized within AKD. This functionality is added protection so auditors don't see user identifiers directly
//! and applies a level of user-randomness (think hashing) in the node labels such that clients cannot trivially generate node labels themselves
//! for given identifiers, however they _can_ verify that a label is valid for a given identitifier. Transitively will add dependencies on crates
//! [`curve25519-dalek`] and [`ed25519-dalek`]. You can disable the VRF functionality by adding the no-default-features flags to your cargo
//! dependencies.
//!
//! 3. _public-tests_: Will expose some internal sanity testing functionality, which is often helpful so you don't have to write all your own
//! unit test cases when implementing a storage layer yourself. This helps guarantee the sanity of a given storage implementation. Should be
//! used only in unit testing scenarios by altering your Cargo.toml as such
//! ```toml
//! [dependencies]
//! akd = { version = "0.5", features = ["vrf"] }
//!
//! [dev-dependencies]
//! akd = { version = "0.5", features = ["vrf", "public-tests"] }
//! ```
//!

#![warn(missing_docs)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "rand")]
extern crate rand;

// Due to the amount of types an implementing storage layer needs to access,
// it's quite unreasonable to expose them all at the crate root, and a storage
// implementer will simply need to import the necessary inner types which are
// a dependency of ths [`Storage`] trait anyways

pub mod append_only_zks;
pub mod auditor;
pub mod client;
pub mod directory;
pub mod ecvrf;
pub mod errors;
pub mod node_state;
pub mod proof_structs;
pub mod serialization;
pub mod storage;
pub mod tree_node;

mod utils;

// ========== Type re-exports which are commonly used ========== //
pub use append_only_zks::Azks;
pub use directory::{Directory, EpochHash};
pub use node_state::{Node, NodeLabel};
pub use storage::types::{AkdLabel, AkdValue};

// ========== Constants and type aliases ========== //
#[cfg(any(test, feature = "public-tests"))]
pub mod test_utils;
#[cfg(test)]
mod tests;

/// The arity of the underlying tree structure of the akd.
pub const ARITY: usize = 2;
/// The length of a leaf node's label
pub const LEAF_LEN: u32 = 256;

/// The value to be hashed every time an empty node's hash is to be considered
pub const EMPTY_VALUE: [u8; 1] = [0u8];

/// The label used for an empty node
pub const EMPTY_LABEL: crate::node_state::NodeLabel = crate::node_state::NodeLabel {
    val: [1u8; 32],
    len: 0,
};

/// The label used for a root node
pub const ROOT_LABEL: crate::node_state::NodeLabel = crate::node_state::NodeLabel {
    val: [0u8; 32],
    len: 0,
};
/// A "tombstone" is a false value in an AKD ValueState denoting that a real value has been removed (e.g. data rentention policies).
/// Should a tombstone be encountered, we have to assume that the hash of the value is correct, and we move forward without being able to
/// verify the raw value. We utilize an empty array to save space in the storage layer
///
/// See [GitHub issue #130](https://github.com/novifinancial/akd/issues/130) for more context
pub const TOMBSTONE: &[u8] = &[];

/// This type is used to indicate a direction for a
/// particular node relative to its parent.
pub type Direction = Option<usize>;
