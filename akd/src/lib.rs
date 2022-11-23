// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of an auditable key directory (AKD), also known as a verifiable registry.
//!
//! ⚠️ **Warning**: This implementation has not been audited and is not ready for use in a real system. Use at your own risk!
//!
//! # Overview
//! An auditable key directory (AKD) provides an interface to a data structure that stores key-value
//! mappings in a database in a verifiable manner. The data structure is similar to that of a
//! Python [dict](https://docs.python.org/3/tutorial/datastructures.html), where directory entries are indexed by
//! _keys_, and allow for storing a _value_ with some key and then extracting the value given the key.
//!
//! Keys can also be updated to be associated with different values. Each batch of updates to these key-value
//! mappings are associated with an epoch along with a commitment to the database of entries at that point in time.
//! The server that controls the database can use this library to generate proofs of inclusion to clients that wish
//! to query entries in the database. These proofs can be _verified_ by a client against the corresponding
//! commitment to the database. We can think of this data structure intuitively as a _verifiable dictionary_.
//!
//! ### Operations
//!
//! This library supports the following operations for the directory it maintains:
//! - [Publishing](#publishing): Allows the directory server to insert and update new entries into the directory.
//! - [Lookup Proofs](#lookup-proofs): Handles point queries to the directory, providing proofs of validity based on the server's
//! public key and a root hash for an epoch.
//! - [History Proofs](#history-proofs): For a given index in the directory, provides proofs for the history of updates to this
//! entry, matched against the server's public key and a root hash for an epoch.
//! - [Append-Only Proofs](#append-only-proofs): For a pair of epochs, provides a proof to an auditor that the database has evolved
//! consistently and in an append-only manner. These append-only proofs use a verifiable random function (VRF)
//! to avoid leaking any information about the labels and their corresponding values.
//!
//!
//! ### Asynchronicity
//!
//! Note that all of the library functions must be called asynchronously (within
//! `async { ... }` blocks) and the responses must be `await`ed. In the following examples,
//! the necessary `async` blocks are omitted for simplicity.
//!
//! ## Setup
//! A [`Directory`] represents an AKD. To set up a [`Directory`], we first need to pick on
//! a database, a hash function, and a VRF. For this example, we use [`Blake3`] as the hash function,
//! [`storage::memory::AsyncInMemoryDatabase`] as in-memory storage, and [`ecvrf::HardCodedAkdVRF`] as the VRF.
//! The [`Directory::new`] function also takes as input a third parameter indicating whether or not it is "read-only".
//! Note that a read-only directory cannot be updated, and so we most likely will want to keep this variable set
//! as `false`.
//! ```
//! use akd::Blake3;
//! use akd::storage::StorageManager;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//! use akd::directory::Directory;
//!
//! let db = AsyncInMemoryDatabase::new();
//! let storage_manager = StorageManager::new_no_cache(&db);
//! let vrf = HardCodedAkdVRF{};
//!
//! # tokio_test::block_on(async {
//! let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false)
//!     .await
//!     .expect("Could not create a new directory");
//! # });
//! ```
//!
//! ## Publishing
//! To add label-value pairs (of type [`AkdLabel`] and [`AkdValue`]) to the directory, we can call [`Directory::publish`]
//! with a list of the pairs. In the following example, we derive the labels and values from strings. After publishing,
//! the new epoch number and root hash are returned.
//! ```
//! # use akd::Blake3;
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! # let vrf = HardCodedAkdVRF{};
//! use akd::EpochHash;
//! use akd::storage::types::{AkdLabel, AkdValue};
//! use akd::winter_crypto::Digest;
//!
//! let entries = vec![
//!     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("first value")),
//!     (AkdLabel::from_utf8_str("second entry"), AkdValue::from_utf8_str("second value")),
//! ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//!
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false).await.unwrap();
//! let EpochHash(epoch, root_hash) = akd.publish(entries)
//!     .await.expect("Error with publishing");
//! println!("Published epoch {} with root hash: {}", epoch, hex::encode(root_hash.as_bytes()));
//! # });
//! ```
//! This function can be called repeatedly to add entries to the directory, with each invocation
//! producing a new epoch and root hash for the directory.
//!
//! ## Lookup Proofs
//! We can call [`Directory::lookup`] to generate a [`LookupProof`] that proves the correctness
//! of a client lookup for an existing entry.
//! ```
//! # use akd::Blake3;
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::storage::types::{AkdLabel, AkdValue};
//! # use akd::winter_crypto::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("first value")),
//! #     (AkdLabel::from_utf8_str("second entry"), AkdValue::from_utf8_str("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! let lookup_proof = akd.lookup(
//!     AkdLabel::from_utf8_str("first entry")
//! ).await.expect("Could not generate proof");
//! # });
//! ```
//!
//! To verify a valid proof, we call [`client::lookup_verify`], with respect to the root hash and
//! the server's public key.
//! ```
//! # use akd::Blake3;
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::storage::types::{AkdLabel, AkdValue};
//! # use akd::winter_crypto::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("first value")),
//! #     (AkdLabel::from_utf8_str("second entry"), AkdValue::from_utf8_str("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! #     let lookup_proof = akd.lookup(
//! #         AkdLabel::from_utf8_str("first entry")
//! #     ).await.expect("Could not generate proof");
//! let public_key = akd.get_public_key().await.expect("Could not fetch public key");
//!
//! assert_eq!(lookup_proof.plaintext_value, AkdValue::from_utf8_str("first value"));
//! let lookup_result = akd::client::lookup_verify(
//!     &public_key,
//!     root_hash,
//!     AkdLabel::from_utf8_str("first entry"),
//!     lookup_proof,
//! );
//! assert!(lookup_result.is_ok());
//! # });
//! ```
//!
//! ## History Proofs
//! As mentioned above, the security is defined by consistent views of the value for a key at any epoch.
//! To this end, a server running an AKD needs to provide a way to check the history of a key. Note that in this case,
//! the server is trusted for validating that a particular client is authorized to run a history check on a particular key.
//! We can use [`Directory::key_history`] to prove the history of a key's values at a given epoch, as follows.
//! ```
//! # use akd::Blake3;
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::storage::types::{AkdLabel, AkdValue};
//! # use akd::winter_crypto::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("first value")),
//! #     (AkdLabel::from_utf8_str("second entry"), AkdValue::from_utf8_str("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! let history_proof = akd.key_history(
//!     &AkdLabel::from_utf8_str("first entry"),
//! ).await.expect("Could not generate proof");
//! # });
//! ```
//! To verify the above proof, we call [`client::key_history_verify`],
//! with respect to the latest root hash and public key, as follows:
//! ```
//! # use akd::Blake3;
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::storage::types::{AkdLabel, AkdValue};
//! # use akd::winter_crypto::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("first value")),
//! #     (AkdLabel::from_utf8_str("second entry"), AkdValue::from_utf8_str("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! #     let history_proof = akd.key_history(
//! #         &AkdLabel::from_utf8_str("first entry"),
//! #     ).await.expect("Could not generate proof");
//! let public_key = akd.get_public_key().await.expect("Could not fetch public key");
//! let key_history_result = akd::client::key_history_verify(
//!     &public_key,
//!     root_hash,
//!     epoch,
//!     AkdLabel::from_utf8_str("first entry"),
//!     history_proof.clone(),
//!     false,
//! );
//! assert!(key_history_result.is_ok());
//!
//! for entry in history_proof.update_proofs {
//!     println!("({}, {}, {:?})", entry.epoch, entry.version, entry.plaintext_value);
//! }
//! # });
//! ```
//!
//! ## Append-Only Proofs
//! In addition to the client API calls, the AKD also provides proofs to auditors that its commitments evolved correctly.
//! Below we illustrate how the server responds to an audit query between two epochs.
//! ```
//! # use akd::Blake3;
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::storage::types::{AkdLabel, AkdValue};
//! # use akd::winter_crypto::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("first value")),
//! #     (AkdLabel::from_utf8_str("second entry"), AkdValue::from_utf8_str("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! // Publish new entries into a second epoch
//! let entries = vec![
//!     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("new first value")),
//!     (AkdLabel::from_utf8_str("third entry"), AkdValue::from_utf8_str("third value")),
//! ];
//! let EpochHash(epoch2, root_hash2) = akd.publish(entries)
//!     .await.expect("Error with publishing");
//!
//! // Generate audit proof for the evolution from epoch 1 to epoch 2.
//! let audit_proof = akd.audit(epoch, epoch2)
//!     .await.expect("Error with generating proof");
//! # });
//! ```
//! The auditor then verifies the above [`AppendOnlyProof`] using [`auditor::audit_verify`].
//! ```
//! # use akd::Blake3;
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db); 
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::storage::types::{AkdLabel, AkdValue};
//! # use akd::winter_crypto::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("first value")),
//! #     (AkdLabel::from_utf8_str("second entry"), AkdValue::from_utf8_str("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(&db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<_, _, Blake3>::new(&storage_manager, &vrf, false).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! #     // Publish new entries into a second epoch
//! #     let new_entries = vec![
//! #         (AkdLabel::from_utf8_str("first entry"), AkdValue::from_utf8_str("new first value")),
//! #         (AkdLabel::from_utf8_str("third entry"), AkdValue::from_utf8_str("third value")),
//! #     ];
//! #     let EpochHash(epoch2, root_hash2) = akd.publish(new_entries)
//! #         .await.expect("Error with publishing");
//! #
//! #     // Generate audit proof for the evolution from epoch 1 to epoch 2.
//! #     let audit_proof = akd.audit(epoch, epoch2)
//! #         .await.expect("Error with generating proof");
//! let audit_result = akd::auditor::audit_verify(
//!     vec![root_hash, root_hash2],
//!     audit_proof,
//! ).await;
//! assert!(audit_result.is_ok());
//! # });
//! ```
//!
//! # Compilation Features
//!
//! The `akd` crate supports multiple compilation features:
//!
//! 1. `serde`: Will enable [`serde`] serialization support on all public structs used in storage & transmission operations. This is helpful
//! in the event you wish to directly serialize the structures to transmit between library <-> storage layer or library <-> clients. If you're
//! also utilizing VRFs (see (2.) below) it will additionally enable the _serde_ feature in the ed25519-dalek crate.
//!
//! 2. `public-tests`: Will expose some internal sanity testing functionality, which is often helpful so you don't have to write all your own
//! unit test cases when implementing a storage layer yourself. This helps guarantee the sanity of a given storage implementation. Should be
//! used only in unit testing scenarios by altering your Cargo.toml as such:
//! ```toml
//! [dependencies]
//! akd = { version = "0.7" }
//!
//! [dev-dependencies]
//! akd = { version = "0.7", features = ["public-tests"] }
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
pub mod helper_structs;
pub mod node_label;
pub mod proof_structs;
pub mod serialization;
pub mod storage;
pub mod tree_node;

#[cfg(feature = "protobuf")]
pub mod proto;

mod utils;

// ========== Type re-exports which are commonly used ========== //
pub use append_only_zks::Azks;
pub use directory::Directory;
pub use helper_structs::{EpochHash, Node};
pub use node_label::NodeLabel;
pub use proof_structs::{AppendOnlyProof, HistoryProof, LookupProof};
pub use storage::types::{AkdLabel, AkdValue};
pub use winter_crypto;
/// The [Blake3](https://github.com/BLAKE3-team/BLAKE3) hash function
pub type Blake3 = winter_crypto::hashers::Blake3_256<winter_math::fields::f128::BaseElement>;
/// The [Sha3](https://en.wikipedia.org/wiki/SHA-3) hash function
pub type Sha3 = winter_crypto::hashers::Sha3_256<winter_math::fields::f128::BaseElement>;

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
pub const EMPTY_LABEL: crate::node_label::NodeLabel = crate::node_label::NodeLabel {
    label_val: [1u8; 32],
    label_len: 0,
};

/// The label used for a root node
pub const ROOT_LABEL: crate::node_label::NodeLabel = crate::node_label::NodeLabel {
    label_val: [0u8; 32],
    label_len: 0,
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
