// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! An implementation of an auditable key directory (AKD), also known as a verifiable registry or authenticated dictionary.
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
//! to query for keys in the database to retrieve their associated values. These proofs can be _verified_ by a client
//! against the corresponding commitment to the database. We can think of this data structure intuitively as a
//! _verifiable dictionary_.
//!
//! This library can be used as part of a key transparency system to generate commitments and serve proofs for a database
//! of public keys. However, note that a full key transparency solution still needs to provide a way for clients to ensure
//! that they are receiving the same commitment for each database epoch. This is outside of the scope of this library and
//! must be handled separately.
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
//! a database, a tree configuration, and a VRF. For this example, we use `WhatsAppV1Configuration`
//! as the configuration,
//! [`storage::memory::AsyncInMemoryDatabase`] as in-memory storage, and [`ecvrf::HardCodedAkdVRF`] as the VRF.
//! The [`directory::ReadOnlyDirectory`] creates a read-only directory which cannot be updated.
//! ```
//! use akd::storage::StorageManager;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! use akd::ecvrf::HardCodedAkdVRF;
//! use akd::directory::Directory;
//!
//! type Config = akd::WhatsAppV1Configuration;
//!
//! let db = AsyncInMemoryDatabase::new();
//! let storage_manager = StorageManager::new_no_cache(db);
//! let vrf = HardCodedAkdVRF{};
//!
//! # tokio_test::block_on(async {
//! let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf)
//!     .await
//!     .expect("Could not create a new directory");
//! # });
//! ```
//!
//! For more information on setting configurations, see the [Configurations](#configurations) section.
//!
//! ## Publishing
//! To add label-value pairs (of type [`AkdLabel`] and [`AkdValue`]) to the directory, we can call [`Directory::publish`]
//! with a list of the pairs. In the following example, we derive the labels and values from strings. After publishing,
//! the new epoch number and root hash are returned.
//! ```
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # type Config = akd::WhatsAppV1Configuration;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! # let vrf = HardCodedAkdVRF{};
//! use akd::EpochHash;
//! use akd::{AkdLabel, AkdValue};
//! use akd::Digest;
//!
//! let entries = vec![
//!     (AkdLabel::from("first entry"), AkdValue::from("first value")),
//!     (AkdLabel::from("second entry"), AkdValue::from("second value")),
//! ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//!
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf).await.unwrap();
//! let EpochHash(epoch, root_hash) = akd.publish(entries)
//!     .await.expect("Error with publishing");
//! println!("Published epoch {} with root hash: {}", epoch, hex::encode(root_hash));
//! # });
//! ```
//! This function can be called repeatedly to add entries to the directory, with each invocation
//! producing a new epoch and root hash for the directory.
//!
//! ## Lookup Proofs
//! We can call [`Directory::lookup`] to generate a [`LookupProof`] that proves the correctness
//! of a client lookup for an existing entry.
//! ```
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # type Config = akd::WhatsAppV1Configuration;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::{AkdLabel, AkdValue};
//! # use akd::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from("first entry"), AkdValue::from("first value")),
//! #     (AkdLabel::from("second entry"), AkdValue::from("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! let (lookup_proof, epoch_hash) = akd.lookup(
//!     AkdLabel::from("first entry")
//! ).await.expect("Could not generate proof");
//! # });
//! ```
//!
//! To verify a valid proof, we call [`client::lookup_verify`], with respect to the root hash and
//! the server's public key.
//! ```
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # type Config = akd::WhatsAppV1Configuration;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::{AkdLabel, AkdValue};
//! # use akd::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from("first entry"), AkdValue::from("first value")),
//! #     (AkdLabel::from("second entry"), AkdValue::from("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf).await.unwrap();
//! #     let _ = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! #     let (lookup_proof, epoch_hash) = akd.lookup(
//! #         AkdLabel::from("first entry")
//! #     ).await.expect("Could not generate proof");
//! let public_key = akd.get_public_key().await.expect("Could not fetch public key");
//!
//! let lookup_result = akd::client::lookup_verify::<Config>(
//!     public_key.as_bytes(),
//!     epoch_hash.hash(),
//!     epoch_hash.epoch(),
//!     AkdLabel::from("first entry"),
//!     lookup_proof,
//! ).expect("Could not verify lookup proof");
//!
//! assert_eq!(
//!     lookup_result,
//!     akd::VerifyResult {
//!         epoch: 1,
//!         version: 1,
//!         value: AkdValue::from("first value"),
//!     },
//! );
//! # });
//! ```
//!
//! ## History Proofs
//! As mentioned above, security is defined by consistent views of the value for a key at any epoch.
//! To this end, a server running an AKD needs to provide a way to check the history of a key. Note that in this case,
//! the server is trusted for validating that a particular client is authorized to run a history check on a particular key.
//! We can use [`Directory::key_history`] to prove the history of a key's values at a given epoch.
//!
//! The [HistoryParams] field can be used to limit the history that we issue proofs for, but in this
//! example we default to a complete history. For more information on the parameters, see the
//! [History Parameters](#history-parameters) section.
//! ```
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # type Config = akd::WhatsAppV1Configuration;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::{AkdLabel, AkdValue};
//! # use akd::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from("first entry"), AkdValue::from("first value")),
//! #     (AkdLabel::from("second entry"), AkdValue::from("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! use akd::HistoryParams;
//!
//! let EpochHash(epoch2, root_hash2) = akd.publish(
//!     vec![(AkdLabel::from("first entry"), AkdValue::from("updated value"))],
//! ).await.expect("Error with publishing");
//! let (history_proof, _) = akd.key_history(
//!     &AkdLabel::from("first entry"),
//!     HistoryParams::default(),
//! ).await.expect("Could not generate proof");
//! # });
//! ```
//! To verify the above proof, we call [`client::key_history_verify`],
//! with respect to the latest root hash and public key, as follows. This function
//! returns a list of values that have been associated with the specified entry, in
//! reverse chronological order.
//! ```
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # type Config = akd::WhatsAppV1Configuration;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::HistoryParams;
//! # use akd::{AkdLabel, AkdValue};
//! # use akd::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from("first entry"), AkdValue::from("first value")),
//! #     (AkdLabel::from("second entry"), AkdValue::from("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf).await.unwrap();
//! #     let _ = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! #     let _ = akd.publish(
//! #         vec![(AkdLabel::from("first entry"), AkdValue::from("updated value"))],
//! #     ).await.expect("Error with publishing");
//! #     let (history_proof, epoch_hash) = akd.key_history(
//! #         &AkdLabel::from("first entry"),
//! #         HistoryParams::default(),
//! #     ).await.expect("Could not generate proof");
//! let public_key = akd.get_public_key().await.expect("Could not fetch public key");
//! let key_history_result = akd::client::key_history_verify::<Config>(
//!     public_key.as_bytes(),
//!     epoch_hash.hash(),
//!     epoch_hash.epoch(),
//!     AkdLabel::from("first entry"),
//!     history_proof,
//!     akd::HistoryVerificationParams::default(),
//! ).expect("Could not verify history");
//!
//! assert_eq!(
//!     key_history_result,
//!     vec![
//!         akd::VerifyResult {
//!             epoch: 2,
//!             version: 2,
//!             value: AkdValue::from("updated value"),
//!         },
//!         akd::VerifyResult {
//!             epoch: 1,
//!             version: 1,
//!             value: AkdValue::from("first value"),
//!         },
//!     ],
//! );
//! # });
//! ```
//!
//! ## Append-Only Proofs
//! In addition to the client API calls, the AKD also provides proofs to auditors that its commitments evolved correctly.
//! Below we illustrate how the server responds to an audit query between two epochs.
//! ```
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # type Config = akd::WhatsAppV1Configuration;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::{AkdLabel, AkdValue};
//! # use akd::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from("first entry"), AkdValue::from("first value")),
//! #     (AkdLabel::from("second entry"), AkdValue::from("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! // Publish new entries into a second epoch
//! let entries = vec![
//!     (AkdLabel::from("first entry"), AkdValue::from("new first value")),
//!     (AkdLabel::from("third entry"), AkdValue::from("third value")),
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
//! # use akd::storage::StorageManager;
//! # use akd::storage::memory::AsyncInMemoryDatabase;
//! # use akd::ecvrf::HardCodedAkdVRF;
//! # use akd::directory::Directory;
//! #
//! # type Config = akd::WhatsAppV1Configuration;
//! #
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! # let vrf = HardCodedAkdVRF{};
//! # use akd::EpochHash;
//! # use akd::{AkdLabel, AkdValue};
//! # use akd::Digest;
//! #
//! # let entries = vec![
//! #     (AkdLabel::from("first entry"), AkdValue::from("first value")),
//! #     (AkdLabel::from("second entry"), AkdValue::from("second value")),
//! # ];
//! # let db = AsyncInMemoryDatabase::new();
//! # let storage_manager = StorageManager::new_no_cache(db);
//! #
//! # tokio_test::block_on(async {
//! #     let vrf = HardCodedAkdVRF{};
//! #     let mut akd = Directory::<Config, _, _>::new(storage_manager, vrf).await.unwrap();
//! #     let EpochHash(epoch, root_hash) = akd.publish(entries)
//! #         .await.expect("Error with publishing");
//! #     // Publish new entries into a second epoch
//! #     let new_entries = vec![
//! #         (AkdLabel::from("first entry"), AkdValue::from("new first value")),
//! #         (AkdLabel::from("third entry"), AkdValue::from("third value")),
//! #     ];
//! #     let EpochHash(epoch2, root_hash2) = akd.publish(new_entries)
//! #         .await.expect("Error with publishing");
//! #
//! #     // Generate audit proof for the evolution from epoch 1 to epoch 2.
//! #     let audit_proof = akd.audit(epoch, epoch2)
//! #         .await.expect("Error with generating proof");
//! let audit_result = akd::auditor::audit_verify::<Config>(
//!     vec![root_hash, root_hash2],
//!     audit_proof,
//! ).await;
//! assert!(audit_result.is_ok());
//! # });
//! ```
//!
//! # Advanced Usage
//!
//! ## Configurations
//!
//! This library supports the notion of a [Configuration], which can be used to customize the directory's cryptographic operations. We provide
//! two default configurations: `WhatsAppV1Configuration` and `ExperimentalConfiguration`.
//!
//! - `WhatsAppV1Configuration` matches the configuration used for Whatsapp's key transparency deployment
//! - `ExperimentalConfiguration` is the configuration which matches the main branch deployment for AKD
//!
//! An `ExperimentalConfiguration` implements domain separation for its hashing operations by the specifying of a struct that
//! implements [DomainLabel]. For example, to set the domain label as `"ExampleLabel"`, we define the struct [ExampleLabel] as:
//! ```
//! #[derive(Clone)]
//! struct ExampleLabel;
//!
//! impl akd::DomainLabel for ExampleLabel {
//!     fn domain_label() -> &'static [u8] {
//!         "ExampleLabel".as_bytes()
//!     }
//! }
//! ```
//! An application can set their own specific domain label to a custom string achieve domain separation from other applications.
//!
//! ## History Parameters
//!
//! The [HistoryParams] enum can be used to limit the number of updates for a given entry that the server provides
//! to the client. The enum has the following options:
//! - [HistoryParams::Complete]: Includes a complete history of all updates to an entry. This is the default option.
//! - [HistoryParams::MostRecentInsecure]: Includes (at most) the most recent input number of updates for an entry.
//! - [HistoryParams::SinceEpochInsecure]: Includes all updates to an entry since a given epoch.
//!
//! Note that the "insecure" options are not recommended for use in production, as they do not provide a
//! complete history of updates, and lack inclusion proofs for earlier entries. These options should only be
//! used for testing purposes.
//!
//!
//! ## Compilation Features
//!
//! This crate supports multiple compilation features:
//!
//! Configurations:
//! - `whatsapp_v1`: Enables usage of `WhatsAppV1Configuration`
//! - `experimental`: Enables usage of `ExperimentalConfiguration`
//!
//! Performance optimizations:
//! - `parallel_vrf`: Enables the VRF computations to be run in parallel
//! - `parallel_insert`: Enables nodes to be inserted via multiple threads during a publish operation
//! - `preload_history`: Enable pre-loading of the nodes when generating history proofs
//! - `greedy_lookup_preload`: Greedy loading of lookup proof nodes
//!
//! Benchmarking:
//! - `bench`: Feature used when running benchmarks
//! - `slow_internal_db`: Artifically slow the in-memory database (for benchmarking)
//!
//! Utilities:
//! - `public_auditing`: Enables the publishing of audit proofs
//! - `serde_serialization`: Will enable `serde` serialization support on all public structs used in storage & transmission operations. This is helpful
//! in the event you wish to directly serialize the structures to transmit between library <-> storage layer or library <-> clients. If you're
//! also utilizing VRFs (see (2.) below) it will additionally enable the _serde_ feature in the ed25519-dalek crate.
//! - `runtime_metrics`: Collects metrics on the accesses to the storage layer
//! - `public_tests`: Will expose some internal sanity testing functionality, which is often helpful so you don't have to write all your own
//! unit test cases when implementing a storage layer yourself. This helps guarantee the sanity of a given storage implementation. Should be
//! used only in unit testing scenarios by altering your Cargo.toml as such:
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
pub mod errors;
pub mod helper_structs;
pub mod storage;
pub mod tree_node;

#[cfg(feature = "public_auditing")]
pub mod local_auditing;

pub use akd_core::{
    configuration, configuration::*, ecvrf, hash, hash::Digest, proto, types::*, verify, ARITY,
};

#[macro_use]
mod utils;

// ========== Type re-exports which are commonly used ========== //
pub use append_only_zks::Azks;
pub use client::HistoryVerificationParams;
pub use directory::{Directory, HistoryParams};
pub use helper_structs::EpochHash;

// ========== Constants and type aliases ========== //
#[cfg(any(test, feature = "public_tests"))]
pub mod test_utils;
#[cfg(test)]
mod tests;

/// The length of a leaf node's label (in bits)
pub const LEAF_LEN: u32 = 256;

/// The label used for a root node
pub const ROOT_LABEL: crate::node_label::NodeLabel = crate::NodeLabel {
    label_val: [0u8; 32],
    label_len: 0,
};
