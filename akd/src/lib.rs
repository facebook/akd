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
//! a database and a hash function. For this example, we use the [winter_crypto::hashers::Blake3_256] as the hash function and
//! AsyncInMemoryDatabase as storage.
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! type Blake3 = Blake3_256<BaseElement>;
//! use akd::directory::Directory;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//! let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//! };
//! ```
//!
//! ## Adding key-value pairs to the akd
//! To add key-value pairs to the akd, we assume that the types of keys and the corresponding values are String.
//! After adding key-value pairs to the akd's data structure, it also needs to be committed. To do this, after running the setup, as in the previous step,
//! we use the `publish` function of an akd. The argument of publish is a vector of tuples of type (AkdKey(String), Values(String)). See below for example usage.
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! type Blake3 = Blake3_256<BaseElement>;
//! use akd::directory::Directory;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//!     // commit the latest changes
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!          (AkdKey("hello2".to_string()), Values("world2".to_string())),], false)
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
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//!use akd::storage::memory::AsyncInMemoryDatabase;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!         (AkdKey("hello2".to_string()), Values("world2".to_string())),], false)
//!          .await.unwrap();
//!     // Generate latest proof
//!     let lookup_proof = akd.lookup::<Blake3_256<BaseElement>>(AkdKey("hello".to_string())).await;
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
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//!use akd::storage::memory::AsyncInMemoryDatabase;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!         (AkdKey("hello2".to_string()), Values("world2".to_string())),], false)
//!          .await.unwrap();
//!     // Generate latest proof
//!     let lookup_proof = akd.lookup::<Blake3_256<BaseElement>>(AkdKey("hello".to_string())).await.unwrap();
//!     let current_azks = akd.retrieve_current_azks().await.unwrap();
//!     // Get the latest commitment, i.e. azks root hash
//!     let root_hash = akd.get_root_hash::<Blake3_256<BaseElement>>(&current_azks).await.unwrap();
//!     client::lookup_verify::<Blake3_256<BaseElement>>(
//!     root_hash,
//!     AkdKey("hello".to_string()),
//!     lookup_proof,
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
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!         (AkdKey("hello2".to_string()), Values("world2".to_string())),], false)
//!          .await.unwrap();
//!     // Generate latest proof
//!     let history_proof = akd.key_history::<Blake3_256<BaseElement>>(&AkdKey("hello".to_string())).await;
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
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!         (AkdKey("hello2".to_string()), Values("world2".to_string())),], false)
//!          .await.unwrap();
//!     // Generate latest proof
//!     let history_proof = akd.key_history::<Blake3_256<BaseElement>>(&AkdKey("hello".to_string())).await.unwrap();
//!     let current_azks = akd.retrieve_current_azks().await.unwrap();
//!     // Get the azks root hashes at the required epochs
//!     let (root_hashes, previous_root_hashes) = akd::directory::get_key_history_hashes::<_, Blake3_256<BaseElement>>(&akd, &history_proof).await.unwrap();
//!     key_history_verify::<Blake3_256<BaseElement>>(
//!     root_hashes,
//!     previous_root_hashes,
//!     AkdKey("hello".to_string()),
//!     history_proof,
//!     ).unwrap();
//! };
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
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//!     // Commit to the first epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!         (AkdKey("hello2".to_string()), Values("world2".to_string())),], false)
//!          .await.unwrap();
//!     // Commit to the second epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello3".to_string()), Values("world3".to_string())),
//!         (AkdKey("hello4".to_string()), Values("world4".to_string())),], false)
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
//! use akd::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use akd::storage::V2Storage;
//! use akd::storage::memory::AsyncInMemoryDatabase;
//! let db = AsyncInMemoryDatabase::new();
//! async {
//!     let mut akd = Directory::<_>::new::<Blake3_256<BaseElement>>(&db).await.unwrap();
//!     // Commit to the first epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!         (AkdKey("hello2".to_string()), Values("world2".to_string())),], false)
//!          .await.unwrap();
//!     // Commit to the second epoch
//!     akd.publish::<Blake3_256<BaseElement>>(vec![(AkdKey("hello3".to_string()), Values("world3".to_string())),
//!         (AkdKey("hello4".to_string()), Values("world4".to_string())),], false)
//!          .await.unwrap();
//!     // Generate audit proof for the evolution from epoch 1 to epoch 2.
//!     let audit_proof = akd.audit::<Blake3_256<BaseElement>>(1u64, 2u64).await.unwrap();
//!     let current_azks = akd.retrieve_current_azks().await.unwrap();
//!     // Get the latest commitment, i.e. azks root hash
//!     let start_root_hash = akd.get_root_hash_at_epoch::<Blake3_256<BaseElement>>(&current_azks, 1u64).await.unwrap();
//!     let end_root_hash = akd.get_root_hash_at_epoch::<Blake3_256<BaseElement>>(&current_azks, 2u64).await.unwrap();
//!     auditor::audit_verify::<Blake3_256<BaseElement>>(
//!         start_root_hash,
//!         end_root_hash,
//!         audit_proof,
//!     ).await.unwrap();
//! };
//! ```
//!
//!
//!
//!
//!
#![warn(missing_docs)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate rand;

pub mod append_only_zks;
pub mod directory;
pub mod history_tree_node;
pub mod node_state;
pub mod proof_structs;
mod serialization;
pub mod storage;
mod utils;

pub mod auditor;
pub mod client;
pub mod errors;

#[cfg(test)]
pub mod tests;

/// The arity of the underlying tree structure of the akd.
pub const ARITY: usize = 2;

/// This type is used to indicate a direction for a
/// particular node relative to its parent.
pub type Direction = Option<usize>;
