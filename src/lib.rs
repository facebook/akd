// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of an authenticated key directory (AKD), also known as a verifiable registery or verifiable key directory.
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
//! locally, where the code is running, and instead, uses a [storage::Storage] as a generic type.
//!
//! ## Setup
//! A [directory::Directory] represents an AKD. To setup a [directory::Directory], we first need to decide on
//! a database and a hash function. For this example, we use the [winter_crypto::hashers::Blake3_256] as the hash function and
//! AsyncInMemoryDatabase as storage.
//! ```
//! use winter_crypto::Hasher;
//! use winter_crypto::hashers::Blake3_256;
//! use winter_math::fields::f128::BaseElement;
//! use crate::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
//! use crate::storage::V2Storage;
//! storage::memory::AsyncInMemoryDatabase;
//! type Blake3 = Blake3_256<BaseElement>;
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! let db = crate::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
//! let mut akd = akd::Directory::<
//!    crate::storage::V2FromV1StorageWrapper<AsyncInMemoryDatabase>,
//!    Blake3_256<BaseElement>,
//!    >::new(&db).unwrap();
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
//! type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;
//! let db = akd::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
//! async {
//!     let mut akd = akd::Directory::<
//!         akd::storage::V2FromV1StorageWrapper<AsyncInMemoryDatabase>,
//!         Blake3_256<BaseElement>,
//!         >::new(&db).unwrap();
//!     // commit the latest changes
//!     akd.publish(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!          (AkdKey("hello2".to_string()), Values("world2".to_string())),])
//!       .await;
//! };
//! ```
//!
//!
//! ## Responding to a client lookup
//! We can use the lookup API call of the [crate::directory::Directory] to prove the correctness of a client lookup at a given epoch.
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
//! let db = akd::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
//! async {
//!     let mut akd = Directory::<
//!         akd::storage::V2FromV1StorageWrapper<AsyncInMemoryDatabase>,
//!         Blake3_256<BaseElement>,
//!         >::new(&db).await;
//!     akd.publish(vec![(AkdKey("hello".to_string()), Values("world".to_string())),
//!         (AkdKey("hello2".to_string()), Values("world2".to_string())),])
//!          .await.unwrap();
//!     // Generate latest proof
//!     let lookup_proof = akd.lookup(AkdKey("hello".to_string())).await;
//! };
//! ```
//!  and to verify this proof, we call the client's verification algorithm, with respect to the latest commitment, as follows:
//! ```
//! async {
//!     let current_azks = akd.retrieve_current_azks().unwrap();
//!     // Get the latest commitment, i.e. azks root hash
//!     let root_hash = akd.get_root_hash(&current_azks).unwrap();
//!     lookup_verify::<Blake3_256<BaseElement>>(
//!     root_hash,
//!     AkdKey("hello".to_string()),
//!     lookup_proof,
//!     ).unwrap();
//! };
//! ```
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

pub mod auditor;
pub mod client;
pub mod errors;

#[cfg(test)]
pub mod tests;

/// The arity of the underlying tree structure of the vkd.
pub const ARITY: usize = 2;

/// This type is used to indicate a direction for a
/// particular node relative to its parent.
pub type Direction = Option<usize>;
