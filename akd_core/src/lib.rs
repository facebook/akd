// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Core utilities for the auditable key directory `akd` crate.
//! Mainly contains (1) hashing utilities for the core cryptographic operations
//! involved in building an AKD and issuing proofs, (2) type definitions, and (3)
//! protobuf specifications for all external types
//!
//! The default configuration is to utilize the standard library (`std`) along with
//! blake3 hashing (from the [blake3] crate). If you wish to customize which hash and
//! which features are utilized, you can pass `--no-default-features` on the command line
//! or `default-features = false` in your Cargo.toml import to disable all of the default features
//! which you can then enable one-by-one as you wish.
//!
//! In the following, we will cover the protocol-level implementation details behind:
//! - The setup parameters for an AKD
//! - How the tree (and its root hash) is constructed from a set of `([AkdLabel], [AkdValue])` pairs
//! - How lookup, history, and audit proofs work
//!
//! # Setup parameters
//!
//! An AKD is configured by a set of parameters which are set by the server when it is initialized. The server
//! picks a random VRF private key `vsk` and derives (and distributes) a public key `vpk` to its clients. The server also
//! produces a commitment key (`commitment_key`) by hashing the VRF private key. The VRF private key will be used to provide
//! selective privacy of the database's inserted labels to auditors and other clients, while the commitment key
//! will be used to provide privacy over the database's inserted values. Hence, both `vsk` and `commitment_key` must be kept
//! private to the server and not leaked to any clients.
//!
//! # Inserting into the Merkle Tree
//!
//! The [Merkle Patricia Tree](https://eprint.iacr.org/2016/683.pdf) is a perfect binary tree consisting
//! of nodes that are associated with a [NodeLabel] and a 32-byte value (its hash). There are three types
//! of nodes in the tree: the root node, the interior nodes, and the leaf nodes.
//! The leaf nodes of the tree are positioned based on their [NodeLabel], with a hash derived from the
//! leaf node's value and the epoch it was inserted into the tree. The interior nodes of the tree each consist
//! of two child nodes, with their [NodeLabel] being the longest common prefix of their two children's [NodeLabel]s.
//! The hash of an interior node is derived as the concatenation of the hashes of its two children along with their
//! labels. The root node always has a label of 0, and its hash is the hash of its two children's labels.
//!
//! There are multiple steps for inserting a single ([AkdLabel], [AkdValue]) pair into the tree:
//!
//! ## Step 1: Deriving an [AzksElement]
//!
//! The server computes a VRF on [AkdLabel] to derive a [NodeLabel] which determines the leaf's position in the tree.
//! This is computed by the
//! `[akd::utils::get_hash_from_label_input]` function, which sets the node label to be the output of a VRF, with
//! the input to the VRF computed as:
//! `vrf_input = Hash(label, staleness, version)`
//!
//! Specifically, we concatenate the following together:
//! - `I2OSP(len(label) as u64)`
//! - The label in bytes
//! - A single byte encoded as `0u8` if "stale", `1u8` if "fresh"
//! - A `u64` representing the version (starting at 1 for newly inserted labels, and incremented by 1 for each update)
//!
//! The resulting values are hashed together and used as the byte string (truncated to 256 bits) that is stored
//! as the [NodeLabel].
//!
//! The server then computes a VRF on the [NodeLabel] to derive a value for the leaf node. This is computed as:
//! `node_label = VRF(vsk, vrf_input)`.
//!
//! Once the node label for this entry is derived (as `node_label`), the functions `compute_fresh_azks_value()`
//! and `stale_azks_value()`
//! are used to commit the [AkdValue] to the tree. The actual value
//! that is stored in the node is an [AzksValue], generated using the server's commitment key as follows:
//! - `commitment_nonce = Hash(commitment_key, node_label, version, I2OSP(len(value) as u64), value)`
//! - `commmitment = Hash(I2OSP(len(value) as u64), value, I2OSP(len(commitment_nonce) as u64), commitment_nonce)`
//!
//! Finally, the commitment is hashed together with the epoch that it ends up being inserted into the tree,
//! computed as: `azks_value = Hash(commitment, epoch)`
//!
//! For each entry, the server constructs an [AzksElement] out of `node_label` and `azks_value` in the above-described manner with staleness set to [VersionFreshness::Fresh] and
//! `version` to `1`. If this is the `n`th time the label is being inserted into the tree where `n > 1`, then the server constructs two
//! [AzksElement]s,
//! one with `version` set to `n-1` and freshness set to [VersionFreshness::Stale] with `node_value = Hash(0u8)`, and the other
//! with `version` set to `n` and freshness set to [VersionFreshness::Fresh], and `node_value` derived as above.
//!
//! ## Step 2: Inserting an [AzksElement] into the Merkle tree
//!
//! In order to insert a single node label and value pair into the tree, the server constructs a leaf node `new_node` with this
//! [NodeLabel] and commitment value, and identifies the leaf node `lcp_node` with the longest common prefix with this node in the tree.
//! It creates an interior node with this prefix as its label, and makes `new_node` and `lcp_node` siblings based on the ordering of
//! their [NodeLabel]s. The hash for this interior node is computed as the concatenation of the hashes of its two children along with
//! their labels, explicitly as:
//! `interior_node.label = longest_common_prefix(lcp_node.label, new_node.label)`
//! `interior_node.hash = Hash(Hash(lcp_node.hash, lcp_node.label), Hash(new_node.hash, new_node.label))`.
//! The server then traverses up the tree, updating the hashes of all the interior nodes it encounters, until it reaches the root.
//!
//! In the case of the root node, which may have only one child (or zero children in the event of an empty database), for the
//! purposes of deriving the root node's hash, the missing child's hash is set to `Hash(`[EMPTY_VALUE]`)`, and the label is set to [Configuration::empty_label()].
//! The final root hash output by the tree is then computed as: `Hash(root_node.hash, `[NodeLabel::root()]`)`.
//!
//! Conceptually, to insert multiple entries into the tree, the above process is repeated iteratively for each entry. In the implementation
//! of the tree, however, the entries are inserted in batches, and the tree is updated in a single pass.
//!
//! # Generating and verifying proofs
//!
//! AKD supports three types of proofs: lookup proofs, history proofs, and audit proofs. A lookup proof is used to prove that
//! a given label and value are present in the database. A history proof returns all the history of all values corresponding to
//! a given label, and an audit proof is used to prove to an auditor that the database is being maintained in a consistent
//! and append-only manner. The first two types of proofs rely on the ability to provide membership and non-membership proofs
//! for the tree.
//!
//! ### Membership and non-membership proofs
//!
//! A Merkle Patricia Tree supports membership and non-membership proofs for its leaf nodes. For a given [NodeLabel] and value,
//! the server can produce a membership proof by traversing the tree from the root node to the leaf node corresponding to the
//! target `node_label`. A [MembershipProof] for a `node_label` and value consists of the following:
//! - The `node_label` of the leaf node
//! - The hashed value of the leaf node (hash of the `node_value` and the epoch that the node was inserted in)
//! - The hashes and labels of the sibling nodes along the path to the root
//!
//! A client verifies this proof by iteratively traversing up the tree and computing the hash of the sibling nodes along the
//! path from the leaf node to the root node. If the computed root hash matches
//! the client's expected root hash, the proof is considered valid.
//!
//! A [NonMembershipProof] for a `node_label` consists of the following:
//! - The node in the tree with the longest common prefix with the target label
//! - A membership proof for this node
//! - The two children of this node
//!
//! A client verifies this proof by verifying the membership proof for the node with the longest common prefix, verifying that
//! the two children's hashes will hash to the node, and finally that the target label is not equal to either of the children's
//! node labels.
//!
//! ## Lookup proofs
//!
//! A client is able to query for the stored [AkdValue] corresponding to the [AkdLabel] and a target root hash. The server
//! returns a [LookupProof] which can be verified to extract a [VerifyResult], which contains
//! the corresponding [AkdValue], along with the epoch it was inserted in and the version
//! for the label.
//!
//! Let `n` be the current version, and let `m` be the largest power
//! of 2 that is at most `n`. The [LookupProof] consists of:
//! - The `commitment_nonce` corresponding to the value, which the client
//!   can hash together with the value to reconstruct the commitment
//! - A membership and VRF proof for version `n` being marked as fresh
//! - A non-membership and VRF proof for version `n` being marked as stale
//! - A membership and VRF proof for version `m` being marked as fresh
//!
//! The client can then verify that `commitment_nonce` produces the proof's hash value, and that the
//! three subproofs are valid.
//!
//! ## History proofs
//!
//! A client can query for a history of all (or a subset) of the versions associated with a given [AkdLabel].
//! The server returns a [HistoryProof] which can be verified to extract a list of [VerifyResult]s, one for each
//! version.
//!
//! Let `n` be the latest version, `n_next_pow` the next power of 2 after `n`, and `epoch_prev_pow` be the power of 2 that
//! is at most the current epoch. The [HistoryProof] consists of:
//! - A list of [UpdateProof]s, one for each version, which each contain a membership proof for the version `n` being fresh,
//!   and a membership proof for the version `n-1` being stale
//! - A (possibly empty) series of membership proof for past versions
//! - A (possibly empty) series of non-membership proofs for future versions
//!
//! A client verifies this proof by first verifying each of the update proofs, checking that they are in decreasing
//! consecutive order by version. Then, it verifies the remaining membership and non-membership proofs corresponding
//! to the past and future versions.
//!
//! The purpose behind these past and future version checks is essentially to ensure that, for a fixed epoch, two history
//! proofs cannot present conflicting information about the history of updates for any given user's versions. This is perhaps
//! better illustrated by considering what could happen if the history proofs did not contain the past membership and future
//! non-membership proofs. Then, an attacker could present two history proofs for the same epoch, one containing a version `n`
//! and the other containing a version `n+1`, and the client would have no way to determine what the latest version for that
//! user actually is. So, the way this is resolved (originally as described in the SEEMless paper) is to provide a series of
//! non-membership proofs for future versions, and membership proofs for past versions, with the guarantee that for two differing
//! versions n and m (assuming n < m), the corresponding history proofs will be such that the non-membership proofs for n will
//! intersect for at least one version number with the membership proofs for m. This would force the server to have to equivocate
//! on that version number, which would be detectable by the client.
//!
//! There are several ways to algorithmically implement the past and future marker versions to guarantee that an intersection will
//! always occur. One naive way is to simply have the server provide membership proofs for all versions from 1 to n (and 1 to m). This
//! is the approach as described in OPTIKS (<https://eprint.iacr.org/2024/796.pdf>), which has the downside that the proof size is
//! of course linear in the number of versions.
//!
//! In this implementation, we use a more efficient approach, which is inspired by SEEMless's approach to this problem (but is
//! generalized to support "partial" history proofs that do not contain all versions of updates for a user). The basic idea is to
//! include a constant number of membership proofs for past versions, and a relatively small number of non-membership proofs for
//! future versions that technically still grows with the total number of epochs published, but by taking advantage of a carefully
//! selected skiplist structure, the proof size is still logarithmic in the number of versions. This is described in the
//! [utils::get_marker_versions()] function.
//!
//! ## Audit proofs
//!
//! An audit proof allows for an auditor to verify, given two root hashes corresponding to consecutive epochs, that the first
//! root hash corresponds to a tree that contains a subset of the values of the tree for the second root hash. In particular,
//! no values were deleted or history altered betweeen the two epochs. The [AppendOnlyProof] consists of:
//! - The hashes of each value that was added to the tree between the two epochs
//! - The corresponding sibling nodes along the path from each of these added nodes to the root of the tree
//!
//! The client first verifies that the corresponding sibling nodes can be used to reconstruct the first epoch's root hash.
//! Then, the client hashes each of the provided hash values with the epoch, and then verifies that the computed hashes can be used,
//! alongside the sibling nodes, to reconstruct the second epoch's root hash. For audit proofs that span multiple epochs and root hashes,
//! these checks are repeated iteratively.
//!

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "nostd", no_std)]
extern crate alloc;

#[cfg(all(feature = "protobuf", not(feature = "nostd")))]
pub mod proto;

pub mod ecvrf;
pub mod hash;
pub mod utils;
pub mod verify;

pub mod configuration;
pub use configuration::{Configuration, DomainLabel, ExampleLabel};

// Note(new_config): Update this when adding a new configuration

#[cfg(feature = "experimental")]
pub use configuration::experimental::ExperimentalConfiguration;
#[cfg(feature = "whatsapp_v1")]
pub use configuration::whatsapp_v1::WhatsAppV1Configuration;

pub mod types;
pub use types::*;

/// The number of children each non-leaf node has in the tree
pub const ARITY: usize = 2;
