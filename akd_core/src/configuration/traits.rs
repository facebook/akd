// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Defines the configuration trait for customizing the directory's cryptographic operations

use crate::hash::Digest;
use crate::{AkdLabel, AkdValue, AzksValue, AzksValueWithEpoch, NodeLabel, VersionFreshness};

#[cfg(feature = "nostd")]
use alloc::vec::Vec;

/// Trait for specifying a domain separation label that should be specific to the
/// application
pub trait DomainLabel: Clone + 'static {
    /// Returns a label, which is used as a domain separator when computing hashes
    fn domain_label() -> &'static [u8];
}

/// An example domain separation label (this should not be used in a production setting!)
#[derive(Clone)]
pub struct ExampleLabel;

impl DomainLabel for ExampleLabel {
    fn domain_label() -> &'static [u8] {
        "ExampleLabel".as_bytes()
    }
}

/// Trait for customizing the directory's cryptographic operations
pub trait Configuration: Clone + Send + Sync + 'static {
    /// Hash a single byte array
    fn hash(item: &[u8]) -> crate::hash::Digest;

    /// The value stored in the root node upon initialization, with no children
    fn empty_root_value() -> AzksValue;

    /// AZKS value corresponding to an empty node
    fn empty_node_hash() -> AzksValue;

    /// Hash a leaf epoch and nonce with a given [AkdValue]
    fn hash_leaf_with_value(
        value: &crate::AkdValue,
        epoch: u64,
        nonce: &[u8],
    ) -> AzksValueWithEpoch;

    /// Hash a commit and epoch together to get the leaf's hash value
    fn hash_leaf_with_commitment(commitment: AzksValue, epoch: u64) -> AzksValueWithEpoch;

    /// Used by the server to produce a commitment nonce for an AkdLabel, version, and AkdValue.
    fn get_commitment_nonce(
        commitment_key: &[u8],
        label: &NodeLabel,
        version: u64,
        value: &AkdValue,
    ) -> Digest;

    /// Used by the server to produce a commitment for an AkdLabel, version, and AkdValue
    fn compute_fresh_azks_value(
        commitment_key: &[u8],
        label: &NodeLabel,
        version: u64,
        value: &AkdValue,
    ) -> AzksValue;

    /// To convert a regular label (arbitrary string of bytes) into a [NodeLabel], we compute the
    /// output as: H(label || freshness || version)
    ///
    /// Specifically, we concatenate the following together:
    /// - I2OSP(len(label) as u64, label)
    /// - A single byte encoded as 0u8 if "stale", 1u8 if "fresh"
    /// - A u64 representing the version
    ///
    /// These are all interpreted as a single byte array and hashed together, with the output
    /// of the hash returned.
    fn get_hash_from_label_input(
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Vec<u8>;

    /// Computes the parent hash from the children hashes and labels
    fn compute_parent_hash_from_children(
        left_val: &AzksValue,
        left_label: &[u8],
        right_val: &AzksValue,
        right_label: &[u8],
    ) -> AzksValue;

    /// Given the top-level hash, compute the "actual" root hash that is published
    /// by the directory maintainer
    fn compute_root_hash_from_val(root_val: &AzksValue) -> Digest;

    /// Similar to commit_fresh_value, but used for stale values.
    fn stale_azks_value() -> AzksValue;

    /// Computes the node label value from the bytes of the label
    fn compute_node_label_value(bytes: &[u8]) -> Vec<u8>;

    /// Returns the representation of the empty label
    fn empty_label() -> NodeLabel;
}

/// For fixture generation / testing purposes only
#[cfg(feature = "public_tests")]
pub trait NamedConfiguration: Configuration {
    /// The name of the configuration
    fn name() -> &'static str;
}
