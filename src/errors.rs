// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Errors for various data structure operations.
use core::fmt;

use crate::node_state::NodeLabel;

/// Symbolizes a AkdError, thrown by the vkd.
#[derive(Debug)]
pub enum AkdError {
    /// Error propogation
    HistoryTreeNodeErr(HistoryTreeNodeError),
    /// Error propogation
    DirectoryErr(DirectoryError),
    /// Error propogation
    AzksErr(AzksError),
    /// Thrown when a direction should have been given but isn't
    NoDirectionError,
    /// Thrown when a place where an epoch is needed wasn't provided one.
    NoEpochGiven,
}

impl From<HistoryTreeNodeError> for AkdError {
    fn from(error: HistoryTreeNodeError) -> Self {
        Self::HistoryTreeNodeErr(error)
    }
}

impl From<StorageError> for AkdError {
    fn from(error: StorageError) -> Self {
        Self::HistoryTreeNodeErr(HistoryTreeNodeError::StorageError(error))
    }
}

impl From<DirectoryError> for AkdError {
    fn from(error: DirectoryError) -> Self {
        Self::DirectoryErr(error)
    }
}

impl From<AzksError> for AkdError {
    fn from(error: AzksError) -> Self {
        Self::AzksErr(error)
    }
}

impl From<StorageError> for HistoryTreeNodeError {
    fn from(error: StorageError) -> Self {
        Self::StorageError(error)
    }
}

/// Errors thown by HistoryTreeNodes
#[derive(Debug)]
pub enum HistoryTreeNodeError {
    /// Tried to set a child and the direction given was none.
    NoDirectionInSettingChild(u64, u64),
    /// Direction is unexpectedly None
    DirectionIsNone,
    /// The node didn't have a child in the given epoch
    NoChildInTreeAtEpoch(u64, usize),
    /// The node had no children at the given epoch
    NoChildrenInTreeAtEpoch(u64),
    /// The hash was being updated for an invalid epoch
    InvalidEpochForUpdatingHash(u64),
    /// Tried to update the parent of the root, which should not be done
    TriedToUpdateParentOfRoot,
    /// The next epoch of this node's parent was invalid
    ParentNextEpochInvalid(u64),
    /// The hash of a parent was attempted to be updated, without setting the calling node as a child.
    HashUpdateOnlyAllowedAfterNodeInsertion,
    /// The children of a leaf are always dummy and should not be hashed
    TriedToHashLeafChildren,
    /// The list of epochs for a given node was empty
    NodeCreatedWithoutEpochs(u64),
    /// The label of a leaf node was shorter than that of an interior node.
    LeafNodeLabelLenLessThanInterior(NodeLabel),
    /// Error compressing the Merkle trie
    CompressionError(NodeLabel),
    /// Tried to access something about the node at an epoch that didn't exist.
    NodeDidNotExistAtEp(NodeLabel, u64),
    /// The state of a node did not exist at a given epoch
    NodeDidNotHaveExistingStateAtEp(NodeLabel, u64),
    /// Error propogation
    StorageError(StorageError),
    /// Error propogation
    SerializationError,
}

impl fmt::Display for HistoryTreeNodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDirectionInSettingChild(node_label, child_label) => {
                write!(
                    f,
                    "no direction provided to set the child {} of this node {}",
                    node_label, child_label
                )
            }
            Self::NoChildrenInTreeAtEpoch(epoch) => {
                write!(f, "no children at epoch {}", epoch)
            }
            Self::NoChildInTreeAtEpoch(epoch, direction) => {
                write!(f, "no node in direction {} at epoch {}", direction, epoch)
            }
            Self::DirectionIsNone => {
                write!(f, "Direction provided is None")
            }
            Self::InvalidEpochForUpdatingHash(epoch) => {
                write!(f, "Invalid epoch for updating hash {}", epoch)
            }
            Self::TriedToUpdateParentOfRoot => {
                write!(f, "Tried to update parent of root")
            }
            Self::ParentNextEpochInvalid(epoch) => {
                write!(f, "Next epoch of parent is invalid, epoch = {}", epoch)
            }
            Self::HashUpdateOnlyAllowedAfterNodeInsertion => {
                write!(
                    f,
                    "Hash update in parent only allowed after node is inserted"
                )
            }
            Self::TriedToHashLeafChildren => {
                write!(f, "Tried to hash the children of a leaf")
            }
            Self::NodeCreatedWithoutEpochs(label) => {
                write!(f, "A node exists which has no epochs. Nodes should always have epochs, labelled: {}", label)
            }
            Self::LeafNodeLabelLenLessThanInterior(label) => {
                write!(f, "A leaf was inserted with lable length shorter than an interior node, labelled: {:?}", label)
            }
            Self::CompressionError(label) => {
                write!(
                    f,
                    "A node without a child in some direction exists, labelled: {:?}",
                    label
                )
            }
            Self::NodeDidNotExistAtEp(label, epoch) => {
                write!(
                    f,
                    "This node, labelled {:?}, did not exist at epoch {:?}.",
                    label, epoch
                )
            }
            Self::NodeDidNotHaveExistingStateAtEp(label, epoch) => {
                write!(
                    f,
                    "This node, labelled {:?}, did not exist at epoch {:?}.",
                    label, epoch
                )
            }
            Self::StorageError(err) => {
                write!(f, "Encountered a storage error: {:?}", err,)
            }
            Self::SerializationError => {
                write!(f, "Encountered a serialization error")
            }
        }
    }
}

/// An error thrown by the Azks data structure.
#[derive(Debug)]
pub enum AzksError {
    /// Popped from the priority queue to update hash but found an empty value
    PopFromEmptyPriorityQueue(u64),
    /// Membership proof did not verify
    MembershipProofDidNotVerify(String),
    /// Append-only proof did not verify
    AppendOnlyProofDidNotVerify,
}

impl fmt::Display for AzksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PopFromEmptyPriorityQueue(epoch) => {
                write!(
                    f,
                    "Tried to pop from an empty priority queue at ep {:?}",
                    epoch
                )
            }
            Self::MembershipProofDidNotVerify(error_string) => {
                write!(f, "{}", error_string)
            }
            Self::AppendOnlyProofDidNotVerify => {
                write!(f, "Append only proof did not verify!")
            }
        }
    }
}

/// The errors thrown by various algorithms in [crate::directory::Directory]
#[derive(Debug)]
pub enum DirectoryError {
    /// Tried to audit for "append-only" from epoch a to b where a > b
    AuditProofStartEpLess(u64, u64),
    /// Looked up a user not in the directory
    LookedUpNonExistentUser(String, u64),
    /// Lookup proof did not verify
    LookupVerificationErr(String),
    /// Key-History proof did not verify
    KeyHistoryVerificationErr(String),
    /// Error generating the key history proof
    KeyHistoryProofErr(String),
    /// Error propogation
    StorageError,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuditProofStartEpLess(start, end) => {
                write!(
                    f,
                    "Audit proof requested for epoch {:?} till {:?} and the audit start epoch is greater than or equal to the end.",
                    start,
                    end
                )
            }
            Self::StorageError => {
                write!(f, "Error with retrieving value from storage")
            }
            Self::LookedUpNonExistentUser(uname, ep) => {
                write!(f, "The user {} did not exist at the epoch {}", uname, ep)
            }
            Self::KeyHistoryVerificationErr(err_string) => {
                write!(f, "{}", err_string)
            }
            Self::LookupVerificationErr(err_string) => {
                write!(f, "{}", err_string)
            }
            Self::KeyHistoryProofErr(err_string) => {
                write!(f, "{}", err_string)
            }
        }
    }
}

/// Represents a storage-layer error
#[derive(PartialEq, Debug)]
pub enum StorageError {
    /// An error occurred setting data in the storage layer
    SetError(String),
    /// An error occurred getting data from the storage layer
    GetError(String),
    /// An error occurred serializing or deserializing data
    SerializationError,
    /// Some kind of storage connection error occurred
    Connection(String),
}
