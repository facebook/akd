// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Errors for various data structure operations.
use core::fmt;

use crate::node_state::NodeLabel;

/// Symbolizes a AkdError, thrown by the akd.
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
    /// Thrown when a requested element is not found.
    NotFoundError(String),
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

impl std::fmt::Display for AkdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "AkdError: {:?}", self)
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
    /// The next epoch of this node's parent was invalid
    ParentNextEpochInvalid(u64),
    /// The hash of a parent was attempted to be updated, without setting the calling node as a child.
    HashUpdateOnlyAllowedAfterNodeInsertion,
    /// The children of a leaf are always dummy and should not be hashed
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
            Self::NoChildInTreeAtEpoch(epoch, direction) => {
                write!(f, "no node in direction {} at epoch {}", direction, epoch)
            }
            Self::DirectionIsNone => {
                write!(f, "Direction provided is None")
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
    /// Membership proof did not verify
    VerifyMembershipProof(String),
    /// Append-only proof did not verify
    VerifyAppendOnlyProof,
}

impl fmt::Display for AzksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerifyMembershipProof(error_string) => {
                write!(f, "{}", error_string)
            }
            Self::VerifyAppendOnlyProof => {
                write!(f, "Append only proof did not verify!")
            }
        }
    }
}

/// The errors thrown by various algorithms in [crate::directory::Directory]
#[derive(Debug)]
pub enum DirectoryError {
    /// Looked up a user not in the directory
    NonExistentUser(String, u64),
    /// Lookup proof did not verify
    VerifyLookupProof(String),
    /// Key-History proof did not verify
    VerifyKeyHistoryProof(String),
    /// Error propogation
    StorageError,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageError => {
                write!(f, "Error with retrieving value from storage")
            }
            Self::NonExistentUser(uname, ep) => {
                write!(f, "The user {} did not exist at the epoch {}", uname, ep)
            }
            Self::VerifyKeyHistoryProof(err_string) => {
                write!(f, "{}", err_string)
            }
            Self::VerifyLookupProof(err_string) => {
                write!(f, "{}", err_string)
            }
        }
    }
}

/// Represents a storage-layer error
#[derive(PartialEq, Debug)]
pub enum StorageError {
    /// An error occurred setting data in the storage layer
    SetData(String),
    /// An error occurred getting data from the storage layer
    GetData(String),
    /// Some kind of storage connection error occurred
    Connection(String),
}
