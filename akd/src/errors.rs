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
#[derive(Debug, PartialEq)]
pub enum AkdError {
    /// Error propagation
    HistoryTreeNode(HistoryTreeNodeError),
    /// Error propagation
    Directory(DirectoryError),
    /// Error propagation
    AzksErr(AzksError),
    /// Vrf related error
    Vrf(VrfError),
    /// Storage layer error thrown
    Storage(StorageError),
}

impl std::error::Error for AkdError {}

impl From<HistoryTreeNodeError> for AkdError {
    fn from(error: HistoryTreeNodeError) -> Self {
        Self::HistoryTreeNode(error)
    }
}

impl From<StorageError> for AkdError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<DirectoryError> for AkdError {
    fn from(error: DirectoryError) -> Self {
        Self::Directory(error)
    }
}

impl From<VrfError> for AkdError {
    fn from(error: VrfError) -> Self {
        Self::Vrf(error)
    }
}

impl From<AzksError> for AkdError {
    fn from(error: AzksError) -> Self {
        Self::AzksErr(error)
    }
}

impl std::fmt::Display for AkdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            AkdError::HistoryTreeNode(err) => {
                writeln!(f, "AKD History Tree Node Error: {}", err)
            }
            AkdError::Directory(err) => {
                writeln!(f, "AKD Directory Error: {}", err)
            }
            AkdError::AzksErr(err) => {
                writeln!(f, "AKD AZKS Error: {}", err)
            }
            AkdError::Vrf(err) => {
                writeln!(f, "AKD VRF Error: {}", err)
            }
            AkdError::Storage(err) => {
                writeln!(f, "AKD Storage Error: {}", err)
            }
        }
    }
}

/// Errors thrown by HistoryTreeNodes
#[derive(Debug, PartialEq)]
pub enum HistoryTreeNodeError {
    /// No direction provided for the node.
    /// Second parameter is the label of the child attempted to be set
    /// -- if there is one, otherwise it is None.
    NoDirection(NodeLabel, Option<NodeLabel>),
    /// The node didn't have a child in the given epoch
    NoChildAtEpoch(u64, usize),
    /// The next epoch of this node's parent was invalid
    ParentNextEpochInvalid(u64),
    /// The hash of a parent was attempted to be updated, without setting the calling node as a child.
    HashUpdateOrderInconsistent,
    /// The node did not exist at epoch
    NonexistentAtEpoch(NodeLabel, u64),
    /// The state of a node did not exist at a given epoch
    NoStateAtEpoch(NodeLabel, u64),
    /// Failed to deserialize a digest
    DigestDeserializationFailed,
}

impl std::error::Error for HistoryTreeNodeError {}

impl fmt::Display for HistoryTreeNodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDirection(node_label, child_label) => {
                let mut to_print = format!("no direction provided for the node {:?}", node_label);
                // Add child info if given.
                if let Some(child_label) = child_label {
                    let child_str = format!(" and child {:?}", child_label);
                    to_print.push_str(&child_str);
                }
                write!(f, "{}", to_print)
            }
            Self::NoChildAtEpoch(epoch, direction) => {
                write!(f, "no node in direction {} at epoch {}", direction, epoch)
            }
            Self::ParentNextEpochInvalid(epoch) => {
                write!(f, "Next epoch of parent is invalid, epoch = {}", epoch)
            }
            Self::HashUpdateOrderInconsistent => {
                write!(
                    f,
                    "Hash update in parent only allowed after node is inserted"
                )
            }
            Self::NonexistentAtEpoch(label, epoch) => {
                write!(
                    f,
                    "This node, labelled {:?}, did not exist at epoch {:?}.",
                    label, epoch
                )
            }
            Self::NoStateAtEpoch(label, epoch) => {
                write!(
                    f,
                    "This node, labelled {:?}, did not exist at epoch {:?}.",
                    label, epoch
                )
            }
            Self::DigestDeserializationFailed => {
                write!(f, "Encountered a serialization error")
            }
        }
    }
}

/// An error thrown by the Azks data structure.
#[derive(Debug, PartialEq)]
pub enum AzksError {
    /// Membership proof did not verify
    VerifyMembershipProof(String),
    /// Append-only proof did not verify
    VerifyAppendOnlyProof,
    /// Thrown when a place where an epoch is needed wasn't provided one.
    NoEpochGiven,
}

impl std::error::Error for AzksError {}

impl fmt::Display for AzksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerifyMembershipProof(error_string) => {
                write!(f, "{}", error_string)
            }
            Self::VerifyAppendOnlyProof => {
                write!(f, "Append only proof did not verify!")
            }
            Self::NoEpochGiven => {
                write!(f, "An epoch was required but not supplied")
            }
        }
    }
}

/// The errors thrown by various algorithms in [crate::directory::Directory]
#[derive(Debug, PartialEq)]
pub enum DirectoryError {
    /// Lookup proof did not verify
    VerifyLookupProof(String),
    /// Key-History proof did not verify
    VerifyKeyHistoryProof(String),
    /// Tried to audit an invalid epoch range
    InvalidEpoch(String),
    /// AZKS not found in read-only directory mode
    ReadOnlyDirectory(bool),
}

impl std::error::Error for DirectoryError {}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerifyKeyHistoryProof(err_string) => {
                write!(f, "Failed to verify key history {}", err_string)
            }
            Self::InvalidEpoch(err_string) => {
                write!(f, "Invalid epoch {}", err_string)
            }
            Self::VerifyLookupProof(err_string) => {
                write!(f, "Failed to verify lookup proof {}", err_string)
            }
            Self::ReadOnlyDirectory(missing_azks) => {
                let specific = if *missing_azks {
                    "AZKS not found"
                } else {
                    "Operation not permitted"
                };
                write!(f, "Directory in read-only mode: {}", specific)
            }
        }
    }
}

/// Represents a storage-layer error
#[derive(PartialEq, Debug)]
pub enum StorageError {
    /// Data wasn't found in the storage layer
    NotFound(String),
    /// A transaction error
    Transaction(String),
    /// Some kind of storage connection error occurred
    Connection(String),
    /// Some other storage-layer error occurred
    Other(String),
}

impl std::error::Error for StorageError {}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Connection(inner) => {
                write!(f, "Storage connection: {}", inner)
            }
            StorageError::Transaction(inner) => {
                write!(f, "Transaction: {}", inner)
            }
            StorageError::NotFound(inner) => {
                write!(f, "Data not found: {}", inner)
            }
            StorageError::Other(inner) => {
                write!(f, "Other storage error: {}", inner)
            }
        }
    }
}

/// Represents a VRF-storage-layer error
#[derive(PartialEq, Debug)]
pub enum VrfError {
    /// An error occurred when getting a key
    PublicKey(String),
    /// An error occurred getting the secret key
    SigningKey(String),
    /// An error in proving verifying
    Verification(String),
}

impl std::error::Error for VrfError {}

impl fmt::Display for VrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningKey(error_string) => {
                write!(f, "VRF signing key: {}", error_string)
            }
            Self::PublicKey(error_string) => {
                write!(f, "VRF public key: {}", error_string)
            }
            Self::Verification(error_string) => {
                write!(f, "VRF prooving or verifying: {}", error_string)
            }
        }
    }
}
