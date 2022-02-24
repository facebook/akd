// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Errors for various data structure operations.
use core::fmt;

use vrf::openssl::Error;

use crate::node_state::NodeLabel;

/// Symbolizes a AkdError, thrown by the akd.
#[derive(Debug)]
pub enum AkdError {
    /// Error propagation
    HistoryTreeNode(HistoryTreeNodeError),
    /// Error propagation
    Directory(DirectoryError),
    /// Error propagation
    AzksErr(AzksError),
    /// Thrown when a place where an epoch is needed wasn't provided one.
    NoEpochGiven,
    /// Thrown when the underlying Azks is not found.
    AzksNotFound(String),
    /// VRF Storage Error: Only called by the client
    VRFStorageErr(VRFStorageError),
}

impl From<HistoryTreeNodeError> for AkdError {
    fn from(error: HistoryTreeNodeError) -> Self {
        Self::HistoryTreeNode(error)
    }
}

impl From<StorageError> for AkdError {
    fn from(error: StorageError) -> Self {
        Self::HistoryTreeNode(HistoryTreeNodeError::Storage(error))
    }
}

impl From<DirectoryError> for AkdError {
    fn from(error: DirectoryError) -> Self {
        Self::Directory(error)
    }
}

impl From<VRFStorageError> for AkdError {
    fn from(error: VRFStorageError) -> Self {
        Self::VRFStorageErr(error)
    }
}

impl From<AzksError> for AkdError {
    fn from(error: AzksError) -> Self {
        Self::AzksErr(error)
    }
}

impl From<StorageError> for HistoryTreeNodeError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for AkdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "AkdError: {:?}", self)
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
    /// A data serialization error occured
    SerializationError,
    /// Error propagation
    Storage(StorageError),
}

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
            Self::Storage(err) => {
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
    /// Tried to audit an invalid epoch range
    InvalidEpoch(String),
    /// Error propagation
    Storage(StorageError),
    /// Error propagation for errors from the VRF crate
    VRFErr(Error),
    /// Error propagation for errors from VRF storage
    VRFStorageErr(VRFStorageError),
    /// Error thrown when vrf and NodeLabel not found equal
    VRFLabelErr(String),
}

impl From<Error> for DirectoryError {
    fn from(error: Error) -> Self {
        Self::VRFErr(error)
    }
}

impl From<VRFStorageError> for DirectoryError {
    fn from(error: VRFStorageError) -> Self {
        Self::VRFStorageErr(error)
    }
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(storage_error) => {
                write!(
                    f,
                    "Error with retrieving value from storage: {:?}",
                    storage_error
                )
            }
            Self::NonExistentUser(uname, ep) => {
                write!(f, "The user {} did not exist at the epoch {}", uname, ep)
            }
            Self::VerifyKeyHistoryProof(err_string) => {
                write!(f, "{}", err_string)
            }
            Self::InvalidEpoch(err_string) => {
                write!(f, "{}", err_string)
            }
            Self::VerifyLookupProof(err_string) => {
                write!(f, "{}", err_string)
            }
            Self::VRFErr(err) => {
                write!(f, "Encountered a VRF error: {:?}", err,)
            }
            Self::VRFStorageErr(err) => {
                write!(f, "Encountered a VRF error: {:?}", err,)
            }
            Self::VRFLabelErr(err_string) => {
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

/// Represents a VRF-storage-layer error
#[derive(PartialEq, Debug)]
pub enum VRFStorageError {
    /// An error occurred when getting a key
    GetPK(String),
    /// An error occurred getting the secret key
    GetSK(String),
    /// An error in proving or verifying
    VRFErr(String),
}

impl fmt::Display for VRFStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GetSK(error_string) => {
                write!(f, "{}", error_string)
            }
            Self::GetPK(error_string) => {
                write!(f, "{}", error_string)
            }
            Self::VRFErr(error_string) => {
                write!(f, "{}", error_string)
            }
        }
    }
}

impl From<Error> for VRFStorageError {
    fn from(error: Error) -> Self {
        Self::VRFErr(error.to_string())
    }
}
