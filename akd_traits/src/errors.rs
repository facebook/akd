// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Error types for the key directory framework.

/// Generic error type for key directory operations.
#[derive(Debug)]
pub enum KeyDirectoryError {
    /// Server-side directory operation error
    Directory(String),
    /// Storage layer error
    Storage(String),
    /// Verification error
    Verification(String),
    /// Audit error
    Audit(String),
    /// Other error
    Other(String),
}

impl std::fmt::Display for KeyDirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyDirectoryError::Directory(s) => write!(f, "Key directory error: {s}"),
            KeyDirectoryError::Storage(s) => write!(f, "Key directory storage error: {s}"),
            KeyDirectoryError::Verification(s) => {
                write!(f, "Key directory verification error: {s}")
            }
            KeyDirectoryError::Audit(s) => write!(f, "Key directory audit error: {s}"),
            KeyDirectoryError::Other(s) => write!(f, "Key directory error: {s}"),
        }
    }
}

impl std::error::Error for KeyDirectoryError {}
