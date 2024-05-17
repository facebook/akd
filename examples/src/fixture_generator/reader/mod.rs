// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains the Reader trait to deserialize the tool's serde-compatible
//! objects from a formatted file, as well as implementations of the trait.

use std::result::Result;

use crate::fixture_generator::generator::{Delta, Metadata, State};

/// Interface for reading output generated by the tool.
pub trait Reader {
    /// Reads a metadata object.
    #[allow(dead_code)]
    fn read_metadata(&mut self) -> Result<Metadata, ReaderError>;

    /// Reads a state object for a given epoch.
    #[allow(dead_code)]
    fn read_state(&mut self, epoch: u32) -> Result<State, ReaderError>;

    /// Reads a delta object for a given epoch.
    #[allow(dead_code)]
    fn read_delta(&mut self, epoch: u32) -> Result<Delta, ReaderError>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReaderError {
    NotFound,
    Format(String),
    Input(String),
}

impl std::error::Error for ReaderError {}

impl std::fmt::Display for ReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ReaderError::NotFound => write!(f, "Object not found"),
            ReaderError::Format(message) => write!(f, "Unexpected format: {message}"),
            ReaderError::Input(message) => write!(f, "Input stream error: {message}"),
        }
    }
}

/// YAML implementor of Reader trait.
pub mod yaml;

#[cfg(test)]
mod tests;
