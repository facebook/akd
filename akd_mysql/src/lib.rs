// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This crate implements a basic MySQL storage layer for the auditable key directory.
//!
//! ⚠️ **Warning**: This implementation has not been audited and is not ready for use in a real system. Use at your own risk!
//! # Overview
//! MySQL is a common storage layer utilized in many deployments. Having a simple, yet performant, storage layer is useful for real applications
//! which may want to utilize the AKD structure. This crate implements a data-layer for MySQL which properly supports all of the calls required
//! by the AKD directory logic at a good performance level. At reasonable scale, on a decent MySQL instance, one can expect publishing 100K records
//! in approximately 10-20 minutes.
//!

#![warn(missing_docs)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod mysql;

pub mod mysql_storables;

#[cfg(test)]
mod mysql_db_tests;
