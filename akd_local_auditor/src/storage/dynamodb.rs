// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module comprises AWS DynamoDb bucket READ ONLY access to download and parse
//! Audit Proofs

use clap::Args;

#[derive(Args, Debug, Clone)]
pub struct DynamoDbClapSettings {
    /// The S3 bucket where the audit proofs are stored
    #[clap(
        long,
    )]
    test: String,
}
