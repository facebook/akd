// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A tool to verify audit proofs from a public (ideally immutable) storage
//! medium. This tool is a read-evaluate-print-loop (REPL) interface, where
//! a user can retrieve the information necessary about all operations by typing
//! `help` into the REPL prompt.
//!
//! # Summary
//!
//! To startup the client, you can choose 1 of the supported storage mediums.
//! Presently the supported storage mediums are
//!
//! 1. AWS DynamoDB index backed by S3 storage
//! 2. AWS S3 only, without an index
//!
//! The applicate is started with all necessary flags to connect to the storage medium
//! of choice, and then the REPL will start allowing the user to interact as an auditor.
//!
//! # Examples
//!
//! Assuming the audit proofs are stored in an S3 bucket in the AWS region `us-east-2` named
//! "myproofs". To start the application, you can run
//!
//! ```bash
//! cargo run -p akd_local_auditor -- s3 --bucket myproofs --region us-east-2
//! ```
//!
//! ## Connection customization
//!
//! If you need to customize the connection to AWS, both data-layers support providing custom
//! endpoints as well as a access key and secret key for authentication.

pub mod auditor;
mod console_log;
pub mod storage;

#[cfg(test)]
pub(crate) mod common_test;

use anyhow::Result;
use clap::{ArgEnum, Parser};
use log::debug;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
/// The hashing type (currently Blake3 256)
pub type Hasher = Blake3_256<BaseElement>;
/// The hash digest format (currently 32-byte digests)
pub type Digest = <Blake3_256<BaseElement> as winter_crypto::Hasher>::Digest;

#[derive(ArgEnum, Clone, Debug)]
enum PublicLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<&PublicLogLevel> for log::Level {
    fn from(level: &PublicLogLevel) -> Self {
        match &level {
            PublicLogLevel::Error => log::Level::Error,
            PublicLogLevel::Warn => log::Level::Warn,
            PublicLogLevel::Info => log::Level::Info,
            PublicLogLevel::Debug => log::Level::Debug,
            PublicLogLevel::Trace => log::Level::Trace,
        }
    }
}

/// AKD audit proof verification utility
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Arguments {
    /// The logging level to use for console output
    #[clap(long, short, arg_enum, ignore_case = true, default_value = "Info")]
    log_level: PublicLogLevel,

    /// Show the verification QR code in the terminal
    #[clap(long)]
    qr: bool,

    /// Storage configuration for audit proofs
    #[clap(subcommand)]
    storage: storage::StorageSubcommand,
}

// MAIN //
#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();

    // initialize the logger
    let log_level: log::Level = (&args.log_level).into();
    console_log::init_logger(log_level);

    debug!("Parsed args: {:?}", args);

    let storage: Box<dyn storage::AuditProofStorage> = match &args.storage {
        storage::StorageSubcommand::S3(s3_settings) => {
            let imp: storage::s3::S3AuditStorage = s3_settings.into();
            Box::new(imp)
        }
        storage::StorageSubcommand::DynamoDb(dynamo_settings) => {
            let imp: storage::dynamodb::DynamoDbAuditStorage = dynamo_settings.into();
            Box::new(imp)
        }
    };

    let command_processor = crate::auditor::AuditProcessor::new_repl_processor(storage);

    let mut repl = rustyrepl::Repl::<auditor::AuditArgs>::new(
        command_processor,
        Some(auditor::HISTORY_FILE.to_string()),
        Some("$ ".to_string()),
    )?;
    repl.process().await
}
