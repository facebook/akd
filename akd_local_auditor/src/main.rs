// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A tool to verify audit proofs from a public S3 bucket storage of all proofs

mod console_log;

pub mod auditor;
pub mod storage;

use anyhow::Result;
use clap::{ArgEnum, Parser};
use log::debug;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
type Hasher = Blake3_256<BaseElement>;

static LOGGER: console_log::ConsoleLogger = console_log::ConsoleLogger {
    level: log::Level::Debug,
};

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
    console_log::ConsoleLogger::touch();

    let args = Arguments::parse();

    // initialize the logger
    let log_level: log::Level = (&args.log_level).into();

    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log_level.to_level_filter()))
        .expect("Failed to set up logging");
    debug!("Parsed args: {:?}", args);

    let storage: Box<dyn storage::AuditProofStorage> = match &args.storage {
        storage::StorageSubcommand::S3(s3_settings) => {
            let imp: storage::s3::S3AuditStorage = s3_settings.into();
            Box::new(imp)
        }
    };

    let command_processor: Box<dyn rustyrepl::ReplCommandProcessor<auditor::AuditArgs>> =
        Box::new(crate::auditor::AuditProcessor { storage });

    let mut repl = rustyrepl::Repl::<auditor::AuditArgs>::new(
        command_processor,
        Some(auditor::HISTORY_FILE.to_string()),
        Some("$ ".to_string()),
    )?;
    repl.process().await
}
