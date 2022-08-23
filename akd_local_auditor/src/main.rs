// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A tool to verify audit proofs from a public S3 bucket storage of all proofs

pub mod auditor;
mod console_log;
pub mod s3;

use clap::{ArgEnum, Parser};
use log::{debug, error, info};

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

impl PublicLogLevel {
    pub(crate) fn to_log_level(&self) -> log::Level {
        match &self {
            PublicLogLevel::Error => log::Level::Error,
            PublicLogLevel::Warn => log::Level::Warn,
            PublicLogLevel::Info => log::Level::Info,
            PublicLogLevel::Debug => log::Level::Debug,
            PublicLogLevel::Trace => log::Level::Trace,
        }
    }
}

#[derive(Parser, Debug)]
pub struct Arguments {
    /// The logging level to use for console output
    #[clap(long, short, arg_enum, ignore_case = true, default_value = "Info")]
    log_level: PublicLogLevel,

    /// Show the verification QR code in the terminal
    #[clap(long)]
    qr: bool,
}

// MAIN //
#[tokio::main]
async fn main() {
    console_log::ConsoleLogger::touch();

    let args = Arguments::parse();

    // initialize the logger
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(args.log_level.to_log_level().to_level_filter()))
        .expect("Failed to setup logging");
    debug!("Parsed args: {:?}", args);

    // Generate the QR code
    if args.qr {
        info!("Generating QR code");
        if let Err(error) = qr2term::print_qr("https://google.com/") {
            error!("Error generating QR code {}", error);
        }
    }
}
