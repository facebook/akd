// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

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
//! The application is started with all necessary flags to connect to the storage medium
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

mod mysql_demo;
mod whatsapp_kt_auditor;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// AKD examples
#[derive(Parser, Debug)]
#[clap(author, about, long_about = None)]
pub struct Arguments {
    /// The type of example to run
    #[clap(subcommand)]
    example: ExampleType,
}

#[derive(Subcommand, Debug, Clone)]
enum ExampleType {
    /// WhatsApp Key Transparency Auditor
    WhatsappKtAuditor(whatsapp_kt_auditor::CliArgs),
    /// MySQL Demo
    MysqlDemo(mysql_demo::CliArgs),
}

// MAIN //
#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();

    match args.example {
        ExampleType::WhatsappKtAuditor(args) => whatsapp_kt_auditor::render_cli(args).await?,
        ExampleType::MysqlDemo(args) => mysql_demo::render_cli(args).await?,
    }

    Ok(())
}
