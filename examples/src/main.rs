// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! A set of example applications and utilities for AKD

mod fixture_generator;
mod mysql_demo;
mod test_vectors;
mod wasm_client;
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
    /// Fixture Generator
    FixtureGenerator(fixture_generator::Args),
    /// Test vectors generator
    TestVectors(test_vectors::Args),
}

// MAIN //
#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();

    match args.example {
        ExampleType::WhatsappKtAuditor(args) => whatsapp_kt_auditor::render_cli(args).await?,
        ExampleType::MysqlDemo(args) => mysql_demo::render_cli(args).await?,
        ExampleType::FixtureGenerator(args) => fixture_generator::run(args).await,
        ExampleType::TestVectors(args) => test_vectors::run(args).await,
    }

    Ok(())
}

// Test macros

#[cfg(test)]
#[macro_export]
// NOTE(new_config): Add new configurations here
macro_rules! test_config {
    ( $x:ident ) => {
        paste::paste! {
            #[tokio::test]
            async fn [<$x _ whatsapp_v1_config>]() {
                $x::<akd::WhatsAppV1Configuration>().await
            }

            #[tokio::test]
            async fn [<$x _ experimental_config>]() {
                $x::<akd::ExperimentalConfiguration<akd::ExampleLabel>>().await
            }
        }
    };
}

#[cfg(test)]
#[macro_export]
// NOTE(new_config): Add new configurations here
macro_rules! test_config_serial {
    ( $x:ident ) => {
        paste::paste! {
            #[serial_test::serial]
            #[tokio::test]
            async fn [<$x _ whatsapp_v1_config>]() {
                $x::<akd::WhatsAppV1Configuration>().await
            }

            #[serial_test::serial]
            #[tokio::test]
            async fn [<$x _ experimental_config>]() {
                $x::<akd::ExperimentalConfiguration<akd::ExampleLabel>>().await
            }
        }
    };
}
