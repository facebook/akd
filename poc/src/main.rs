#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::Storage;
use akd::Directory;
use akd_mysql::mysql::{AsyncMySqlDatabase, MySqlCacheOptions};
use clap::{ArgEnum, Parser};
use commands::Command;
use log::{debug, error, info, warn};
use rand::distributions::Alphanumeric;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::convert::From;
use std::io::*;
use std::marker::PhantomData;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::*;
use tokio::time::timeout;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

mod commands;
mod directory_host;
mod logs;

use logs::ConsoleLogger;

type Blake3 = Blake3_256<BaseElement>;

#[derive(ArgEnum, Clone, Debug)]
enum PublicLogLevels {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl PublicLogLevels {
    pub(crate) fn to_log_level(&self) -> log::Level {
        match &self {
            PublicLogLevels::Error => log::Level::Error,
            PublicLogLevels::Warn => log::Level::Warn,
            PublicLogLevels::Info => log::Level::Info,
            PublicLogLevels::Debug => log::Level::Debug,
            PublicLogLevels::Trace => log::Level::Trace,
        }
    }
}

/// applicationModes
#[derive(Parser)]
enum OtherMode {
    #[clap(about = "Benchmark publish API")]
    BenchPublish {
        num_users: u64,
        num_updates_per_user: u64,
    },
    #[clap(about = "Benchmark lookup API")]
    BenchLookup {
        num_users: u64,
        num_lookups_per_user: u64,
    },
    #[clap(about = "Benchmark database insertion")]
    BenchDbInsert { num_users: u64 },
    #[clap(about = "Flush data from database tables")]
    Flush,
    #[clap(about = "Drop existing database tables (for schema migration etc.)")]
    Drop,
}

#[derive(Parser)]
struct Cli {
    /// The database implementation to utilize
    #[clap(long = "memory", name = "Use in-memory database")]
    memory_db: bool,

    /// Activate debuging mode
    #[clap(long = "debug", short = 'd', name = "Enable debugging mode")]
    debug: bool,

    #[clap(
        arg_enum,
        long = "log_level",
        short = 'l',
        name = "Adjust the console log-level (default = INFO)",
        ignore_case = true,
        default_value = "Info"
    )]
    console_debug: PublicLogLevels,

    #[clap(subcommand)]
    other_mode: Option<OtherMode>,

    #[clap(
        long = "multirow_size",
        short = 'm',
        name = "MySQL multi-row insert size",
        default_value = "100"
    )]
    mysql_insert_depth: usize,
}

// MAIN //
#[tokio::main]
async fn main() {
    ConsoleLogger::touch();

    let cli = Cli::parse();

    // Initialize logging facades
    let mut loggers: Vec<Box<dyn log::Log>> = vec![Box::new(ConsoleLogger {
        level: cli.console_debug.to_log_level(),
    })];

    let level = if cli.debug {
        // File-logging enabled in debug mode
        match logs::FileLogger::new("akd_app.log") {
            Err(err) => println!("Error initializing file logger {}", err),
            Ok(flogger) => loggers.push(Box::new(flogger)),
        }
        // drop the log level to debug (console has a max-level of "Info")
        log::Level::Debug
    } else {
        cli.console_debug.to_log_level()
    };

    if let Err(err) = multi_log::MultiLogger::init(loggers, level) {
        println!("Error initializing multi-logger {}", err);
    }

    let (tx, mut rx) = channel(2);

    let vrf = HardCodedAkdVRF {};
    if cli.memory_db {
        let db = akd::storage::memory::AsyncInMemoryDatabase::new();
        let mut directory = Directory::<_, _>::new::<Blake3>(&db, &vrf, false)
            .await
            .unwrap();
        if let Some(()) = pre_process_input(&cli, &tx, None).await {
            return;
        }
        tokio::spawn(async move {
            directory_host::init_host::<_, Blake3, HardCodedAkdVRF>(&mut rx, &mut directory).await
        });
        process_input(&cli, &tx, None).await;
    } else {
        // MySQL (the default)
        let mysql_db = AsyncMySqlDatabase::new(
            "localhost",
            "default",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
            MySqlCacheOptions::Default, // enable caching
            cli.mysql_insert_depth,
        )
        .await;
        if let Some(()) = pre_process_input(&cli, &tx, Some(&mysql_db)).await {
            return;
        }
        let mut directory = Directory::<_, _>::new::<Blake3>(&mysql_db, &vrf, false)
            .await
            .unwrap();
        tokio::spawn(async move {
            directory_host::init_host::<_, Blake3, HardCodedAkdVRF>(&mut rx, &mut directory).await
        });
        process_input(&cli, &tx, Some(&mysql_db)).await;
    }
}

// Helpers //
// If () is returned, it means the command execution is complete and CLI should
// return
async fn pre_process_input(
    cli: &Cli,
    tx: &Sender<directory_host::Rpc>,
    db: Option<&AsyncMySqlDatabase>,
) -> Option<()> {
    if let Some(OtherMode::Drop) = &cli.other_mode {
        println!("======= Dropping database ======= ");
        if let Some(mysql_db) = db {
            if let Err(error) = mysql_db.drop_tables().await {
                error!("Error dropping database: {}", error);
            } else {
                info!("Database dropped.");
            }
            return Option::from(());
        }
    }
    None
}

async fn process_input(
    cli: &Cli,
    tx: &Sender<directory_host::Rpc>,
    db: Option<&AsyncMySqlDatabase>,
) {
    if let Some(other_mode) = &cli.other_mode {
        match other_mode {
            OtherMode::BenchDbInsert { num_users } => {
                println!("======= Benchmark operation requested ======= ");
                println!("Beginning DB INSERT benchmark of {} users", num_users);

                let mut values: Vec<String> = vec![];
                for i in 0..*num_users {
                    values.push(
                        StdRng::seed_from_u64(i)
                            .sample_iter(&Alphanumeric)
                            .take(30)
                            .map(char::from)
                            .collect(),
                    );
                }

                let mut data = Vec::new();
                for value in values.iter() {
                    let state = akd::storage::types::DbRecord::build_user_state(
                        value.as_bytes().to_vec(),
                        value.as_bytes().to_vec(),
                        1u64,
                        1u32,
                        [1u8; 32],
                        1u64,
                    );
                    data.push(akd::storage::types::DbRecord::ValueState(state));
                }

                if let Some(storage) = db {
                    debug!("Starting the storage request");

                    let tic = Instant::now();
                    let len = data.len();
                    assert_eq!(Ok(()), storage.batch_set(data).await);
                    let toc: Duration = Instant::now() - tic;
                    println!("Insert batch of {} items in {} ms", len, toc.as_millis());
                    storage.log_metrics(log::Level::Warn).await;
                } else {
                    error!("Command available with MySQL db's only");
                }
            }
            OtherMode::BenchPublish {
                num_users,
                num_updates_per_user,
            } => {
                println!("======= Benchmark operation requested ======= ");
                println!(
                    "Beginning PUBLISH benchmark of {} users with {} updates/user",
                    num_users, num_updates_per_user
                );

                let users: Vec<String> = (1..=*num_users)
                    .map(|i| {
                        StdRng::seed_from_u64(i)
                            .sample_iter(&Alphanumeric)
                            .take(256)
                            .map(char::from)
                            .collect()
                    })
                    .collect();
                let data: Vec<String> = (1..=*num_updates_per_user)
                    .map(|i| {
                        StdRng::seed_from_u64(i)
                            .sample_iter(&Alphanumeric)
                            .take(1024)
                            .map(char::from)
                            .collect()
                    })
                    .collect();

                let tic = Instant::now();

                let mut code = None;
                for value in data {
                    let user_data: Vec<(String, String)> = users
                        .iter()
                        .map(|user| (user.clone(), value.clone()))
                        .collect();
                    let (rpc_tx, rpc_rx) = tokio::sync::oneshot::channel();
                    let rpc = directory_host::Rpc(
                        directory_host::DirectoryCommand::PublishBatch(user_data),
                        Some(rpc_tx),
                    );
                    let sent = tx.clone().send(rpc).await;
                    if sent.is_err() {
                        error!("Error sending message to directory");
                        continue;
                    }
                    match rpc_rx.await {
                        Err(err) => code = Some(format!("{}", err)),
                        Ok(Err(dir_err)) => code = Some(dir_err),
                        Ok(Ok(msg)) => info!("{}", msg),
                    }
                    if code.is_some() {
                        break;
                    }
                }

                if let Some(err) = code {
                    error!("Benchmark operation error {}", err);
                } else {
                    let toc = tic.elapsed();

                    let millis = toc.as_millis();
                    println!(
                        "Benchmark output: Inserted {} users with {} updates/user\nExecution time: {} ms\nTime-per-user (avg): {} \u{00B5}s\nTime-per-op (avg): {} \u{00B5}s",
                        num_users,
                        num_updates_per_user,
                        toc.as_millis(),
                        toc.as_micros() / *num_users as u128,
                        toc.as_micros() / *num_users as u128 / *num_updates_per_user as u128
                    );
                }
            }
            OtherMode::BenchLookup {
                num_users,
                num_lookups_per_user,
            } => {
                println!("======= Benchmark operation requested ======= ");
                println!(
                    "Beginning LOOKUP benchmark of {} users with {} lookups/user",
                    num_users, num_lookups_per_user
                );

                let user_data: Vec<(String, String)> = (1..=*num_users)
                    .map(|i| {
                        (
                            StdRng::seed_from_u64(i)
                                .sample_iter(&Alphanumeric)
                                .take(256)
                                .map(char::from)
                                .collect(),
                            StdRng::seed_from_u64(i)
                                .sample_iter(&Alphanumeric)
                                .take(1024)
                                .map(char::from)
                                .collect(),
                        )
                    })
                    .collect();

                info!("Inserting {} users", num_users);
                let (rpc_tx, rpc_rx) = tokio::sync::oneshot::channel();
                let rpc = directory_host::Rpc(
                    directory_host::DirectoryCommand::PublishBatch(user_data.clone()),
                    Some(rpc_tx),
                );
                let sent = tx.clone().send(rpc).await;

                let tic = Instant::now();

                let mut code = None;
                for i in 1..=*num_lookups_per_user {
                    for (user, _) in &user_data {
                        let (rpc_tx, rpc_rx) = tokio::sync::oneshot::channel();
                        let rpc = directory_host::Rpc(
                            directory_host::DirectoryCommand::Lookup(String::from(user)),
                            Some(rpc_tx),
                        );
                        let sent = tx.clone().send(rpc).await;
                        if sent.is_err() {
                            error!("Error sending message to directory");
                            continue;
                        }
                        match rpc_rx.await {
                            Err(err) => code = Some(format!("{}", err)),
                            Ok(Err(dir_err)) => code = Some(dir_err),
                            Ok(Ok(msg)) => {}
                        }
                        if code.is_some() {
                            break;
                        }
                    }
                    info!("LOOKUP of {} users complete (iteration {})", num_users, i);
                }

                if let Some(err) = code {
                    error!("Benchmark operation error {}", err);
                } else {
                    let toc = tic.elapsed();

                    let millis = toc.as_millis();
                    println!(
                        "Benchmark output: Looked up and verified {} users with {} lookups/user\nExecution time: {} ms\nTime-per-user (avg): {} \u{00B5}s\nTime-per-op (avg): {} \u{00B5}s",
                        num_users,
                        num_lookups_per_user,
                        toc.as_millis(),
                        toc.as_micros() / *num_users as u128,
                        toc.as_micros() / *num_users as u128 / *num_lookups_per_user as u128
                    );
                }
            }
            OtherMode::Flush => {
                println!("======= One-off flushing of the database ======= ");
                if let Some(mysql_db) = db {
                    if let Err(error) = mysql_db.delete_data().await {
                        error!("Error flushing database: {}", error);
                    } else {
                        info!("Database flushed.");
                    }
                }
            }
            OtherMode::Drop => {
                println!("======= Dropping database ======= ");
                if let Some(mysql_db) = db {
                    if let Err(error) = mysql_db.drop_tables().await {
                        error!("Error dropping database: {}", error);
                    } else {
                        info!("Database dropped.");
                    }
                }
            }
        }
    } else {
        // Traditional REPL processing loop
        loop {
            println!("Please enter a command");
            print!("> ");
            stdout().flush().unwrap();

            let mut line = String::new();
            stdin().read_line(&mut line).unwrap();

            match Command::parse(&mut line) {
                Command::Unknown(other) => println!(
                    "Input '{}' is not supported, enter 'help' for the help menu",
                    other
                ),
                Command::InvalidArgs(message) => println!("Invalid arguments: {}", message),
                Command::Exit => {
                    info!("Exiting...");
                    break;
                }
                Command::Help => {
                    Command::print_help_menu();
                }
                Command::Flush => {
                    println!("Flushing the database...");
                    if let Some(mysql_db) = db {
                        if let Err(error) = mysql_db.delete_data().await {
                            println!("Error flushing database: {}", error);
                        } else {
                            println!(
                                "Database flushed, exiting application. Please restart to create a new VKD"
                            );
                            break;
                        }
                    }
                }
                Command::Info => {
                    if cli.debug {
                        println!("\t**** DEBUG mode ACTIVE ****");
                    }
                    println!("===== Auditable Key Directory Information =====");
                    if let Some(mysql) = db {
                        println!("      Database properties ({})", mysql);
                    } else {
                        println!("      Connected to an in-memory database");
                    }
                    println!();
                }
                Command::Directory(cmd) => {
                    let (rpc_tx, rpc_rx) = tokio::sync::oneshot::channel();
                    let rpc = directory_host::Rpc(cmd, Some(rpc_tx));
                    let sent = tx.clone().send(rpc).await;
                    if sent.is_err() {
                        warn!("Error sending message to directory");
                        continue;
                    }
                    if cli.debug {
                        match rpc_rx.await {
                            Ok(Ok(success)) => {
                                println!("Response: {}", success);
                            }
                            Ok(Err(dir_err)) => {
                                error!("Error in directory processing command: {}", dir_err);
                            }
                            Err(_) => {
                                error!("Failed to receive result from directory");
                            }
                        }
                    } else {
                        match timeout(Duration::from_millis(1000), rpc_rx).await {
                            Ok(Ok(Ok(success))) => {
                                println!("Response: {}", success);
                            }
                            Ok(Ok(Err(dir_err))) => {
                                error!("Error in directory processing command: {}", dir_err);
                            }
                            Ok(Err(_)) => {
                                error!("Failed to receive result from directory");
                            }
                            Err(_) => {
                                warn!("Timeout waiting on receive from directory");
                            }
                        }
                    }
                }
            }
        }
    }
    // terminate the server proc
    let shutdown = tx
        .clone()
        .send(directory_host::Rpc(
            directory_host::DirectoryCommand::Terminate,
            None,
        ))
        .await;
    if shutdown.is_err() {
        error!("Error shutting down directory");
    }
}
