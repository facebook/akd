#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use akd::directory::Directory;
use akd::storage::mysql::{AsyncMySqlDatabase, MySqlCacheOptions};
use commands::Command;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::io::*;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use tokio::sync::mpsc::*;
use tokio::time::timeout;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

mod commands;
mod directory_host;

type Blake3 = Blake3_256<BaseElement>;

/// applicationModes
#[derive(StructOpt)]
enum OtherMode {
    BenchPublish {
        num_users: u64,
        num_updates_per_user: u64,
    },
    BenchLookup {
        num_users: u64,
        num_updates_per_user: u64,
    },
    Flush,
}

#[derive(StructOpt)]
struct Cli {
    /// The database implementation to utilize
    #[structopt(long = "memory", name = "Use in-memory database")]
    memory_db: bool,

    /// Activate debuging mode
    #[structopt(long = "debug", short = "d", name = "Enable debugging mode")]
    debug: bool,

    #[structopt(subcommand)]
    other_mode: Option<OtherMode>,
}

// MAIN //
#[tokio::main]
async fn main() {
    let cli = Cli::from_args();

    let (tx, mut rx) = channel(2);

    if cli.memory_db {
        let db = akd::storage::V2FromV1StorageWrapper::new(
            akd::storage::memory::AsyncInMemoryDatabase::new(),
        );
        let mut directory = Directory::<
            akd::storage::V2FromV1StorageWrapper<akd::storage::memory::AsyncInMemoryDatabase>,
        >::new::<Blake3>(&db)
        .await
        .unwrap();
        tokio::spawn(async move {
            directory_host::init_host::<_, Blake3>(&mut rx, &mut directory).await
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
        )
        .await;
        let mut directory = Directory::<AsyncMySqlDatabase>::new::<Blake3>(&mysql_db)
            .await
            .unwrap();
        tokio::spawn(async move {
            directory_host::init_host::<_, Blake3>(&mut rx, &mut directory).await
        });
        process_input(&cli, &tx, Some(&mysql_db)).await;
    }
}

// Helpers //
async fn process_input(
    cli: &Cli,
    tx: &Sender<directory_host::Rpc>,
    db: Option<&AsyncMySqlDatabase>,
) {
    if let Some(other_mode) = &cli.other_mode {
        match other_mode {
            OtherMode::BenchPublish {
                num_users,
                num_updates_per_user,
            } => {
                println!("======= Benchmark operation requested ======= ");
                println!(
                    "Beginning PUBLISH benchmark of {} users with {} updates/user",
                    num_users, num_updates_per_user
                );

                let users: Vec<String> = (1..*num_users)
                    .map(|_| {
                        thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(256)
                            .map(char::from)
                            .collect()
                    })
                    .collect();
                let data: Vec<String> = (1..*num_updates_per_user)
                    .map(|_| {
                        thread_rng()
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
                        println!("Error sending message to directory");
                        continue;
                    }
                    match rpc_rx.await {
                        Err(err) => code = Some(format!("{}", err)),
                        Ok(Err(dir_err)) => code = Some(dir_err),
                        _ => {}
                    }
                    if code.is_some() {
                        break;
                    }
                }

                if let Some(err) = code {
                    println!("Benchmark operation completed in ERROR: {}", err);
                }

                let toc = tic.elapsed();

                let millis = toc.as_millis();
                println!(
                    "Benchmark output: Inserted {} users with {} updates/user\nExecution time: {}ms\nTime-per-user (avg): {}\u{00B5}s\nTime-per-op (avg): {}\u{00B5}s",
                    num_users,
                    num_updates_per_user,
                    toc.as_millis(),
                    toc.as_micros() / *num_users as u128,
                    toc.as_micros() / *num_users as u128 / *num_updates_per_user as u128
                );
            }
            OtherMode::BenchLookup {
                num_users,
                num_updates_per_user,
            } => {
                println!("======= Benchmark operation requested ======= ");
                println!(
                    "Beginning LOOKUP benchmark of {} users with {} updates/user",
                    num_users, num_updates_per_user
                );
            }
            OtherMode::Flush => {
                println!("======= One-off flushing of the database ======= ");
                if let Some(mysql_db) = db {
                    if let Err(error) = mysql_db.delete_data().await {
                        panic!("Error flushing database: {}", error);
                    } else {
                        println!("Database flushed.");
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
                    println!("Exiting...");
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
                        println!("Error sending message to directory");
                        continue;
                    }
                    if cli.debug {
                        match rpc_rx.await {
                            Ok(Ok(success)) => {
                                println!("Response: {}", success);
                            }
                            Ok(Err(dir_err)) => {
                                println!(
                                    "ERROR: Error in directory processing command: {}",
                                    dir_err
                                );
                            }
                            Err(_) => {
                                println!("ERROR: Failed to receive result from directory");
                            }
                        }
                    } else {
                        match timeout(Duration::from_millis(1000), rpc_rx).await {
                            Ok(Ok(Ok(success))) => {
                                println!("Response: {}", success);
                            }
                            Ok(Ok(Err(dir_err))) => {
                                println!(
                                    "ERROR: Error in directory processing command: {}",
                                    dir_err
                                );
                            }
                            Ok(Err(_)) => {
                                println!("ERROR: Failed to receive result from directory");
                            }
                            Err(_) => {
                                println!("Timeout waiting on receive from directory");
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
        println!("Error shutting down directory");
    }
}
