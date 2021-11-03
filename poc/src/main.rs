// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use commands::Command;
use std::io::*;
use std::time::Duration;
use tokio::sync::mpsc::*;
use tokio::time::timeout;
use akd::directory::Directory;
use akd::storage::mysql::AsyncMySqlDatabase;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
use structopt::StructOpt;

// any error type implementing Display is acceptable.

mod commands;
mod directory_host;

#[derive(StructOpt)]
#[structopt(about = "The database types")]
enum DatabaseType {
    Mysql,
    Memory
}

#[derive(StructOpt)]
struct Cli {
    /// The database implementation to utilize
    #[structopt(subcommand)]
    db: DatabaseType
}

// MAIN //
#[tokio::main]
async fn main() {

    let cli = Cli::from_args();

    let (tx, mut rx) = channel(2);

    if let DatabaseType::Memory = cli.db {
        let db = akd::storage::V2FromV1StorageWrapper::new(akd::storage::memory::AsyncInMemoryDatabase::new());
        let mut directory = Directory::<akd::storage::V2FromV1StorageWrapper<akd::storage::memory::AsyncInMemoryDatabase>, Blake3_256<BaseElement>>::new(&db).await.unwrap();
        tokio::spawn(async move { directory_host::init_host(&mut rx, &mut directory).await });
        process_input(&tx, None).await;
    } else {
        // MySQL (the default)
        let mysql_db = AsyncMySqlDatabase::new(
            "localhost",
            "default",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
        )
        .await;
        let mut directory = Directory::<AsyncMySqlDatabase, Blake3_256<BaseElement>>::new(&mysql_db)
            .await
            .unwrap();
        tokio::spawn(async move { directory_host::init_host(&mut rx, &mut directory).await });
        process_input(&tx, Some(&mysql_db)).await;
    }
}

// Helpers //
async fn process_input(tx: &Sender<directory_host::Rpc>, db: Option<&AsyncMySqlDatabase>) {
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
            },
            Command::Help => {
                Command::print_help_menu();
            },
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
            },
            Command::Info => {
                if let Some(mysql) = db {
                    println!("Database properties ({})", mysql);
                } else {
                    println!("Connected to an in-memory database");
                }
            },
            Command::Directory(cmd) => {
                let (rpc_tx, rpc_rx) = tokio::sync::oneshot::channel();
                let rpc = directory_host::Rpc(cmd, Some(rpc_tx));
                let sent = tx.clone().send(rpc).await;
                if sent.is_err() {
                    println!("Error sending message to directory");
                    continue;
                }
                match timeout(Duration::from_millis(1000), rpc_rx).await {
                    Ok(Ok(Ok(success))) => {
                        println!("Response: {}", success);
                    }
                    Ok(Ok(Err(dir_err))) => {
                        println!("ERROR: Error in directory processing command: {}", dir_err);
                    }
                    Ok(Err(_)) => {
                        println!("ERROR: Failed to receive result from directory");
                    }
                    Err(_) => {
                        println!("Timeout waiting on receive from directory");
                    }
                }
            },
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
