// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use colored::*;
use directory_host::DirectoryCommand;
use seemless::seemless_directory::SeemlessDirectory;
use seemless::storage::mysql::r#async::AsyncMySqlDatabase;
use std::io::*;
use std::time::Duration;
use tokio::sync::mpsc::*;
use tokio::time::timeout;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

mod directory_host;

enum Command {
    Help,
    Exit,
    Directory(DirectoryCommand),
    InvalidArgs(String),
    Unknown(String),
}

impl Command {
    pub(crate) fn parse(text: &mut String) -> Command {
        trim_newline(text);
        let parts: Vec<&str> = text.split(' ').collect();

        let mut command = String::new();
        if let Some(head) = parts.first() {
            command = String::from(*head);
        }

        match command.to_lowercase().as_ref() {
            "exit" | "x" => Command::Exit,
            "help" | "?" => Command::Help,
            cmd => Command::handle_dir_cmd(cmd, parts, text),
        }
    }

    pub(crate) fn print_help_menu() {
        println!(
            "{}",
            "*************************** Help menu ***************************".red()
        );
        println!(
            "{} are commands, {} are mandatory args, {} are optional args",
            "green".green(),
            "blue".blue(),
            "magenta".magenta()
        );
        println!("=============================================================");
        println!("  {}|{}:\t\t\tprint this menu", "help".green(), "?".green());
        println!(
            "  {}|{}:\t\t\texit the application",
            "exit".green(),
            "x".green()
        );
        println!(
            "  {} {} {}:\t\tpublish key material (value) for user",
            "publish".green(),
            "user".blue(),
            "value".blue()
        );
        println!(
            "  {} {}:\t\t\tlookup a proof for user",
            "lookup".green(),
            "user".blue()
        );
        println!(
            "  {} {}:\t\t\tlookup key history for user",
            "history".green(),
            "user".blue()
        );
        println!(
            "  {} {} {}:\t\tretrieve audit proof between start and end epochs",
            "audit".green(),
            "start".blue(),
            "end".blue()
        );
        println!(
            "  {}|{} {}:\t\tretrieve the root hash at given epoch (default = latest epoch)",
            "root".green(),
            "root_hash".green(),
            "epoch".magenta()
        );
    }

    // ==== Helpers for managing directory commands ==== //
    fn handle_dir_cmd(command: &str, parts: Vec<&str>, full_text: &str) -> Command {
        let dir_cmd: Option<Option<DirectoryCommand>> = match command {
            "publish" => Some(Command::publish(parts)),
            "lookup" => Some(Command::lookup(parts)),
            "history" => Some(Command::history(parts)),
            "audit" => Some(Command::audit(parts)),
            "root" | "root_hash" => Some(Command::root_hash(parts)),
            _ => None,
        };
        match dir_cmd {
            Some(Some(cmd)) => Command::Directory(cmd),
            Some(None) => {
                let msg = format!(
                    "Command {} received invalid argments. Check {} for syntax",
                    command,
                    "help".green()
                );
                Command::InvalidArgs(msg)
            }
            _ => Command::Unknown(String::from(full_text)),
        }
    }

    fn publish(parts: Vec<&str>) -> Option<DirectoryCommand> {
        if parts.len() < 3 {
            return None;
        }
        let (a, b) = (parts[1], parts[2]);
        let cmd = DirectoryCommand::Publish(String::from(a), String::from(b));
        Some(cmd)
    }

    fn lookup(parts: Vec<&str>) -> Option<DirectoryCommand> {
        if parts.len() < 2 {
            return None;
        }
        let a = parts[1];
        let cmd = DirectoryCommand::Lookup(String::from(a));
        Some(cmd)
    }

    fn history(parts: Vec<&str>) -> Option<DirectoryCommand> {
        if parts.len() < 2 {
            return None;
        }
        let a = parts[1];
        let cmd = DirectoryCommand::KeyHistory(String::from(a));
        Some(cmd)
    }

    fn audit(parts: Vec<&str>) -> Option<DirectoryCommand> {
        if parts.len() < 3 {
            return None;
        }
        let (a, b) = (parts[1], parts[2]);
        match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(u_a), Ok(u_b)) => {
                let cmd = DirectoryCommand::Audit(u_a, u_b);
                Some(cmd)
            }
            _ => None,
        }
    }

    fn root_hash(parts: Vec<&str>) -> Option<DirectoryCommand> {
        let mut epoch = None;
        if parts.len() > 1 {
            if let Ok(a) = parts[1].parse::<u64>() {
                epoch = Some(a);
            }
        }

        let cmd = DirectoryCommand::RootHash(epoch);
        Some(cmd)
    }
}

#[tokio::main]
async fn main() {
    let (tx, mut rx) = channel(2);
    let mysql_db = AsyncMySqlDatabase::new(
        "localhost",
        "default",
        Option::from("root"),
        Option::from("example"),
        Option::from(8001),
    )
    .await;

    let mut directory =
        SeemlessDirectory::<AsyncMySqlDatabase, Blake3_256<BaseElement>>::new(&mysql_db)
            .await
            .unwrap();
    tokio::spawn(async move { directory_host::init_host(&mut rx, &mut directory).await });

    process_input(&tx).await;
}

async fn process_input(tx: &Sender<directory_host::Rpc>) {
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

fn trim_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}
