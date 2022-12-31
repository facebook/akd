// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the struct definitions of the tool output and main
//! fixture generation logic.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;

use akd::directory::Directory;
use akd::storage::types::DbRecord;
use akd::storage::{StorageManager, StorageUtil};
use akd::{AkdLabel, AkdValue};
use clap::Parser;
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};

use crate::fixture_generator::parser::Args;
use crate::fixture_generator::writer::yaml::YamlWriter;
use crate::fixture_generator::writer::Writer;

/// Directory state comprises all database records at a particular epoch.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub epoch: u32,
    pub records: Vec<DbRecord>,
}

/// Delta comprises all key updates published to the directory to advance to an
/// epoch.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    pub epoch: u32,
    pub updates: Vec<(AkdLabel, AkdValue)>,
}

/// Metadata about the output, including arguments passed to this tool and
/// the tool version.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub args: Args,
    pub version: String,
}

// "@" has to be separated from "generated" or linters might ignore this file
const HEADER_COMMENT: &str = concat!(
    "@",
    "generated This file was automatically generated by \n\
    the fixture generator tool with the following command:\n\n\
    cargo run -- \\"
);
const METADATA_COMMENT: &str = "Metadata";
const STATE_COMMENT: &str = "State - Epoch";
const DELTA_COMMENT: &str = "Delta - Epoch";

pub async fn run() {
    let args = Args::parse();
    generate(args).await;
}

pub(crate) async fn generate(args: Args) {
    let mut rng = OsRng;

    // args assertions
    assert!(args.max_updates >= args.min_updates);
    assert!(args
        .capture_states
        .as_ref()
        .map_or(true, |states| states.iter().max().unwrap() <= &args.epochs));
    assert!(args
        .capture_deltas
        .as_ref()
        .map_or(true, |deltas| deltas.iter().max().unwrap() <= &args.epochs));

    // process users
    let mut user_map = HashMap::new();
    for user in &args.users {
        let mut events_map = HashMap::new();
        for event in &user.events {
            events_map.insert(event.epoch, event.value.clone());
        }
        user_map.insert(user.label.clone(), events_map);
    }

    // initialize writer
    let buffer: Box<dyn Write> = if let Some(ref file_name) = args.out {
        Box::new(File::create(file_name).unwrap())
    } else {
        Box::new(std::io::stdout())
    };
    let mut writer = YamlWriter::new(buffer);

    // write raw args as comment
    let raw_args = format!(
        " {}",
        env::args().skip(1).collect::<Vec<String>>().join(" ")
    );
    writer.write_comment(HEADER_COMMENT);
    raw_args
        .split(" -")
        .skip(1)
        .map(|arg| format!("  -{} \\", arg))
        .for_each(|comment| writer.write_comment(&comment));

    // write fixture metadata
    let comment = METADATA_COMMENT.to_string();
    let metadata = Metadata {
        args: args.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    writer.write_line();
    writer.write_comment(&comment);
    writer.write_object(metadata);

    // initialize directory
    let db = akd::storage::memory::AsyncInMemoryDatabase::new();
    let vrf = akd::ecvrf::HardCodedAkdVRF {};
    let storage_manager = StorageManager::new_no_cache(&db);
    let akd = Directory::<_, _>::new(storage_manager, vrf, false)
        .await
        .unwrap();

    for epoch in 1..=args.epochs {
        // gather specified key updates
        let mut updates = vec![];
        for (label, events) in user_map.iter() {
            if let Some(maybe_value) = events.get(&epoch) {
                let value = maybe_value
                    .clone()
                    .unwrap_or_else(|| AkdValue::random(&mut rng));
                updates.push((label.clone(), value))
            }
        }

        // generate random key updates if allowed
        if !args.no_generated_updates {
            let num_updates = rng.gen_range(args.min_updates, args.max_updates);
            for _ in updates.len()..num_updates as usize {
                updates.push((AkdLabel::random(&mut rng), AkdValue::random(&mut rng)));
            }
        }

        // write delta if required
        if let Some(ref deltas) = args.capture_deltas {
            if deltas.contains(&epoch) {
                let comment = format!("{} {}", DELTA_COMMENT, epoch);
                let delta = Delta {
                    epoch,
                    updates: updates.clone(),
                };
                writer.write_line();
                writer.write_comment(&comment);
                writer.write_object(delta);
            }
        }

        // perform publish
        akd.publish(updates.clone()).await.unwrap();

        // write state if required
        if let Some(ref states) = args.capture_states {
            if states.contains(&epoch) {
                let comment = format!("{} {}", STATE_COMMENT, epoch);
                let state = State {
                    epoch,
                    records: db.batch_get_all_direct().await.unwrap(),
                };
                writer.write_line();
                writer.write_comment(&comment);
                writer.write_object(state);
            }
        }
    }

    // flush writer and exit
    writer.flush();
}
