// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the CLI argument definitions and parser.

use akd::storage::types::{AkdLabel, AkdValue};
use clap::{AppSettings, Parser};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Any alphanumeric string - spaces are allowed e.g. "User123" or "User 123"
const USER_PATTERN: &str = r"[\w\s]+";

/// A solo string of digits e.g. "10" or a tuple of digits and a string
/// e.g."(10, 'abc')"
const EVENT_PATTERN: &str = r"\d+|(\(\s*(\d+)\s*,\s*'(\w*)'\s*\))";

/// A key update the tool should include in the tree at the given epoch.
/// If "value" is None, the tool will randomly generate a value for the epoch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserEvent {
    pub epoch: u32,
    pub value: Option<AkdValue>,
}

/// A user whose key update events should be included in the tree.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub label: AkdLabel,
    pub events: Vec<UserEvent>,
}

/// This tool allows a directory to be created with specified and random
/// contents, capturing the directory state and epoch-to-epoch delta in
/// an output file for use in debugging and as test fixtures.
#[derive(Parser, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
pub struct Args {
    /// Users and their associated key update events.
    /// A username is expected, followed by a colon and a list of epochs OR
    /// (epoch, value). Usernames are expected to be utf-8 strings, which will
    /// be internally interpreted as bytes.
    /// The following are valid examples of user arguments:
    ///   --user "username: 1, 3, (5, 'xyz')"
    ///   --user="username: [(1,'abc'), 2]"
    ///   -u "some username: 1"
    #[clap(
        long = "user",
        short = 'u',
        multiple_occurrences = true,
        parse(try_from_str = parse_user_events),
    )]
    pub users: Vec<User>,

    /// Number of epochs to advance the tree by
    /// e.g. a value of 3 will perform 3 publishes on an empty directory.
    #[clap(long = "epochs", short = 'e')]
    pub epochs: u32,

    /// Maximum number of key updates **per epoch** the tool should perform.
    /// Note that all user events explicitly passed for an epoch will be
    /// included even if the number exceeds this value.
    #[clap(long = "max_updates", default_value = "10")]
    pub max_updates: u32,

    /// Minimum number of key updates **per epoch** the tool should perform.
    /// The tool will generate random labels and values to include in an epoch
    /// if the user events explicitly passed for an epoch are not sufficients.
    #[clap(long = "min_updates", default_value = "0")]
    pub min_updates: u32,

    /// Epochs where the state of the directory should be captured in the output
    /// e.g. the value 3 will output all db records after epoch 3 is performed.
    /// Multiple values are accepted e.g. --capture_states 9 10
    #[clap(long = "capture_states", short = 's', multiple_values = true)]
    pub capture_states: Option<Vec<u32>>,

    /// Epochs where the key updates required to bring the directory to the
    /// epoch should be captured in the output.
    /// e.g. the value 3 will output all key updates that were performed to
    /// advance the directory from epoch 2 to 3.
    /// Multiple values are accepted e.g. --capture_deltas 9 10
    #[clap(long = "capture_deltas", short = 'd', multiple_values = true)]
    pub capture_deltas: Option<Vec<u32>>,

    /// Name of output file.
    /// If omitted, output will be printed to stdout.
    #[clap(long = "out", short = 'o')]
    pub out: Option<String>,

    /// Stops tool from generating random key updates in publishes.
    /// Use this if you want the tool to only use explicitly passed key updates.
    /// Explicilty passed key updates without values would still use randomly
    /// generated values.
    #[clap(long = "no_generated_updates", short = 'n')]
    pub no_generated_updates: bool,
}

fn parse_user_events(s: &str) -> Result<User, String> {
    let mut split = s.split(':');
    let username_text = split.next().unwrap();
    let maybe_events_text = split.next();

    let username = Regex::new(USER_PATTERN)
        .unwrap()
        .captures(username_text)
        .unwrap()
        .get(0)
        .unwrap()
        .as_str();

    let events = if let Some(events_text) = maybe_events_text {
        Regex::new(EVENT_PATTERN)
            .unwrap()
            .captures_iter(events_text)
            .map(|event| {
                let epoch: u32;
                let value: Option<AkdValue>;
                if event.get(1).is_some() {
                    epoch = event.get(2).unwrap().as_str().parse().unwrap();
                    value = Some(AkdValue::from_utf8_str(event.get(3).unwrap().as_str()));
                } else {
                    epoch = event.get(0).unwrap().as_str().parse().unwrap();
                    value = None;
                }
                UserEvent { epoch, value }
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    Ok(User {
        label: AkdLabel::from_utf8_str(username),
        events,
    })
}
