// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains common test utilities for crates generating tests utilizing the
//! AKD crate

use colored::*;
use log::{Level, Metadata, Record};
use once_cell::sync::OnceCell;
use std::sync::Once;
use tokio::time::{Duration, Instant};

static EPOCH: OnceCell<Instant> = OnceCell::new();
static LOGGER: TestConsoleLogger = TestConsoleLogger {};
static INIT_ONCE: Once = Once::new();

pub(crate) struct TestConsoleLogger;

impl TestConsoleLogger {
    pub(crate) fn format_log_record(record: &Record) {
        let target = {
            if let Some(target_str) = record.target().split(':').last() {
                if let Some(line) = record.line() {
                    format!(" ({}:{})", target_str, line)
                } else {
                    format!(" ({})", target_str)
                }
            } else {
                "".to_string()
            }
        };

        let toc = if let Some(epoch) = EPOCH.get() {
            Instant::now() - *epoch
        } else {
            Duration::from_millis(0)
        };

        let seconds = toc.as_secs();
        let hours = seconds / 3600;
        let minutes = (seconds / 60) % 60;
        let seconds = seconds % 60;
        let miliseconds = toc.subsec_millis();

        let msg = format!(
            "[{:02}:{:02}:{:02}.{:03}] {:6} {}{}",
            hours,
            minutes,
            seconds,
            miliseconds,
            record.level(),
            record.args(),
            target
        );
        let msg = match record.level() {
            Level::Trace | Level::Debug => msg.white(),
            Level::Info => msg.blue(),
            Level::Warn => msg.yellow(),
            Level::Error => msg.red(),
        };
        println!("{}", msg);
    }
}

impl log::Log for TestConsoleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        TestConsoleLogger::format_log_record(record);
    }

    fn flush(&self) {}
}

/// Initialize the logger for console logging within test environments.
/// This is safe to call multiple times, but it will only initialize the logger
/// to the log-level _first_ set. If you want a specific log-level (e.g. Debug)
/// for a specific test, make sure to only run that single test after editing that
/// test's log-level.
///
/// The default level applied everywhere is Info
pub fn init_logger(level: Level) {
    EPOCH.get_or_init(Instant::now);

    INIT_ONCE.call_once(|| {
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(level.to_level_filter()))
            .unwrap();
    });
}

/// Global test startup constructor. Only runs in the TEST profile. Each
/// crate which wants logging enabled in tests being run should make this call
/// itself.
///
/// However we additionally call the init_logger(..) fn in the external storage
/// based test suite in case an external entity doesn't want to deal with the
/// ctor construction (or initializing the logger themselves)
#[cfg(test)]
#[ctor::ctor]
fn test_start() {
    init_logger(Level::Info);
}
