// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module provides a basic logger implementation to the console with
//! some additional information (file, line number, thread, etc)

use colored::*;
use log::Level;
use log::Metadata;
use log::Record;
use once_cell::sync::OnceCell;
use std::io::Write;
use std::sync::Once;
use tokio::time::Duration;
use tokio::time::Instant;

static EPOCH: OnceCell<Instant> = OnceCell::new();
static INIT_ONCE: Once = Once::new();

pub(crate) static LOGGER: ConsoleLogger = ConsoleLogger {
    level: log::Level::Debug,
};

pub struct ConsoleLogger {
    pub level: Level,
}

impl ConsoleLogger {
    pub(crate) fn format_log_record(io: &mut (dyn Write + Send), record: &Record, colored: bool) {
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
        let milliseconds = toc.subsec_millis();

        let msg = format!(
            "[{:02}:{:02}:{:02}.{:03}] {:6} {}{}",
            hours,
            minutes,
            seconds,
            milliseconds,
            record.level(),
            record.args(),
            target
        );
        if colored {
            let msg = match record.level() {
                Level::Trace | Level::Debug => msg.white(),
                Level::Info => msg.green(),
                Level::Warn => msg.yellow().bold(),
                Level::Error => msg.red().bold(),
            };
            let _ = writeln!(io, "{}", msg);
        } else {
            let _ = writeln!(io, "{}", msg);
        }
    }
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut io = std::io::stdout();
        ConsoleLogger::format_log_record(&mut io, record, true);
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
    }
}

/// Initialize the logger for console logging within test environments.
/// This is safe to call multiple times, but it will only initialize the logger
/// to the log-level _first_ set. If you want a specific log-level (e.g. Debug)
/// for a specific test, make sure to only run that single test after editing that
/// test's log-level.
///
/// The default level applied everywhere is Info
pub(crate) fn init_logger(level: Level) {
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
#[cfg(test)]
#[ctor::ctor]
fn test_start() {
    init_logger(Level::Info);
}
