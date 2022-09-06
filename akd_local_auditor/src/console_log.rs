// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use colored::*;
use log::Level;
use log::Metadata;
use log::Record;
use once_cell::sync::OnceCell;
use std::io::Write;
use tokio::time::Duration;
use tokio::time::Instant;

static EPOCH: OnceCell<Instant> = OnceCell::new();

pub struct ConsoleLogger {
    pub level: Level,
}

impl ConsoleLogger {
    pub fn touch() {
        EPOCH.get_or_init(Instant::now);
    }

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
