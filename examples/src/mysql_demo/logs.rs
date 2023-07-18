// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

extern crate thread_id;

use colored::*;
use log::{Level, Metadata, Record};
use once_cell::sync::OnceCell;
use tokio::time::{Duration, Instant};

use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

static EPOCH: OnceCell<Instant> = OnceCell::new();

pub(crate) struct ConsoleLogger {
    pub(crate) level: Level,
}

impl ConsoleLogger {
    pub(crate) fn touch() {
        EPOCH.get_or_init(Instant::now);
    }

    pub(crate) fn format_log_record(io: &mut (dyn Write + Send), record: &Record, no_color: bool) {
        let target = {
            if let Some(target_str) = record.target().split(':').last() {
                if let Some(line) = record.line() {
                    format!(" ({target_str}:{line})")
                } else {
                    format!(" ({target_str})")
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
            "[{:02}:{:02}:{:02}.{:03}] ({:x}) {:6} {}{}",
            hours,
            minutes,
            seconds,
            miliseconds,
            thread_id::get(),
            record.level(),
            record.args(),
            target
        );
        if no_color {
            let _ = writeln!(io, "{msg}");
        } else {
            let msg = match record.level() {
                Level::Trace | Level::Debug => msg.white(),
                Level::Info => msg.blue(),
                Level::Warn => msg.yellow(),
                Level::Error => msg.red(),
            };
            let _ = writeln!(io, "{msg}");
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
        ConsoleLogger::format_log_record(&mut io, record, false);
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
    }
}

pub(crate) struct FileLogger {
    sink: Mutex<File>,
}

impl FileLogger {
    pub(crate) fn new<T: AsRef<Path>>(path: T) -> io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            sink: Mutex::new(file),
        })
    }
}

impl log::Log for FileLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        // use the global log-level
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut sink = &*self.sink.lock().unwrap();
        ConsoleLogger::format_log_record(&mut sink, record, true);
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
    }
}
