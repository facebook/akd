// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use colored::*;
use log::{Level, LevelFilter, Metadata, Record};

pub(crate) struct ConsoleLogger {
    pub(crate) level: Level,
}

impl ConsoleLogger {
    pub(crate) fn touch(&self) {
        println!();
    }
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!("{} - {}", record.level(), record.args());
            let msg = match record.level() {
                Level::Trace | Level::Debug => msg.white(),
                Level::Info => msg.blue(),
                Level::Warn => msg.yellow(),
                Level::Error => msg.red(),
            };
            println!("{}", msg);
        }
    }

    fn flush(&self) {}
}
