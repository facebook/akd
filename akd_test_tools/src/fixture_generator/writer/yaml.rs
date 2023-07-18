// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains an implementor of the Writer trait for the YAML format.

use std::io::Write;

use serde::Serialize;

use crate::fixture_generator::{writer::Writer, YAML_SEPARATOR};

/// YAML format writer.
pub(crate) struct YamlWriter<T: Write> {
    out: T,
}

impl<T: Write> YamlWriter<T> {
    pub fn new(out: T) -> Self {
        Self { out }
    }
}

impl<T: Write> Writer for YamlWriter<T> {
    fn write_object(&mut self, object: impl Serialize) {
        writeln!(self.out, "{}", YAML_SEPARATOR).unwrap();
        serde_yaml::to_writer(&mut self.out, &object).unwrap();
    }

    fn write_comment(&mut self, comment: &str) {
        let lines = comment.split('\n');
        lines.for_each(|line| writeln!(self.out, "# {line}").unwrap());
    }

    fn write_line(&mut self) {
        writeln!(self.out).unwrap()
    }

    fn flush(&mut self) {
        self.out.flush().unwrap();
    }
}
