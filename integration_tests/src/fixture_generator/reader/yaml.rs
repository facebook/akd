// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains an implementor of the Reader trait for the YAML format.

use std::fs::File;
use std::io::{BufRead, BufReader, Lines, Seek, SeekFrom};
use std::iter::Peekable;

use serde::de::DeserializeOwned;

use crate::fixture_generator::generator::{Delta, Metadata, State};
use crate::fixture_generator::reader::Reader;

const YAML_SEPARATOR: &str = "---";

/// YAML format file reader.
pub struct YamlFileReader {
    file: File,
    index: u32,
    buffer: Peekable<Lines<BufReader<File>>>,
}

impl YamlFileReader {
    pub fn new(file: File) -> Self {
        let index = 0;
        let buffer = Self::buffer(&file);
        Self {
            file,
            index,
            buffer,
        }
    }

    // Instantiates a new buffer for a given file.
    fn buffer(file: &File) -> Peekable<Lines<BufReader<File>>> {
        let mut file_ref_copy = file.try_clone().unwrap();
        file_ref_copy.seek(SeekFrom::Start(0)).unwrap();

        BufReader::new(file_ref_copy).lines().peekable()
    }

    // Returns the next YAML "doc" in the file, looping back to the start of the
    // file if EOF is encountered.
    fn next_doc(&mut self) -> String {
        // find start of doc
        loop {
            match self.buffer.peek() {
                Some(Ok(sep)) if sep == YAML_SEPARATOR => {
                    self.buffer.next();
                    break;
                }
                Some(Ok(_)) => {
                    self.buffer.next();
                }
                None => panic!("EOF encountered while looking for start of YAML doc"),
                Some(Err(err)) => panic!("Error parsing YAML file: {}", err),
            }
        }

        // collect lines until end of doc
        let mut doc = String::new();
        loop {
            match self.buffer.peek() {
                Some(Ok(sep)) if sep == YAML_SEPARATOR => {
                    self.index += 1;
                    return doc;
                }
                Some(Ok(line)) => {
                    doc.push_str(&format!("{}\n", line));
                    self.buffer.next();
                }
                None => {
                    self.index = 0;
                    self.buffer = Self::buffer(&self.file);
                    return doc;
                }
                Some(Err(err)) => panic!("Error parsing YAML file: {}", err),
            }
        }
    }

    // Reads an object from the YAML file, utilizing validate_fun to validate
    // the object before returning it.
    fn read_impl<T: DeserializeOwned, F: Fn(&T) -> bool>(&mut self, validate_fun: F) -> Option<T> {
        let start = self.index;
        loop {
            if let Ok(object) = serde_yaml::from_str::<T>(&self.next_doc()) {
                if validate_fun(&object) {
                    return Some(object);
                }
            }
            // exit if all docs have been checked
            if self.index == start {
                return None;
            }
        }
    }
}

impl Reader for YamlFileReader {
    fn read_metadata(&mut self) -> Option<Metadata> {
        self.read_impl(|_: &Metadata| true)
    }

    fn read_state(&mut self, epoch: u32) -> Option<State> {
        self.read_impl(|state: &State| state.epoch == epoch)
    }

    fn read_delta(&mut self, epoch: u32) -> Option<Delta> {
        self.read_impl(|delta: &Delta| delta.epoch == epoch)
    }
}
