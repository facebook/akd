// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Tests basic reader behavior.

use std::env;
use std::fs::File;

use assert_fs::fixture::{FileWriteStr, NamedTempFile, TempDir};
use clap::Parser;

use crate::fixture_generator::generator;
use crate::fixture_generator::parser::Args;
use crate::fixture_generator::reader::yaml::YamlFileReader;
use crate::fixture_generator::reader::Reader;

#[tokio::test]
async fn test_read() {
    // generate a temp fixture file
    let file = TempDir::new().unwrap().with_file_name("test.yaml");
    let args = Args::parse_from(vec![
        env!("CARGO_CRATE_NAME"),
        "--epochs",
        "10",
        "--capture_deltas",
        "10",
        "--capture_states",
        "9",
        "10",
        "--out",
        &format!("{}", file.display()),
    ]);
    generator::generate(args).await;

    // initialize reader
    let mut reader = YamlFileReader::new(File::open(file).unwrap());

    // objects can be read in any order
    assert!(reader.read_state(10).is_some());
    assert!(reader.read_delta(10).is_some());
    assert!(reader.read_state(9).is_some());
    assert!(reader.read_metadata().is_some());

    // reading a non-existent object will return a None
    assert!(reader.read_delta(9).is_none());
    assert!(reader.read_state(11).is_none());

    // reading an already read object is OK
    assert!(reader.read_metadata().is_some());
}

#[tokio::test]
#[should_panic]
async fn test_read_invalid_file() {
    // create an invalid file with no YAML separators
    let file = NamedTempFile::new("invalid.yaml").unwrap();
    file.write_str("a\nb\nc\n").unwrap();

    // initialize reader
    let mut reader = YamlFileReader::new(File::open(file).unwrap());

    // reading any object will cause a panic
    reader.read_metadata();
}
