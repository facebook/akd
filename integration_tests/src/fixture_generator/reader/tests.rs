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
use crate::fixture_generator::reader::{Reader, ReaderError};

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
    let mut reader = YamlFileReader::new(File::open(file).unwrap()).unwrap();

    // objects can be read in any order
    assert!(reader.read_state(10).is_ok());
    assert!(reader.read_delta(10).is_ok());
    assert!(reader.read_state(9).is_ok());
    assert!(reader.read_metadata().is_ok());

    // reading a non-existent object will return a NotFound error
    assert_eq!(Err(ReaderError::NotFound), reader.read_delta(9));
    assert_eq!(Err(ReaderError::NotFound), reader.read_state(11));

    // reading an already read object is OK
    assert!(reader.read_metadata().is_ok());
}

#[tokio::test]
async fn test_read_invalid_format() {
    // create an invalid file with no YAML separators
    let file = NamedTempFile::new("invalid.yaml").unwrap();
    file.write_str("a\nb\nc\n").unwrap();

    // initialize reader
    let mut reader = YamlFileReader::new(File::open(file).unwrap()).unwrap();

    // reading any object will return a Format error
    assert!(matches!(
        reader.read_metadata(),
        Err(ReaderError::Format(_))
    ));
    assert!(matches!(reader.read_state(0), Err(ReaderError::Format(_))));
}
