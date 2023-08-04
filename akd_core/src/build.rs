// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This is the pre-compilation build script for the crate `akd_core`. Mainly it's used to compile
//! protobuf files into rust code prior to compilation.

// NOTE: build.rs documentation = https://doc.rust-lang.org/cargo/reference/build-scripts.html

/// The shared-path for all protobuf specifications
const PROTOBUF_BASE_DIRECTORY: &str = "src/proto/specs";
/// The list of protobuf files to generate inside PROBUF_BASE_DIRECTORY
const PROTOBUF_FILES: [&str; 1] = ["types"];
/// The output directory in the cargo build folder to emit the generated sources to
const PROTOS_OUTPUT_DIR: &str = "protos";

fn build_protobufs() {
    let mut protobuf_files = Vec::with_capacity(PROTOBUF_FILES.len());

    for file in PROTOBUF_FILES.iter() {
        let proto_file = format!("{PROTOBUF_BASE_DIRECTORY}/{file}.proto");
        println!("cargo:rerun-if-changed={proto_file}");
        protobuf_files.push(proto_file);
    }

    // Code generator writes to the output directory
    protobuf_codegen::Codegen::new()
        .pure()
        .includes([PROTOBUF_BASE_DIRECTORY])
        .inputs(&protobuf_files)
        .cargo_out_dir(PROTOS_OUTPUT_DIR)
        .run_from_script();
}

fn main() {
    // compile the spec files into Rust code
    build_protobufs();
}
