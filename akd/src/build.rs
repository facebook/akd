// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This is the pre-compilation build script for the crate `akd_client`. Mainly it's used to compile
//! protobuf files into rust code prior to compilation.

// NOTE: build.rs documentation = https://doc.rust-lang.org/cargo/reference/build-scripts.html

const PROTO_BASE_PATH: &str = "src/proto/raw";

/// The list of protobuf files to generate
const PROTOBUF_FILES: [&str; 1] = ["audit"];

fn build_protobuf(file: &str) {
    // Tell Cargo that if the given files change, rerun this build script
    let full_filename_without_ext = format!("{}/{}", PROTO_BASE_PATH, file);
    let proto_file = format!("{}.proto", full_filename_without_ext);
    println!("cargo:rerun-if-changed={}.rs", full_filename_without_ext);
    println!("cargo:rerun-if-changed={}", proto_file);

    // compile the file
    protobuf_codegen::Codegen::new()
        .pure()
        // // use protoc parser, (optional)
        // .protoc()
        // // Use `protoc-bin-vendored` bundled protoc command, optional.
        // .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        // All inputs and imports from the inputs must reside in `includes` directories.
        .includes([PROTO_BASE_PATH])
        // Inputs must reside in some of the include paths
        .input(&proto_file)
        // Specify output directory relative to Cargo output directory
        .out_dir(PROTO_BASE_PATH)
        .run_from_script();
}

fn build_protobufs() {
    for file in PROTOBUF_FILES.iter() {
        build_protobuf(file);
    }
}

fn main() {
    // If the feature is enabled, Cargo will set this env var prior to building
    match (
        std::env::var("CARGO_FEATURE_PROTOBUF"),
        std::env::var("CARGO_FEATURE_THISERROR"),
        std::env::var("CARGO_FEATURE_PUBLIC_AUDITING"),
    ) {
        (Ok(_), Ok(_), _) => {
            // feature is present, compile the protobuf files
            build_protobufs();
        }
        (_, _, Ok(_)) => {
            // feature is present, compile the protobuf files
            build_protobufs();
        }
        _ => {}
    }
}
