// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This is the pre-compilation build script for the crate akd_quorum. Mainly it's used to compile
//! protobuf files into rust code prior to compilation.

// NOTE: build.rs documentation = https://doc.rust-lang.org/cargo/reference/build-scripts.html

extern crate protoc_rust;

/// The list of protobuf files to generate
const PROTOBUF_FILES: [&str; 1] = ["src/proto/inter-node"];

fn build_protobuf(file: &str) {
    // Tell Cargo that if the given files change, rerun this build script
    let proto_file = format!("{}.proto", file);
    println!("cargo:rerun-if-changed={}.rs", file);
    println!("cargo:rerun-if-changed={}.proto", file);

    // compile the file
    protoc_rust::run(protoc_rust::Args {
        out_dir: "src/proto",
        input: &[&proto_file],
        includes: &[],
        customize: protoc_rust::Customize {
            ..Default::default()
        },
    })
    .expect("protoc");
}

fn build_protobufs() {
    for file in PROTOBUF_FILES.iter() {
        build_protobuf(file);
    }
}

fn main() {
    build_protobufs();
}
