// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Criterion benchmark functions for key directory implementations.

use super::BenchmarkSetup;
use crate::traits::KeyDirectory;
use criterion::{BatchSize, Criterion};

/// Register publish benchmarks.
pub fn bench_publish<S: BenchmarkSetup>(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let num_entries = 1000;
    let id = format!("KD publish ({} entries) [{}]", num_entries, S::name());
    c.bench_function(&id, |b| {
        b.iter_batched(
            || {
                let dir = runtime.block_on(S::create_directory());
                let data = S::generate_test_data(num_entries, 42);
                (dir, data)
            },
            |(dir, data)| {
                runtime.block_on(dir.publish(data)).unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

/// Register lookup benchmarks.
pub fn bench_lookup<S: BenchmarkSetup>(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let num_entries = 1000;
    let id = format!("KD lookup ({} entries) [{}]", num_entries, S::name());
    c.bench_function(&id, |b| {
        b.iter_batched(
            || {
                let dir = runtime.block_on(S::create_directory());
                let data = S::generate_test_data(num_entries, 42);
                runtime.block_on(dir.publish(data.clone())).unwrap();
                let label = data[0].0.clone();
                (dir, label)
            },
            |(dir, label)| {
                runtime.block_on(dir.lookup(label)).unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

/// Register lookup verification benchmarks.
///
/// The `proof_size_fn` parameter computes the size of a lookup proof in bytes.
/// This avoids orphan-rule issues by letting the caller provide the sizing logic.
pub fn bench_lookup_verify<S, F>(c: &mut Criterion, proof_size_fn: F)
where
    S: BenchmarkSetup,
    F: Fn(&<S::Directory as KeyDirectory>::LookupProof) -> usize,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let num_entries = 1000;
    let id = format!("KD lookup_verify ({} entries) [{}]", num_entries, S::name());
    c.bench_function(&id, |b| {
        b.iter_batched(
            || {
                let dir = runtime.block_on(S::create_directory());
                let data = S::generate_test_data(num_entries, 42);
                runtime.block_on(dir.publish(data.clone())).unwrap();
                let label = data[0].0.clone();
                let (proof, epoch_hash) = runtime.block_on(dir.lookup(label.clone())).unwrap();
                let pk = runtime.block_on(dir.get_public_key()).unwrap();

                // Print proof size on first iteration
                eprintln!("  Lookup proof size: {} bytes", proof_size_fn(&proof));

                (pk, epoch_hash, label, proof)
            },
            |(pk, epoch_hash, label, proof)| {
                <S::Directory as KeyDirectory>::lookup_verify(
                    &pk,
                    epoch_hash.hash(),
                    epoch_hash.epoch(),
                    label,
                    proof,
                )
                .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

/// Register key history benchmarks.
pub fn bench_key_history<S: BenchmarkSetup>(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let num_entries = 100;
    let num_epochs = 5;
    let id = format!(
        "KD key_history ({} entries, {} epochs) [{}]",
        num_entries,
        num_epochs,
        S::name()
    );
    c.bench_function(&id, |b| {
        b.iter_batched(
            || {
                let dir = runtime.block_on(S::create_directory());
                let label = {
                    let data = S::generate_test_data(num_entries, 42);
                    let label = data[0].0.clone();
                    runtime.block_on(dir.publish(data)).unwrap();
                    label
                };
                // Publish additional epochs with updated values
                for epoch in 1..num_epochs {
                    let data = S::generate_test_data(num_entries, 42 + epoch as u64);
                    runtime.block_on(dir.publish(data)).unwrap();
                }
                (dir, label)
            },
            |(dir, label)| {
                let params = Default::default();
                runtime.block_on(dir.key_history(&label, params)).unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

/// Register audit proof generation benchmarks.
pub fn bench_audit<S: BenchmarkSetup>(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let num_entries = 1000;
    let id = format!("KD audit ({} entries) [{}]", num_entries, S::name());
    c.bench_function(&id, |b| {
        b.iter_batched(
            || {
                let dir = runtime.block_on(S::create_directory());
                let data1 = S::generate_test_data(num_entries, 42);
                runtime.block_on(dir.publish(data1)).unwrap();
                let data2 = S::generate_test_data(num_entries, 43);
                runtime.block_on(dir.publish(data2)).unwrap();
                dir
            },
            |dir| {
                runtime.block_on(dir.audit(1, 2)).unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

/// Register audit verification benchmarks.
pub fn bench_audit_verify<S: BenchmarkSetup>(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let num_entries = 1000;
    let id = format!("KD audit_verify ({} entries) [{}]", num_entries, S::name());
    c.bench_function(&id, |b| {
        b.iter_batched(
            || {
                let dir = runtime.block_on(S::create_directory());
                let data1 = S::generate_test_data(num_entries, 42);
                let eh1 = runtime.block_on(dir.publish(data1)).unwrap();
                let data2 = S::generate_test_data(num_entries, 43);
                let eh2 = runtime.block_on(dir.publish(data2)).unwrap();
                let proof = runtime.block_on(dir.audit(1, 2)).unwrap();
                (vec![eh1.hash(), eh2.hash()], proof)
            },
            |(hashes, proof)| {
                runtime
                    .block_on(<S::Directory as KeyDirectory>::audit_verify(hashes, proof))
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}
