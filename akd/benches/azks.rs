// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#[macro_use]
extern crate criterion;

use akd::append_only_zks::InsertMode;
use akd::auditor;
use akd::storage::manager::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::{Azks, AzksElement, NodeLabel};
use criterion::{BatchSize, Criterion};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn batch_insertion(c: &mut Criterion) {
    let num_initial_leaves = 10000;
    let num_inserted_leaves = 100000;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    // prepare node set for initial leaves
    let initial_node_set = gen_nodes(&mut rng, num_initial_leaves);

    // prepare node set for batch insertion
    let node_set = gen_nodes(&mut rng, num_inserted_leaves);

    // benchmark batch insertion
    let id = format!(
        "Batch insertion ({} initial leaves, {} inserted leaves)",
        num_initial_leaves, num_inserted_leaves
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {
                let database = AsyncInMemoryDatabase::new();
                let db = StorageManager::new(database, None, None, None);
                let mut azks = runtime.block_on(Azks::new(&db)).unwrap();

                // create transaction object
                db.begin_transaction();

                // insert initial leaves as part of setup
                runtime
                    .block_on(azks.batch_insert_nodes(
                        &db,
                        initial_node_set.clone(),
                        InsertMode::Directory,
                    ))
                    .unwrap();
                (azks, db, node_set.clone())
            },
            |(mut azks, db, node_set)| {
                runtime
                    .block_on(azks.batch_insert_nodes(&db, node_set, InsertMode::Directory))
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

fn audit_verify(c: &mut Criterion) {
    let num_initial_leaves = 10000;
    let num_inserted_leaves = 10000;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    // prepare node sets for start and end epochs
    let initial_node_set = gen_nodes(&mut rng, num_initial_leaves);
    let node_set = gen_nodes(&mut rng, num_inserted_leaves);

    // benchmark audit verify
    let id = format!(
        "Audit verify (epoch 1: {} leaves, epoch 2: {} leaves)",
        num_initial_leaves, num_inserted_leaves
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {
                let database = AsyncInMemoryDatabase::new();
                let db = StorageManager::new(database, None, None, None);
                let mut azks = runtime.block_on(Azks::new(&db)).unwrap();

                // epoch 1
                runtime
                    .block_on(azks.batch_insert_nodes(
                        &db,
                        initial_node_set.clone(),
                        InsertMode::Directory,
                    ))
                    .unwrap();

                let start_hash = runtime.block_on(azks.get_root_hash(&db)).unwrap();

                // epoch 2
                runtime
                    .block_on(azks.batch_insert_nodes(&db, node_set.clone(), InsertMode::Directory))
                    .unwrap();

                let end_hash = runtime.block_on(azks.get_root_hash(&db)).unwrap();
                let proof = runtime
                    .block_on(azks.get_append_only_proof(&db, 1, 2))
                    .unwrap();

                (start_hash, end_hash, proof)
            },
            |(start_hash, end_hash, proof)| {
                runtime
                    .block_on(auditor::audit_verify(vec![start_hash, end_hash], proof))
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

fn gen_nodes(rng: &mut impl Rng, num_nodes: usize) -> Vec<AzksElement> {
    (0..num_nodes)
        .map(|_| {
            let label = NodeLabel {
                label_val: rng.gen::<[u8; 32]>(),
                label_len: 256,
            };
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let value = akd_core::hash::hash(&input);
            AzksElement { label, value }
        })
        .collect()
}

criterion_group!(azks_benches, batch_insertion, audit_verify);
criterion_main!(azks_benches);
