// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

#[macro_use]
extern crate criterion;

mod common;

use akd::append_only_zks::InsertMode;
use akd::auditor;
use akd::storage::manager::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::NamedConfiguration;
use akd::{Azks, AzksElement, AzksValue, NodeLabel};
use criterion::{BatchSize, Criterion};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

bench_config!(batch_insertion);
fn batch_insertion<TC: NamedConfiguration>(c: &mut Criterion) {
    let num_initial_leaves = 1000;
    let num_inserted_leaves = 1000;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    // prepare node set for initial leaves
    let initial_node_set = gen_nodes(&mut rng, num_initial_leaves);

    // prepare node set for batch insertion
    let node_set = gen_nodes(&mut rng, num_inserted_leaves);

    // benchmark batch insertion
    let id = format!(
        "Batch insertion ({} initial leaves, {} inserted leaves) ({})",
        num_initial_leaves,
        num_inserted_leaves,
        TC::name(),
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {
                let database = AsyncInMemoryDatabase::new();
                let db = StorageManager::new(database, None, None, None);
                let mut azks = runtime.block_on(Azks::new::<TC, _>(&db)).unwrap();

                // create transaction object
                db.begin_transaction();

                // insert initial leaves as part of setup
                runtime
                    .block_on(azks.batch_insert_nodes::<TC, _>(
                        &db,
                        initial_node_set.clone(),
                        InsertMode::Directory,
                    ))
                    .unwrap();
                (azks, db, node_set.clone())
            },
            |(mut azks, db, node_set)| {
                runtime
                    .block_on(azks.batch_insert_nodes::<TC, _>(
                        &db,
                        node_set,
                        InsertMode::Directory,
                    ))
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

bench_config!(audit_verify);
fn audit_verify<TC: NamedConfiguration>(c: &mut Criterion) {
    let num_initial_leaves = 10000;
    let num_inserted_leaves = 10000;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    // prepare node sets for start and end epochs
    let initial_node_set = gen_nodes(&mut rng, num_initial_leaves);
    let node_set = gen_nodes(&mut rng, num_inserted_leaves);

    // benchmark audit verify
    let id = format!(
        "Audit verify (epoch 1: {} leaves, epoch 2: {} leaves) ({})",
        num_initial_leaves,
        num_inserted_leaves,
        TC::name(),
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {
                let database = AsyncInMemoryDatabase::new();
                let db = StorageManager::new(database, None, None, None);
                let mut azks = runtime.block_on(Azks::new::<TC, _>(&db)).unwrap();

                // epoch 1
                runtime
                    .block_on(azks.batch_insert_nodes::<TC, _>(
                        &db,
                        initial_node_set.clone(),
                        InsertMode::Directory,
                    ))
                    .unwrap();

                let start_hash = runtime.block_on(azks.get_root_hash::<TC, _>(&db)).unwrap();

                // epoch 2
                runtime
                    .block_on(azks.batch_insert_nodes::<TC, _>(
                        &db,
                        node_set.clone(),
                        InsertMode::Directory,
                    ))
                    .unwrap();

                let end_hash = runtime.block_on(azks.get_root_hash::<TC, _>(&db)).unwrap();
                let proof = runtime
                    .block_on(azks.get_append_only_proof::<TC, _>(&db, 1, 2))
                    .unwrap();

                (start_hash, end_hash, proof)
            },
            |(start_hash, end_hash, proof)| {
                runtime
                    .block_on(auditor::audit_verify::<TC>(
                        vec![start_hash, end_hash],
                        proof,
                    ))
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

bench_config!(audit_generate);
fn audit_generate<TC: NamedConfiguration>(c: &mut Criterion) {
    let num_leaves = 10000;
    let num_epochs = 100;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    let database = AsyncInMemoryDatabase::new();
    let db = StorageManager::new(database, None, None, None);
    let mut azks = runtime.block_on(Azks::new::<TC, _>(&db)).unwrap();

    // publish 10 epochs
    for _epoch in 0..num_epochs {
        let node_set = gen_nodes(&mut rng, num_leaves);
        runtime
            .block_on(azks.batch_insert_nodes::<TC, _>(&db, node_set, InsertMode::Directory))
            .unwrap();
    }
    let epoch = azks.get_latest_epoch();

    // benchmark audit verify
    let id = format!(
        "Audit proof generation. {num_leaves} leaves over {num_epochs} epochs ({})",
        TC::name()
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {},
            |_| {
                let _proof = runtime
                    .block_on(azks.get_append_only_proof::<TC, _>(&db, epoch - 1, epoch))
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
            let value = AzksValue(rng.gen::<[u8; 32]>());
            AzksElement { label, value }
        })
        .collect()
}

group_config!(azks_benches, batch_insertion, audit_verify, audit_generate);

fn main() {
    // NOTE(new_config): Add a new configuration here

    #[cfg(feature = "whatsapp_v1")]
    azks_benches_whatsapp_v1_config();
    #[cfg(feature = "experimental")]
    azks_benches_experimental_config();

    Criterion::default().configure_from_args().final_summary();
}
