// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#[macro_use]
extern crate criterion;

use akd::append_only_zks::InsertMode;
use akd::storage::manager::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::{Azks, Node, NodeLabel};
use criterion::{BatchSize, Criterion};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

fn batch_insertion(c: &mut Criterion) {
    let num_initial_leaves = 10000;
    let num_inserted_leaves = 100000;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    // prepare node set for initial leaves
    let mut initial_node_set = vec![];
    for _ in 0..num_initial_leaves {
        let label = random_label(&mut rng);
        let mut input = [0u8; 32];
        rng.fill_bytes(&mut input);
        let hash = akd_core::hash::hash(&input);
        initial_node_set.push(Node { label, hash });
    }

    // prepare node set for batch insertion
    let mut node_set = vec![];
    for _ in 0..num_inserted_leaves {
        let label = random_label(&mut rng);
        let mut input = [0u8; 32];
        rng.fill_bytes(&mut input);
        let hash = akd_core::hash::hash(&input);
        node_set.push(Node { label, hash });
    }

    // benchmark batch insertion
    let id = format!(
        "Batch insertion ({} initial leaves, {} inserted leaves)",
        num_initial_leaves, num_inserted_leaves
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {
                let database = AsyncInMemoryDatabase::new();
                let db = StorageManager::new_no_cache(&database);
                runtime.block_on(db.begin_transaction());
                let mut azks = runtime.block_on(Azks::new(&db)).unwrap();

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

fn random_label(rng: &mut impl rand::Rng) -> NodeLabel {
    NodeLabel {
        label_val: rng.gen::<[u8; 32]>(),
        label_len: 256,
    }
}

criterion_group!(azks_benches, batch_insertion);
criterion_main!(azks_benches);
