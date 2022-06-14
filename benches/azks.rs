// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#[macro_use]
extern crate criterion;

use akd::{append_only_zks::Azks, node_state::Node, node_state::NodeLabel};
use criterion::Criterion;
use rand::{prelude::ThreadRng, thread_rng, RngCore};
use std::time::Instant;
use winter_crypto::{hashers::Blake3_256, Hasher};
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;
type InMemoryDb = akd::storage::memory::AsyncInMemoryDatabase;

fn single_insertion(c: &mut Criterion) {
    let num_nodes = 1000;

    let mut rng: ThreadRng = thread_rng();

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let db = InMemoryDb::new();

    let mut azks1 = runtime.block_on(Azks::new::<_, Blake3>(&db)).unwrap();
    for _ in 0..num_nodes {
        let label = NodeLabel::random(&mut rng);
        let mut input = [0u8; 32];
        rng.fill_bytes(&mut input);
        let hash = Blake3::hash(&input);
        runtime
            .block_on(azks1.insert_leaf::<_, Blake3>(&db, Node::<Blake3> { hash, label }, 1))
            .unwrap();
    }

    c.bench_function("single insertion into tree with 1000 nodes", move |b| {
        b.iter(|| {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3::hash(&input);

            let _start = Instant::now();
            runtime
                .block_on(azks1.insert_leaf::<_, Blake3>(&db, Node::<Blake3> { hash, label }, 2))
                .unwrap();
        })
    });
}

criterion_group!(azks_benches, single_insertion);
criterion_main!(azks_benches);
