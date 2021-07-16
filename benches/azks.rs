// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use crypto::{hashers::Blake3_256, Hasher};
use math::fields::f128::BaseElement;
use rand::{prelude::ThreadRng, thread_rng, RngCore};
use seemless::{append_only_zks::Azks, node_state::NodeLabel};
use std::time::{Duration, Instant};

type Blake3 = Blake3_256<BaseElement>;

fn single_insertion(c: &mut Criterion) {
    let num_nodes = 1000;

    let mut rng: ThreadRng = thread_rng();

    let mut azks1 = Azks::<Blake3>::new();

    for _ in 0..num_nodes {
        let node = NodeLabel::random(&mut rng);
        let mut input = [0u8; 32];
        rng.fill_bytes(&mut input);
        let val = Blake3::hash(&input);
        azks1.insert_leaf(node, val).unwrap();
    }

    c.bench_function("single insertion into tree with 1000 nodes", move |b| {
        b.iter_custom(|iters| {
            let mut total_elapsed = Duration::ZERO;
            for _ in 0..iters {
                let node = NodeLabel::random(&mut rng);
                let mut input = [0u8; 32];
                rng.fill_bytes(&mut input);
                let val = Blake3::hash(&input);

                let start = Instant::now();
                azks1.insert_leaf(node, val).unwrap();
                total_elapsed = start.elapsed();
            }
            total_elapsed
        })
    });
}

criterion_group!(azks_benches, single_insertion);
criterion_main!(azks_benches);
