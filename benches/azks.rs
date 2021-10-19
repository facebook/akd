// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand::{prelude::ThreadRng, thread_rng, RngCore};
use seemless::{append_only_zks::Azks, node_state::NodeLabel, storage::Storage};
use std::time::{Duration, Instant};
use winter_crypto::{hashers::Blake3_256, Hasher};
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;
type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;

use lazy_static::lazy_static;
use seemless::errors::StorageError;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    static ref HASHMAP: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Debug)]
pub(crate) struct InMemoryDb(HashMap<String, String>);

impl Storage for InMemoryDb {
    fn set(pos: String, value: String) -> Result<(), StorageError> {
        let mut hashmap = HASHMAP.lock().unwrap();
        hashmap.insert(pos, value);
        Ok(())
    }

    fn get(pos: String) -> Result<String, StorageError> {
        let hashmap = HASHMAP.lock().unwrap();
        hashmap
            .get(&pos)
            .map(|v| v.clone())
            .ok_or(StorageError::GetError)
    }
}

fn single_insertion(c: &mut Criterion) {
    let num_nodes = 1000;

    let mut rng: ThreadRng = thread_rng();

    let mut azks1 = Azks::<Blake3, InMemoryDb>::new(&mut rng).unwrap();
    let mut insertion_set = Vec::<(NodeLabel, Blake3Digest)>::new();
    for _ in 0..num_nodes {
        let node = NodeLabel::random(&mut rng);
        let mut input = [0u8; 32];
        rng.fill_bytes(&mut input);
        let val = Blake3::hash(&input);
        insertion_set.push((node, val));
        azks1.insert_leaf(node, val).unwrap();
    }
    c.bench_function("single insertion into tree with 1000 nodes", move |b| {
        b.iter(|| {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let val = Blake3::hash(&input);

            let start = Instant::now();
            azks1.insert_leaf(node, val).unwrap();
        })
    });
}

criterion_group!(azks_benches, single_insertion);
criterion_main!(azks_benches);
