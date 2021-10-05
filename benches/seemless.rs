// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand::{CryptoRng, RngCore, rngs::OsRng};
use seemless::{append_only_zks::Azks, node_state::NodeLabel, storage::Storage};
use std::time::{Duration, Instant};
use winter_crypto::{hashers::Blake3_256, Hasher};
use winter_math::fields::f128::BaseElement;
use seemless::seemless_directory::{SeemlessDirectory, Username, Values};

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

fn create_usernames_and_values(
    num_insertions: usize,
    rng: &mut OsRng,
) -> Vec<(Username, Values)> {
    let mut updates = Vec::<(Username, Values)>::new();
    for _ in 0..num_insertions {
        let username = Username::random(rng);
        let val = Values::random(rng);
        updates.push((username, val));
    }
    updates
}

fn publish(c: &mut Criterion) {
    let num_init_insertions = 30000;

    let mut seemless_dir =
        SeemlessDirectory::<InMemoryDb, Blake3_256<BaseElement>>::new().unwrap();

    // Populating the updates
    let mut rng = rand::rngs::OsRng;
    let updates = create_usernames_and_values(num_init_insertions, &mut rng);

    // Publishing updated set with an initial set of users
    seemless_dir.publish(updates.clone()).unwrap();

    let num_new_insertions = 10;


    c.bench_function(&format!("inserting {} new users into a directory of {} existing users", num_new_insertions, num_init_insertions), move |b| {
        b.iter_custom(|iters| {
            let mut total_elapsed = Duration::ZERO;
            for _ in 0..iters {
                let new_updates = create_usernames_and_values(num_new_insertions, &mut rng);
                let start = Instant::now();
                seemless_dir.publish(new_updates.clone()).unwrap();
                total_elapsed += start.elapsed();
            }
            total_elapsed
        })
    });
}

fn lookup_verify(c: &mut Criterion) {
    let num_init_insertions = 30000;

    let mut seemless_dir =
        SeemlessDirectory::<InMemoryDb, Blake3_256<BaseElement>>::new().unwrap();

    // Populating the updates
    let mut rng = rand::rngs::OsRng;
    let updates = create_usernames_and_values(num_init_insertions, &mut rng);

    // Publishing updated set with an initial set of users
    seemless_dir.publish(updates.clone()).unwrap();


    c.bench_function(&format!("lookup into a directory of {} existing users", num_init_insertions), move |b| {
        b.iter_custom(|iters| {
            let mut total_elapsed = Duration::ZERO;
            for _ in 0..iters {
                // Get a new lookup proof for the current user
                let new_lookup_proof = seemless_dir.lookup(updates.clone()[0].0.clone()).unwrap();
                let start = Instant::now();
                // Verify this lookup proof
                seemless_dir
                .lookup_verify(updates.clone()[0].0.clone(), new_lookup_proof)
                .unwrap();
                total_elapsed += start.elapsed();
            }
            total_elapsed
        })
    });
}

criterion_group!(seemless_benches, publish, lookup_verify);
criterion_main!(seemless_benches);
