// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use rand::{prelude::ThreadRng, thread_rng, RngCore};
use seemless::{append_only_zks::Azks, node_state::NodeLabel, storage::Storage};
use winter_crypto::{hashers::Blake3_256, Hasher};
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;

use lazy_static::lazy_static;
use seemless::errors::StorageError;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    static ref HASHMAP: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref STATS: Mutex<HashMap<String, usize>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Debug)]
pub(crate) struct InMemoryDb(HashMap<String, String>);

impl Storage for InMemoryDb {
    fn set(pos: String, value: String) -> Result<(), StorageError> {
        let mut stats = STATS.lock().unwrap();
        let calls_to_set = stats.entry(String::from("calls_to_set")).or_insert(0);
        *calls_to_set += 1;

        let mut hashmap = HASHMAP.lock().unwrap();
        hashmap.insert(pos, value);

        Ok(())
    }

    fn get(pos: String) -> Result<String, StorageError> {
        let mut stats = STATS.lock().unwrap();
        let calls_to_get = stats.entry(String::from("calls_to_get")).or_insert(0);
        *calls_to_get += 1;

        let hashmap = HASHMAP.lock().unwrap();
        hashmap
            .get(&pos)
            .map(|v| v.clone())
            .ok_or(StorageError::GetError)
    }
}

fn clear_stats() {
    let mut stats = STATS.lock().unwrap();
    stats.clear();
}

fn print_stats() {
    println!("Statistics collected:");
    println!("---------------------");

    let stats = STATS.lock().unwrap();
    for (key, val) in stats.iter() {
        println!("{}: {}", key, val);
    }

    println!("---------------------");
}

fn print_hashmap_distribution() {
    println!("Hashmap distrubtion of length of entries (in bytes):");
    println!("---------------------");

    let hashmap = HASHMAP.lock().unwrap();

    let mut distribution: HashMap<usize, usize> = HashMap::new();

    for (_, val) in hashmap.iter() {
        let len = val.len();

        let counter = distribution.entry(len).or_insert(0);
        *counter += 1;
    }

    let mut sorted_keys: Vec<usize> = distribution.keys().cloned().collect();
    sorted_keys.sort();

    for key in sorted_keys {
        println!("{}: {}", key, distribution[&key]);
    }
    println!("---------------------");
    println!("HashMap number of elements: {}", hashmap.len());
    println!("---------------------");
}

fn main() {
    let num_nodes = 200;

    let mut rng: ThreadRng = thread_rng();

    let mut azks1 = Azks::<Blake3, InMemoryDb>::new(&mut rng).unwrap();

    for _ in 0..num_nodes {
        let node = NodeLabel::random(&mut rng);
        let mut input = [0u8; 32];
        rng.fill_bytes(&mut input);
        let val = Blake3::hash(&input);
        azks1.insert_leaf(node, val).unwrap();
    }

    let node = NodeLabel::random(&mut rng);
    let mut input = [0u8; 32];
    rng.fill_bytes(&mut input);
    let val = Blake3::hash(&input);

    // Start measurement
    clear_stats();
    azks1.insert_leaf(node, val).unwrap();

    print_hashmap_distribution();
    print_stats();
}
