// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use rand::prelude::IteratorRandom;
use rand::{prelude::ThreadRng, thread_rng};
use seemless::seemless_directory::{SeemlessDirectory, Username, Values};
use seemless::storage::Storage;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

use lazy_static::lazy_static;
use seemless::errors::StorageError;
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    static ref DB: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref CACHE: Mutex<HashMap<String, String>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    static ref STATS: Mutex<HashMap<String, usize>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Debug)]
pub(crate) struct InMemoryDbWithCache(HashMap<String, String>);

impl Storage for InMemoryDbWithCache {
    fn set(pos: String, value: String) -> Result<(), StorageError> {
        let mut stats = STATS.lock().unwrap();
        let calls_to_cache_set = stats.entry(String::from("calls_to_cache_set")).or_insert(0);
        *calls_to_cache_set += 1;

        let mut cache = CACHE.lock().unwrap();
        cache.insert(pos.clone(), value.clone());

        Ok(())
    }

    fn get(pos: String) -> Result<String, StorageError> {
        let mut stats = STATS.lock().unwrap();

        let cache = &mut CACHE.lock().unwrap();
        let calls_to_cache_get = stats.entry(String::from("calls_to_cache_get")).or_insert(0);
        *calls_to_cache_get += 1;

        match cache.get(&pos) {
            Some(value) => Ok(value.clone()),
            None => {
                let calls_to_db_get = stats.entry(String::from("calls_to_db_get")).or_insert(0);
                *calls_to_db_get += 1;

                let db = DB.lock().unwrap();
                let value = db
                    .get(&pos)
                    .map(|v| v.clone())
                    .ok_or(StorageError::GetError)?;

                cache.insert(pos, value.clone());
                Ok(value)
            }
        }
    }
}

fn clear_stats() {
    // Flush cache to db

    let mut cache = CACHE.lock().unwrap();

    let mut db = DB.lock().unwrap();
    for (key, val) in cache.iter() {
        db.insert(key.clone(), val.clone());
    }

    cache.clear();

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
    println!("Cache distribution of length of entries (in bytes):");
    println!("---------------------");

    let cache = CACHE.lock().unwrap();

    let mut distribution: HashMap<usize, usize> = HashMap::new();

    for (_, val) in cache.iter() {
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
    println!("Cache number of elements: {}", cache.len());
    println!("---------------------");
}

fn create_usernames_and_values(
    num_insertions: usize,
    mut rng: ThreadRng,
) -> Vec<(Username, Values)> {
    let mut updates = Vec::<(Username, Values)>::new();
    for _ in 0..num_insertions {
        let username = Username::random(&mut rng);
        let val = Values::random(&mut rng);
        updates.push((username, val));
    }
    updates
}

fn create_random_subset_of_existing_users(
    existing_users: Vec<Username>,
    subset_size: usize,
    mut rng: ThreadRng,
) -> Vec<(Username, Values)> {
    let mut user_subset = Vec::<(Username, Values)>::new();
    let mut actual_subset_size = subset_size;
    if existing_users.len() < subset_size {
        actual_subset_size = existing_users.len();
    }
    let sample = existing_users
        .iter()
        .choose_multiple(&mut rng, actual_subset_size);
    for i in 0..actual_subset_size {
        let username = sample[i].clone();
        let val = Values::random(&mut rng);
        user_subset.push((username, val));
    }
    user_subset
}

fn main() {
    let num_init_insertions = 50;

    let mut existing_usernames = Vec::<Username>::new();

    let mut seemless_dir =
        SeemlessDirectory::<InMemoryDbWithCache, Blake3_256<BaseElement>>::new().unwrap();

    // Populating the updates
    let rng: ThreadRng = thread_rng();
    let mut updates = create_usernames_and_values(num_init_insertions, rng);

    // Publishing updated set with an initial set of users
    seemless_dir.publish(updates.clone()).unwrap();

    let mut new_usernames = updates
        .clone()
        .iter()
        .map(|x| x.0.clone())
        .collect::<Vec<Username>>();
    existing_usernames.append(&mut new_usernames);

    let num_new_insertions = 10;
    let rng: ThreadRng = thread_rng();
    updates = create_usernames_and_values(num_new_insertions, rng);
    println!("*********************************************************************************");
    println!(
        "* Measurements for inserting {} new users into a directory of {} existing users *",
        num_new_insertions, num_init_insertions
    );
    println!("*********************************************************************************");
    // Publish measurement
    clear_stats();
    seemless_dir.publish(updates.clone()).unwrap();

    print_hashmap_distribution();
    print_stats();
    new_usernames = updates
        .clone()
        .iter()
        .map(|x| x.0.clone())
        .collect::<Vec<Username>>();
    existing_usernames.append(&mut new_usernames);

    let new_epochs = 5;
    // Adding a few new epochs and updating keys for some users
    for _ in 0..new_epochs {
        let num_new_insertions = 10;
        let num_updates = 10;
        let rng: ThreadRng = thread_rng();
        let mut new_users = create_usernames_and_values(num_new_insertions, rng);
        let rng: ThreadRng = thread_rng();
        updates = create_random_subset_of_existing_users(existing_usernames.clone(), num_updates, rng);
        updates.append(&mut new_users);
        seemless_dir.publish(updates.clone()).unwrap();
        new_usernames = new_users
        .clone()
        .iter()
        .map(|x| x.0.clone())
        .collect::<Vec<Username>>();
        existing_usernames.append(&mut new_usernames);

    }

    let num_lookups = 10;
    let rng: ThreadRng = thread_rng();
    let lookup_set =
        create_random_subset_of_existing_users(existing_usernames.clone(), num_lookups, rng);
    println!("******************************************************************************************************");
    println!("* Measurements for looking up and verifying lookups for {} users in a directory of {} existing users *", num_lookups, existing_usernames.len());
    println!("*****************************************************************************************************");
    // Lookup and verification of lookup measurement
    clear_stats();

    for i in 0..num_lookups {
        // Get a new lookup proof for the current user
        let new_lookup_proof = seemless_dir.lookup(lookup_set[i].0.clone()).unwrap();
        // Verify this lookup proof
        seemless_dir
            .lookup_verify(lookup_set[i].0.clone(), new_lookup_proof)
            .unwrap();
    }

    print_hashmap_distribution();
    print_stats();

    let num_key_history = 10;
    let rng: ThreadRng = thread_rng();
    let key_history_set =
        create_random_subset_of_existing_users(existing_usernames.clone(), num_key_history, rng);
    println!("******************************************************************************************************");
    println!("* Measurements for running and verifying key history of {} users in a directory of {} existing users *", num_key_history, existing_usernames.len());
    println!("******************************************************************************************************");
    // Key history and verification measurement
    clear_stats();

    for i in 0..num_key_history {
        // Get a new lookup proof for the current user
        let new_history_proof = seemless_dir.key_history(&key_history_set[i].0).unwrap();
        // Verify this lookup proof
        seemless_dir
            .key_history_verify(key_history_set[i].0.clone(), new_history_proof)
            .unwrap();
    }

    print_hashmap_distribution();
    print_stats();

    let total_ep = new_epochs + 2;
    println!("*************************************************************************************************");
    println!("* Measurements for running and verifying audit of {} epochs in a directory of {} existing users *", total_ep, existing_usernames.len());
    println!("*************************************************************************************************");
    // Key history and verification measurement
    clear_stats();

    for i in 1..total_ep {
        for j in i..total_ep {
            // Get a new lookup proof for the current user
            let audit_proof = seemless_dir.audit(i, j).unwrap();
            // Verify this lookup proof
            seemless_dir
                .audit_verify(i, j, audit_proof)
                .unwrap();
        }
    }

    print_hashmap_distribution();
    print_stats();


}
