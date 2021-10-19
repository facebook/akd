// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use rand::prelude::IteratorRandom;
use rand::{prelude::ThreadRng, thread_rng};

use seemless::seemless_auditor::audit_verify;
use seemless::seemless_client::{key_history_verify, lookup_verify};
use seemless::seemless_directory::{get_key_history_hashes, SeemlessDirectory, Username, Values};

use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

pub mod measurements;
use measurements::*;

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
    let num_init_insertions = 1000;

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
        updates =
            create_random_subset_of_existing_users(existing_usernames.clone(), num_updates, rng);
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
        lookup_verify::<Blake3_256<BaseElement>>(
            seemless_dir.get_root_hash().unwrap(),
            lookup_set[i].0.clone(),
            new_lookup_proof,
        )
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
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&seemless_dir, &new_history_proof).unwrap();
        key_history_verify::<Blake3_256<BaseElement>>(
            root_hashes,
            previous_root_hashes,
            key_history_set[i].0.clone(),
            new_history_proof,
        )
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
            audit_verify::<Blake3_256<BaseElement>>(
                seemless_dir.get_root_hash_at_epoch(i).unwrap(),
                seemless_dir.get_root_hash_at_epoch(j).unwrap(),
                audit_proof,
            )
            .unwrap();
        }
    }

    print_hashmap_distribution();
    print_stats();
}
