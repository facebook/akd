// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Provides measurements for how many accesses to memory etc are made.
use rand::prelude::IteratorRandom;
use rand::{prelude::ThreadRng, thread_rng};

use akd::auditor::audit_verify;
use akd::client::{key_history_verify, lookup_verify};
use akd::directory::{get_key_history_hashes, Directory};
use akd::storage::memory::AsyncInMemoryDbWithCache;
use akd::storage::types::{AkdKey, Values};

use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

fn create_keys_and_values(num_insertions: usize, mut rng: ThreadRng) -> Vec<(AkdKey, Values)> {
    let mut updates = Vec::<(AkdKey, Values)>::new();
    for _ in 0..num_insertions {
        let akd_key = AkdKey::random(&mut rng);
        let val = Values::random(&mut rng);
        updates.push((akd_key, val));
    }
    updates
}

fn create_random_subset_of_existing_keys(
    existing_keys: Vec<AkdKey>,
    subset_size: usize,
    mut rng: ThreadRng,
) -> Vec<(AkdKey, Values)> {
    let mut key_subset = Vec::<(AkdKey, Values)>::new();
    let mut actual_subset_size = subset_size;
    if existing_keys.len() < subset_size {
        actual_subset_size = existing_keys.len();
    }
    let sample = existing_keys
        .iter()
        .choose_multiple(&mut rng, actual_subset_size);
    for i in 0..actual_subset_size {
        let username = sample[i].clone();
        let val = Values::random(&mut rng);
        key_subset.push((username, val));
    }
    key_subset
}

#[tokio::main]
async fn main() {
    let num_init_insertions = 1000;

    let mut existing_keys = Vec::<AkdKey>::new();

    let db = akd::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDbWithCache::new());
    let mut akd_dir =
        Directory::<akd::storage::V2FromV1StorageWrapper<AsyncInMemoryDbWithCache>>::new::<
            Blake3_256<BaseElement>,
        >(&db)
        .await
        .unwrap();

    // Populating the updates
    let rng: ThreadRng = thread_rng();
    let mut updates = create_keys_and_values(num_init_insertions, rng);

    // Publishing updated set with an initial set of users
    akd_dir
        .publish::<Blake3_256<BaseElement>>(updates.clone(), false)
        .await
        .unwrap();

    let mut new_keys = updates
        .clone()
        .iter()
        .map(|x| x.0.clone())
        .collect::<Vec<AkdKey>>();
    existing_keys.append(&mut new_keys);

    let num_new_insertions = 10;
    let rng: ThreadRng = thread_rng();
    updates = create_keys_and_values(num_new_insertions, rng);
    println!("*********************************************************************************");
    println!(
        "* Measurements for inserting {} new users into a directory of {} existing users *",
        num_new_insertions, num_init_insertions
    );
    println!("*********************************************************************************");
    // Publish measurement
    db.db.clear_stats();
    akd_dir
        .publish::<Blake3_256<BaseElement>>(updates.clone(), false)
        .await
        .unwrap();

    db.db.print_hashmap_distribution();
    db.db.print_stats();
    new_keys = updates
        .clone()
        .iter()
        .map(|x| x.0.clone())
        .collect::<Vec<AkdKey>>();
    existing_keys.append(&mut new_keys);

    let new_epochs = 5;
    // Adding a few new epochs and updating keys for some users
    for _ in 0..new_epochs {
        let num_new_insertions = 10;
        let num_updates = 10;
        let rng: ThreadRng = thread_rng();
        let mut new_users = create_keys_and_values(num_new_insertions, rng);
        let rng: ThreadRng = thread_rng();
        updates = create_random_subset_of_existing_keys(existing_keys.clone(), num_updates, rng);
        updates.append(&mut new_users);
        akd_dir
            .publish::<Blake3_256<BaseElement>>(updates.clone(), false)
            .await
            .unwrap();
        new_keys = new_users
            .clone()
            .iter()
            .map(|x| x.0.clone())
            .collect::<Vec<AkdKey>>();
        existing_keys.append(&mut new_keys);
    }

    let num_lookups = 10;
    let rng: ThreadRng = thread_rng();
    let lookup_set = create_random_subset_of_existing_keys(existing_keys.clone(), num_lookups, rng);
    println!("******************************************************************************************************");
    println!("* Measurements for looking up and verifying lookups for {} users in a directory of {} existing users *", num_lookups, existing_keys.len());
    println!("*****************************************************************************************************");
    // Lookup and verification of lookup measurement
    db.db.clear_stats();

    let current_azks = akd_dir.retrieve_current_azks().await.unwrap();

    for i in 0..num_lookups {
        // Get a new lookup proof for the current user
        let new_lookup_proof = akd_dir.lookup(lookup_set[i].0.clone()).await.unwrap();
        // Verify this lookup proof
        lookup_verify::<Blake3_256<BaseElement>>(
            akd_dir
                .get_root_hash::<Blake3_256<BaseElement>>(&current_azks)
                .await
                .unwrap(),
            lookup_set[i].0.clone(),
            new_lookup_proof,
        )
        .unwrap();
    }

    db.db.print_hashmap_distribution();
    db.db.print_stats();

    let num_key_history = 10;
    let rng: ThreadRng = thread_rng();
    let key_history_set =
        create_random_subset_of_existing_keys(existing_keys.clone(), num_key_history, rng);
    println!("******************************************************************************************************");
    println!("* Measurements for running and verifying key history of {} users in a directory of {} existing users *", num_key_history, existing_keys.len());
    println!("******************************************************************************************************");
    // Key history and verification measurement
    db.db.clear_stats();

    for i in 0..num_key_history {
        // Get a new lookup proof for the current user
        let new_history_proof = akd_dir.key_history(&key_history_set[i].0).await.unwrap();
        // Verify this lookup proof
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd_dir, &new_history_proof)
                .await
                .unwrap();
        key_history_verify::<Blake3_256<BaseElement>>(
            root_hashes,
            previous_root_hashes,
            key_history_set[i].0.clone(),
            new_history_proof,
        )
        .unwrap();
    }

    db.db.print_hashmap_distribution();
    db.db.print_stats();

    let total_ep = new_epochs + 2;
    println!("*************************************************************************************************");
    println!("* Measurements for running and verifying audit of {} epochs in a directory of {} existing users *", total_ep, existing_keys.len());
    println!("*************************************************************************************************");
    // Key history and verification measurement
    db.db.clear_stats();

    let current_azks = akd_dir.retrieve_current_azks().await.unwrap();

    for i in 1..total_ep {
        for j in i..total_ep {
            // Get a new lookup proof for the current user
            let audit_proof = akd_dir.audit(i, j).await.unwrap();
            // Verify this lookup proof
            audit_verify::<Blake3_256<BaseElement>>(
                akd_dir
                    .get_root_hash_at_epoch::<Blake3_256<BaseElement>>(&current_azks, i)
                    .await
                    .unwrap(),
                akd_dir
                    .get_root_hash_at_epoch::<Blake3_256<BaseElement>>(&current_azks, j)
                    .await
                    .unwrap(),
                audit_proof,
            )
            .await
            .unwrap();
        }
    }

    db.db.print_hashmap_distribution();
    db.db.print_stats();
}
