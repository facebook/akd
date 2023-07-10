// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

extern crate thread_id;

use akd::configuration::Configuration;
use akd::ecvrf::VRFKeyStorage;
use akd::storage::Database;
use akd::Directory;
use akd::HistoryParams;
use akd::{AkdLabel, AkdValue};
use rand::distributions::Alphanumeric;
use rand::seq::IteratorRandom;
use rand::{thread_rng, Rng};

/// The suite of tests to run against a fully-instantated and storage-backed directory.
/// This will publish 3 epochs of ```num_users``` records and
/// perform 10 random lookup proofs + 2 random history proofs + and audit proof from epochs 1u64 -> 2u64
pub async fn directory_test_suite<TC: Configuration, S: Database + 'static, V: VRFKeyStorage>(
    mysql_db: &akd::storage::StorageManager<S>,
    num_users: usize,
    vrf: &V,
) {
    // generate the test data
    let mut rng = thread_rng();

    let mut users: Vec<String> = vec![];
    for _ in 0..num_users {
        users.push(
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect(),
        );
    }
    let mut root_hashes = vec![];
    // create & test the directory
    let maybe_dir = Directory::<TC, _, _>::new(mysql_db.clone(), vrf.clone()).await;
    match maybe_dir {
        Err(akd_error) => panic!("Error initializing directory: {:?}", akd_error),
        Ok(dir) => {
            // Publish 3 epochs of user material
            for i in 1..=3 {
                let mut data = Vec::new();
                for value in users.iter() {
                    data.push((
                        AkdLabel::from(value),
                        AkdValue(format!("{i}").as_bytes().to_vec()),
                    ));
                }

                if let Err(error) = dir.publish(data).await {
                    panic!("Error publishing batch {:?}", error);
                }
                let root_hash = dir.get_epoch_hash().await.unwrap().1;
                root_hashes.push(root_hash);
            }

            // Perform 10 random lookup proofs on the published users
            for user in users.iter().choose_multiple(&mut rng, 10) {
                let key = AkdLabel::from(user);
                match dir.lookup(key.clone()).await {
                    Err(error) => panic!("Error looking up user information {:?}", error),
                    Ok((proof, root_hash)) => {
                        let vrf_pk = dir.get_public_key().await.unwrap();
                        if let Err(error) = akd::client::lookup_verify::<TC>(
                            vrf_pk.as_bytes(),
                            root_hash.hash(),
                            key,
                            proof,
                        ) {
                            panic!("Lookup proof failed to verify {:?}", error);
                        }
                    }
                }
            }

            // Perform 2 random history proofs on the published material
            for user in users.iter().choose_multiple(&mut rng, 2) {
                let key = AkdLabel::from(user);
                match dir.key_history(&key, HistoryParams::default()).await {
                    Err(error) => panic!("Error performing key history retrieval {:?}", error),
                    Ok((proof, root_hash)) => {
                        let vrf_pk = dir.get_public_key().await.unwrap();
                        if let Err(error) = akd::client::key_history_verify::<TC>(
                            vrf_pk.as_bytes(),
                            root_hash.hash(),
                            root_hash.epoch(),
                            key,
                            proof,
                            akd::HistoryVerificationParams::default(),
                        ) {
                            panic!("History proof failed to verify {:?}", error);
                        }
                    }
                }
            }

            // Perform an audit proof from 1u64 -> 2u64

            mysql_db.log_metrics(log::Level::Info).await;
            log::warn!("Beginning audit proof generation");
            mysql_db.flush_cache().await;
            match dir.audit(1u64, 2u64).await {
                Err(error) => panic!("Error perform audit proof retrieval {:?}", error),
                Ok(proof) => {
                    mysql_db.log_metrics(log::Level::Info).await;
                    log::warn!("Done with audit proof generation");
                    let start_root_hash = root_hashes[0];
                    let end_root_hash = root_hashes[1];
                    akd::auditor::audit_verify::<TC>(vec![start_root_hash, end_root_hash], proof)
                        .await
                        .unwrap();
                }
            }
        }
    }
}
