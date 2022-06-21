extern crate thread_id;

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use akd::ecvrf::VRFKeyStorage;
use akd::storage::types::{AkdLabel, AkdValue};
use akd::Directory;
use rand::distributions::Alphanumeric;
use rand::seq::IteratorRandom;
use rand::{thread_rng, Rng};

use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
type Blake3 = Blake3_256<BaseElement>;

/// The suite of tests to run against a fully-instantated and storage-backed directory.
/// This will publish 3 epochs of ```num_users``` records and
/// perform 10 random lookup proofs + 2 random history proofs + and audit proof from epochs 1u64 -> 2u64
pub async fn directory_test_suite<S: akd::storage::Storage + Sync + Send, V: VRFKeyStorage>(
    mysql_db: &S,
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
    let maybe_dir = Directory::<_, _>::new::<Blake3>(mysql_db, vrf, false).await;
    match maybe_dir {
        Err(akd_error) => panic!("Error initializing directory: {:?}", akd_error),
        Ok(dir) => {
            // Publish 3 epochs of user material
            for i in 1..=3 {
                let mut data = Vec::new();
                for value in users.iter() {
                    data.push((
                        AkdLabel::from_utf8_str(value),
                        AkdValue(format!("{}", i).as_bytes().to_vec()),
                    ));
                }

                if let Err(error) = dir.publish::<Blake3>(data).await {
                    panic!("Error publishing batch {:?}", error);
                }
                let azks = dir.retrieve_current_azks().await.unwrap();
                root_hashes.push(dir.get_root_hash::<Blake3>(&azks).await);
            }

            // Perform 10 random lookup proofs on the published users
            let azks = dir.retrieve_current_azks().await.unwrap();
            let root_hash = dir.get_root_hash::<Blake3>(&azks).await.unwrap();

            for user in users.iter().choose_multiple(&mut rng, 10) {
                let key = AkdLabel::from_utf8_str(user);
                match dir.lookup::<Blake3>(key.clone()).await {
                    Err(error) => panic!("Error looking up user information {:?}", error),
                    Ok(proof) => {
                        let vrf_pk = dir.get_public_key().await.unwrap();
                        if let Err(error) =
                            akd::client::lookup_verify::<Blake3>(&vrf_pk, root_hash, key, proof)
                        {
                            panic!("Lookup proof failed to verify {:?}", error);
                        }
                    }
                }
            }

            // Perform 2 random history proofs on the published material
            for user in users.iter().choose_multiple(&mut rng, 2) {
                let key = AkdLabel::from_utf8_str(user);
                match dir.key_history::<Blake3>(&key).await {
                    Err(error) => panic!("Error performing key history retrieval {:?}", error),
                    Ok(proof) => {
                        let (root_hash, current_epoch) =
                            akd::directory::get_directory_root_hash_and_ep::<_, Blake3, _>(&dir)
                                .await
                                .unwrap();
                        let vrf_pk = dir.get_public_key().await.unwrap();
                        if let Err(error) = akd::client::key_history_verify::<Blake3>(
                            &vrf_pk,
                            root_hash,
                            current_epoch,
                            key,
                            proof,
                            false,
                        ) {
                            panic!("History proof failed to verify {:?}", error);
                        }
                    }
                }
            }

            // Perform an audit proof from 1u64 -> 2u64
            match dir.audit::<Blake3>(1u64, 2u64).await {
                Err(error) => panic!("Error perform audit proof retrieval {:?}", error),
                Ok(proof) => {
                    let start_root_hash = root_hashes[0].as_ref();
                    let end_root_hash = root_hashes[1].as_ref();
                    match (start_root_hash, end_root_hash) {
                        (Ok(start), Ok(end)) => {
                            if let Err(error) =
                                akd::auditor::audit_verify(vec![*start, *end], proof).await
                            {
                                panic!("Error validating audit proof {:?}", error);
                            }
                        }
                        (Err(err), _) => {
                            panic!("Error retrieving root hash at epoch {:?}", err);
                        }
                        (_, Err(err)) => {
                            panic!("Error retrieving root hash at epoch {:?}", err);
                        }
                    }
                }
            }
        }
    }
}
