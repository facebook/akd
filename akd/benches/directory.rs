// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#[macro_use]
extern crate criterion;

use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::manager::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::{AkdLabel, AkdValue, Directory};
use criterion::{BatchSize, Criterion};
use rand::distributions::Alphanumeric;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn history_generation(c: &mut Criterion) {
    let num_users = 1000;
    let num_updates = 10;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .build()
        .unwrap();

    let idata = (1..num_users)
        .into_iter()
        .map(|i| {
            let user = format!("User {}", i);
            AkdLabel::from(&user)
        })
        .collect::<Vec<_>>();

    let id = "Benchmark key history proof generation on a small tree".to_string();

    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {
                let mut rng = StdRng::seed_from_u64(42);
                let database = AsyncInMemoryDatabase::new();
                let vrf = HardCodedAkdVRF {};
                let db = StorageManager::new(
                    database,
                    Some(std::time::Duration::from_secs(60)),
                    None,
                    Some(std::time::Duration::from_secs(60)),
                );
                let db_clone = db.clone();
                let directory = runtime
                    .block_on(async move { Directory::new(db, vrf).await })
                    .unwrap();

                for _epoch in 1..num_updates {
                    let value: String = (0..rng.gen_range(10, 20))
                        .map(|_| rng.sample(&Alphanumeric))
                        .map(char::from)
                        .collect();
                    let data = idata
                        .iter()
                        .map(|k| (k.clone(), AkdValue::from(&value)))
                        .collect::<Vec<_>>();
                    runtime.block_on(directory.publish(data)).unwrap();
                }

                (directory, db_clone)
            },
            |(directory, db)| {
                // flush the cache prior to each generation to get fresh results
                runtime.block_on(db.flush_cache());

                // generate for the most recent 10 updates
                let label = AkdLabel::from("User 1");
                let params = akd::HistoryParams::MostRecent(5);
                runtime
                    .block_on(directory.key_history(&label, params))
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

criterion_group!(directory_benches, history_generation);
criterion_main!(directory_benches);
