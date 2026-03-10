// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

use akd::append_only_zks::AzksParallelismConfig;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::manager::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::{AkdLabel, AkdValue, Directory, LookupProof};
use async_trait::async_trait;
use criterion::Criterion;
use rand::distributions::Alphanumeric;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

type Config = akd::WhatsAppV1Configuration;

struct AkdBenchSetup;

#[async_trait]
impl akd_traits::bench::BenchmarkSetup for AkdBenchSetup {
    type Directory = Directory<Config, AsyncInMemoryDatabase, HardCodedAkdVRF>;

    async fn create_directory() -> Self::Directory {
        let db = AsyncInMemoryDatabase::new();
        let storage = StorageManager::new_no_cache(db);
        let vrf = HardCodedAkdVRF {};
        Directory::<Config, _, _>::new(storage, vrf, AzksParallelismConfig::default())
            .await
            .unwrap()
    }

    fn generate_test_data(num_entries: usize, seed: u64) -> Vec<(AkdLabel, AkdValue)> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..num_entries)
            .map(|i| {
                let label = format!("user_{}", i);
                let value: String = (0..16)
                    .map(|_| rng.sample(Alphanumeric))
                    .map(char::from)
                    .collect();
                (AkdLabel::from(&label), AkdValue::from(&value))
            })
            .collect()
    }

    fn name() -> &'static str {
        "AKD (WhatsAppV1)"
    }
}

/// Compute the approximate size of an AKD lookup proof in bytes.
fn akd_lookup_proof_size(proof: &LookupProof) -> usize {
    proof.existence_vrf_proof.len()
        + proof.marker_vrf_proof.len()
        + proof.freshness_vrf_proof.len()
        + proof.commitment_nonce.len()
        + std::mem::size_of_val(&proof.existence_proof)
        + std::mem::size_of_val(&proof.marker_proof)
        + std::mem::size_of_val(&proof.freshness_proof)
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    akd_traits::bench::bench_publish::<AkdBenchSetup>(&mut criterion);
    akd_traits::bench::bench_lookup::<AkdBenchSetup>(&mut criterion);
    akd_traits::bench::bench_lookup_verify::<AkdBenchSetup, _>(
        &mut criterion,
        akd_lookup_proof_size,
    );
    akd_traits::bench::bench_key_history::<AkdBenchSetup>(&mut criterion);
    akd_traits::bench::bench_audit::<AkdBenchSetup>(&mut criterion);
    akd_traits::bench::bench_audit_verify::<AkdBenchSetup>(&mut criterion);

    criterion.final_summary();
}
