// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Benchmarks for parallel vs sequential VRF calculations

extern crate criterion;
use self::criterion::*;
use akd_core::{ecvrf::VRFKeyStorage, AkdLabel};

fn bench_parallel_vrfs(c: &mut Criterion) {
    // utilize all cores available
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();
    // A runtime which is capped at 4 worker threads (cores)
    let limited_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .build()
        .unwrap();

    // generate 1K labels to do VRFs for
    let labels = (0..1_000)
        .into_iter()
        .map(|i| {
            let name = format!("user {}", i);
            (AkdLabel::from_utf8_str(&name), false, i as u64)
        })
        .collect::<Vec<_>>();
    let labels_clone = labels.clone();

    c.bench_function("Sequential VRFs", |b| {
        b.iter(|| {
            let key = runtime
                .block_on(akd_core::ecvrf::HardCodedAkdVRF.get_vrf_private_key())
                .unwrap();
            for (label, stale, version) in labels.iter() {
                akd_core::ecvrf::HardCodedAkdVRF::get_node_label_with_key(
                    &key, label, *stale, *version,
                );
            }
        })
    });

    c.bench_function("Parallel VRFs (all cores)", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let vrf = akd_core::ecvrf::HardCodedAkdVRF;
                vrf.get_node_labels(&labels_clone).await.unwrap();
            })
        })
    });

    c.bench_function("Parallel VRFs (4 cores)", |b| {
        b.iter(|| {
            limited_runtime.block_on(async {
                let vrf = akd_core::ecvrf::HardCodedAkdVRF;
                vrf.get_node_labels(&labels_clone).await.unwrap();
            })
        })
    });
}

criterion_group!(benches, bench_parallel_vrfs);
criterion_main!(benches);
