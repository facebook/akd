// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Benchmarks for parallel vs sequential VRF calculations

extern crate criterion;
use self::criterion::*;
use akd_core::configuration::NamedConfiguration;
use akd_core::ecvrf::{VRFExpandedPrivateKey, VRFPublicKey};
use akd_core::VersionFreshness;
use akd_core::{ecvrf::VRFKeyStorage, AkdLabel, AkdValue};
use rand::distributions::Alphanumeric;
use rand::Rng;

macro_rules! bench_config {
    ( $x:ident ) => {
        paste::paste! {
            // NOTE(new_config): Add a new configuration here

            #[cfg(feature = "whatsapp_v1")]
            fn [<$x _ whatsapp_v1_config>](c: &mut Criterion) {
                $x::<akd_core::WhatsAppV1Configuration>(c)
            }

            #[cfg(feature = "experimental")]
            fn [<$x _ experimental_config>](c: &mut Criterion) {
                $x::<akd_core::ExperimentalConfiguration<akd_core::ExampleLabel>>(c)
            }
        }
    };
}

macro_rules! group_config {
    ( $( $group:path ),+ $(,)* ) => {
        paste::paste! {
            // NOTE(new_config): Add a new configuration here

            #[cfg(feature = "whatsapp_v1")]
            criterion_group!(
                $(
                    [<$group _ whatsapp_v1_config>],
                )+
            );

            #[cfg(feature = "experimental")]
            criterion_group!(
                $(
                    [<$group _ experimental_config>],
                )+
            );
        }
    };
}

group_config!(benches, bench_single_vrf, bench_parallel_vrfs);

fn main() {
    // NOTE(new_config): Add a new configuration here

    #[cfg(feature = "whatsapp_v1")]
    benches_whatsapp_v1_config();
    #[cfg(feature = "experimental")]
    benches_experimental_config();

    Criterion::default().configure_from_args().final_summary();
}

bench_config!(bench_single_vrf);
fn bench_single_vrf<TC: NamedConfiguration>(c: &mut Criterion) {
    let rng = rand::rngs::OsRng;

    // Generate a random label
    let label = AkdLabel::from(
        &rng.sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>(),
    );

    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();
    let key = runtime
        .block_on(akd_core::ecvrf::HardCodedAkdVRF.get_vrf_private_key())
        .unwrap();
    let expanded_key = VRFExpandedPrivateKey::from(&key);
    let pk = VRFPublicKey::from(&key);

    c.bench_function(
        &format!("Single VRF label generation ({})", TC::name()),
        |b| {
            b.iter(|| {
                akd_core::ecvrf::HardCodedAkdVRF::get_node_label_with_expanded_key::<TC>(
                    &expanded_key,
                    &pk,
                    &label,
                    VersionFreshness::Fresh,
                    1,
                );
            })
        },
    );
}

bench_config!(bench_parallel_vrfs);
fn bench_parallel_vrfs<TC: NamedConfiguration>(c: &mut Criterion) {
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
            (
                AkdLabel::from(&name),
                VersionFreshness::Fresh,
                i as u64,
                AkdValue::from(&name),
            )
        })
        .collect::<Vec<_>>();
    let labels_clone = labels.clone();

    c.bench_function(&format!("Sequential VRFs ({})", TC::name()), |b| {
        b.iter(|| {
            let key = runtime
                .block_on(akd_core::ecvrf::HardCodedAkdVRF.get_vrf_private_key())
                .unwrap();
            let expanded_key = VRFExpandedPrivateKey::from(&key);
            let pk = VRFPublicKey::from(&key);
            for (label, stale, version, _) in labels.iter() {
                akd_core::ecvrf::HardCodedAkdVRF::get_node_label_with_expanded_key::<TC>(
                    &expanded_key,
                    &pk,
                    label,
                    *stale,
                    *version,
                );
            }
        })
    });

    c.bench_function(
        &format!("Parallel VRFs (all cores) ({})", TC::name()),
        |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let vrf = akd_core::ecvrf::HardCodedAkdVRF;
                    vrf.get_node_labels::<TC>(&labels_clone).await.unwrap();
                })
            })
        },
    );

    c.bench_function(&format!("Parallel VRFs (4 cores) ({})", TC::name()), |b| {
        b.iter(|| {
            limited_runtime.block_on(async {
                let vrf = akd_core::ecvrf::HardCodedAkdVRF;
                vrf.get_node_labels::<TC>(&labels_clone).await.unwrap();
            })
        })
    });
}
