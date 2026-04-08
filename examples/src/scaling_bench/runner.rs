// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Generic benchmark runner for any [`BenchCache`] implementation.

use std::time::{Duration, Instant};

use akd_core::types::{AkdLabel, EpochHash};
use akd_traits::KeyDirectory;
use indicatif::{ProgressBar, ProgressStyle};

use super::cache::{self, BenchCache};
use super::table::Results;
use super::Op;

/// Set up a directory populated with `size` entries and 5 additional epochs
/// of `updates_per_epoch` entries each.
///
/// When `use_cache` is true, attempts to load from disk first and saves
/// after setup.
async fn setup_directory<S: BenchCache>(
    size: usize,
    updates_per_epoch: usize,
    use_cache: bool,
) -> (S::Directory, Vec<EpochHash>) {
    let cache_file = cache::cache_path(size);

    if use_cache {
        if let Some(cached) = S::load(&cache_file).await {
            return cached;
        }
    }

    let num_history_epochs = 5;
    let (dir, cache_handle) = S::create_directory_with_handle().await;
    let data = S::generate_test_data(size, 42);
    let initial_eh = dir.publish(data).await.map_err(Into::into).unwrap();

    let mut epoch_hashes = vec![initial_eh];
    for epoch_seed in 1..=num_history_epochs {
        let epoch_data = S::generate_test_data(updates_per_epoch, 100 + epoch_seed as u64);
        let eh = dir.publish(epoch_data).await.map_err(Into::into).unwrap();
        epoch_hashes.push(eh);
    }

    if use_cache {
        S::save(&cache_handle, &epoch_hashes, &cache_file).await;
    }

    (dir, epoch_hashes)
}

/// Compute the median of a slice of durations. Panics if the slice is empty.
fn median_duration(times: &mut [Duration]) -> Duration {
    assert!(!times.is_empty(), "cannot compute median of empty slice");
    times.sort();
    let mid = times.len() / 2;
    if times.len().is_multiple_of(2) {
        (times[mid - 1] + times[mid]) / 2
    } else {
        times[mid]
    }
}

/// Create a spinner-style progress bar for a benchmark phase.
fn make_progress_bar(msg: &str, size: usize) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {msg} (N={pos}) {spinner}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    pb.set_message(msg.to_string());
    pb.set_position(size as u64);
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Run all benchmarks for the given sizes and operations.
pub(crate) async fn run_benchmarks<S: BenchCache>(
    sizes: &[usize],
    ops: &[Op],
    updates_per_epoch: usize,
    iterations: usize,
    use_cache: bool,
) -> Results {
    assert!(iterations >= 1, "iterations must be at least 1");

    let mut results = Results::new();

    for &size in sizes {
        // --- Setup: create directory and populate with `size` entries ---
        let pb = make_progress_bar("Setting up directory", size);
        let setup_start = Instant::now();

        let (dir, epoch_hashes) = setup_directory::<S>(size, updates_per_epoch, use_cache).await;

        let setup_elapsed = setup_start.elapsed();
        pb.finish_and_clear();

        // Record setup time
        results.insert((Op::Setup, size), setup_elapsed);

        let label = AkdLabel::from("user_0");

        // --- Publish benchmark: time publishing N entries into an empty directory ---
        if ops.contains(&Op::Publish) {
            let pb = make_progress_bar("Benchmarking publish", size);
            let mut times = Vec::with_capacity(iterations);
            for iter in 0..iterations {
                let fresh_dir = S::create_directory().await;
                let publish_data = S::generate_test_data(size, 1000 + iter as u64);
                let start = Instant::now();
                fresh_dir
                    .publish(publish_data)
                    .await
                    .map_err(Into::into)
                    .unwrap();
                times.push(start.elapsed());
            }
            results.insert((Op::Publish, size), median_duration(&mut times));
            pb.finish_and_clear();
        }

        // --- Publish update benchmark: time publishing M entries into the existing directory ---
        if ops.contains(&Op::PublishUpdate) {
            let pb = make_progress_bar("Benchmarking publish update", size);
            let mut times = Vec::with_capacity(iterations);
            for iter in 0..iterations {
                let update_data = S::generate_test_data(updates_per_epoch, 2000 + iter as u64);
                let start = Instant::now();
                dir.publish(update_data).await.map_err(Into::into).unwrap();
                times.push(start.elapsed());
            }
            results.insert((Op::PublishUpdate, size), median_duration(&mut times));
            pb.finish_and_clear();
        }

        // --- Lookup benchmark ---
        if ops.contains(&Op::Lookup) || ops.contains(&Op::LookupVerify) {
            let pb = make_progress_bar("Benchmarking lookup", size);

            if ops.contains(&Op::Lookup) {
                let mut times = Vec::with_capacity(iterations);
                for _ in 0..iterations {
                    let start = Instant::now();
                    let (_proof, _eh) =
                        dir.lookup(label.clone()).await.map_err(Into::into).unwrap();
                    times.push(start.elapsed());
                }
                results.insert((Op::Lookup, size), median_duration(&mut times));
            }

            // --- Lookup verify ---
            if ops.contains(&Op::LookupVerify) {
                let pk = dir.get_public_key().await.map_err(Into::into).unwrap();
                let mut verify_times = Vec::with_capacity(iterations);
                for _ in 0..iterations {
                    let (p, e) = dir.lookup(label.clone()).await.map_err(Into::into).unwrap();
                    let start = Instant::now();
                    <S::Directory as KeyDirectory>::lookup_verify(
                        &pk,
                        e.hash(),
                        e.epoch(),
                        label.clone(),
                        p,
                    )
                    .unwrap();
                    verify_times.push(start.elapsed());
                }
                results.insert((Op::LookupVerify, size), median_duration(&mut verify_times));
            }

            pb.finish_and_clear();
        }

        // --- Key history benchmark ---
        if ops.contains(&Op::History) {
            let pb = make_progress_bar("Benchmarking history", size);
            let mut times = Vec::with_capacity(iterations);

            for _ in 0..iterations {
                let params = Default::default();
                let start = Instant::now();
                let (_proof, _eh) = dir
                    .key_history(&label, params)
                    .await
                    .map_err(Into::into)
                    .unwrap();
                times.push(start.elapsed());
            }

            results.insert((Op::History, size), median_duration(&mut times));
            pb.finish_and_clear();
        }

        // --- Audit benchmark ---
        if ops.contains(&Op::Audit) || ops.contains(&Op::AuditVerify) {
            let pb = make_progress_bar("Benchmarking audit", size);

            // Audit between epoch 1 and 2
            if ops.contains(&Op::Audit) {
                let mut times = Vec::with_capacity(iterations);
                for _ in 0..iterations {
                    let start = Instant::now();
                    let _proof = dir.audit(1, 2).await.map_err(Into::into).unwrap();
                    times.push(start.elapsed());
                }
                results.insert((Op::Audit, size), median_duration(&mut times));
            }

            // --- Audit verify ---
            if ops.contains(&Op::AuditVerify) {
                let hashes = vec![epoch_hashes[0].hash(), epoch_hashes[1].hash()];
                let mut verify_times = Vec::with_capacity(iterations);
                for _ in 0..iterations {
                    let proof = dir.audit(1, 2).await.map_err(Into::into).unwrap();
                    let start = Instant::now();
                    <S::Directory as KeyDirectory>::audit_verify(hashes.clone(), proof)
                        .await
                        .unwrap();
                    verify_times.push(start.elapsed());
                }
                results.insert((Op::AuditVerify, size), median_duration(&mut verify_times));
            }

            pb.finish_and_clear();
        }
    }

    results
}

/// Run a sweep of publish_update benchmarks across different M (updates-per-epoch) values
/// for a fixed directory size N.
pub(crate) async fn run_sweep_updates<S: BenchCache>(
    size: usize,
    m_values: &[usize],
    iterations: usize,
    use_cache: bool,
) -> Vec<(usize, Duration)> {
    assert!(iterations >= 1, "iterations must be at least 1");

    // Use the smallest M value for initial setup
    let setup_m = *m_values.iter().min().unwrap();

    // Set up directory once
    let pb = make_progress_bar("Setting up directory for sweep", size);
    let (dir, _epoch_hashes) = setup_directory::<S>(size, setup_m, use_cache).await;
    pb.finish_and_clear();

    let mut results = Vec::with_capacity(m_values.len());

    for &m in m_values {
        let pb = make_progress_bar(&format!("Sweeping M=2^{}", m.trailing_zeros()), size);
        let mut times = Vec::with_capacity(iterations);

        for iter in 0..iterations {
            let update_data = S::generate_test_data(m, 3000 + iter as u64);
            let start = Instant::now();
            dir.publish(update_data).await.map_err(Into::into).unwrap();
            times.push(start.elapsed());
        }

        results.push((m, median_duration(&mut times)));
        pb.finish_and_clear();
    }

    results
}
