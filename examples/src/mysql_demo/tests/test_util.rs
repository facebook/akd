// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

extern crate thread_id;

use akd::configuration::Configuration;
use akd::ecvrf::VRFKeyStorage;
use akd::storage::{Database, StorageManager};
use akd::Directory;
use akd::HistoryParams;
use akd::{AkdLabel, AkdValue};
use log::{info, Level, Metadata, Record};
use once_cell::sync::OnceCell;
use rand::distributions::Alphanumeric;
use rand::seq::IteratorRandom;
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use tokio::time::{Duration, Instant};

static EPOCH: OnceCell<Instant> = OnceCell::new();

static LOG: OnceCell<u64> = OnceCell::new();

// ================== Logging ================== //

pub(crate) fn log_init(level: Level) {
    EPOCH.get_or_init(Instant::now);
    LOG.get_or_init(|| {
        if let Ok(logger) = FileLogger::new(String::from("integration_test.log")) {
            let loggers: Vec<Box<dyn log::Log>> = vec![Box::new(logger)];
            let mlogger = multi_log::MultiLogger::new(loggers);

            log::set_max_level(level.to_level_filter());
            if let Err(error) = log::set_boxed_logger(Box::new(mlogger)) {
                panic!("Error initializing multi-logger: {}", error);
            }
        } else {
            panic!("Error creating file logger!");
        }
        0
    });
}

pub(crate) fn format_log_record(io: &mut (dyn Write + Send), record: &Record) {
    let target = {
        if let Some(target_str) = record.target().split(':').last() {
            if let Some(line) = record.line() {
                format!(" ({target_str}:{line})")
            } else {
                format!(" ({target_str})")
            }
        } else {
            "".to_string()
        }
    };

    let toc = if let Some(epoch) = EPOCH.get() {
        Instant::now() - *epoch
    } else {
        Duration::from_millis(0)
    };

    let seconds = toc.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;
    let miliseconds = toc.subsec_millis();

    let msg = format!(
        "[{:02}:{:02}:{:02}.{:03}] ({:x}) {:6} {}{}",
        hours,
        minutes,
        seconds,
        miliseconds,
        thread_id::get(),
        record.level(),
        record.args(),
        target
    );
    let _ = writeln!(io, "{msg}");
}

pub(crate) struct FileLogger {
    sink: Mutex<File>,
}

impl FileLogger {
    pub(crate) fn new<T: AsRef<Path>>(path: T) -> io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            sink: Mutex::new(file),
        })
    }
}

impl log::Log for FileLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        // use the global log-level
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut sink = &*self.sink.lock().unwrap();
        format_log_record(&mut sink, record);
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
    }
}

// ================== Test Helpers ================== //

pub(crate) async fn test_lookups<TC: Configuration, S: Database + 'static, V: VRFKeyStorage>(
    mysql_db: &StorageManager<S>,
    vrf: &V,
    num_users: u64,
    num_epochs: u64,
    num_lookups: usize,
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

    // create & test the directory
    let maybe_dir = Directory::<TC, _, _>::new(mysql_db.clone(), vrf.clone()).await;
    match maybe_dir {
        Err(akd_error) => panic!("Error initializing directory: {:?}", akd_error),
        Ok(dir) => {
            info!("AKD Directory started. Beginning tests");

            // Publish `num_epochs` epochs of user material
            for i in 1..=num_epochs {
                let mut data = Vec::new();
                for value in users.iter() {
                    data.push((
                        AkdLabel::from(value),
                        AkdValue(format!("{i}").as_bytes().to_vec()),
                    ));
                }

                if let Err(error) = dir.publish(data).await {
                    panic!("Error publishing batch {:?}", error);
                } else {
                    info!("Published epoch {}", i);
                }
            }

            // Perform `num_lookup` random lookup proofs on the published users

            // Pick a set of users to lookup
            let mut labels = Vec::new();
            for user in users.iter().choose_multiple(&mut rng, num_lookups) {
                let label = AkdLabel::from(user);
                labels.push(label);
            }

            log::warn!("Metrics after publish(es).");
            reset_mysql_db::<S>(mysql_db).await;

            let start = Instant::now();
            // Lookup selected users one by one
            for label in labels.clone() {
                match dir.lookup(label.clone()).await {
                    Err(error) => panic!("Error looking up user information {:?}", error),
                    Ok((proof, root_hash)) => {
                        let vrf_pk = dir.get_public_key().await.unwrap();
                        if let Err(error) = akd::client::lookup_verify::<TC>(
                            vrf_pk.as_bytes(),
                            root_hash.hash(),
                            root_hash.epoch(),
                            label,
                            proof,
                        ) {
                            panic!("Lookup proof failed to verify {:?}", error);
                        }
                    }
                }
            }
            log::warn!(
                "Individual {} lookups took {}ms.",
                num_lookups,
                start.elapsed().as_millis()
            );

            log::warn!("Metrics after individual lookups:");
            reset_mysql_db::<S>(mysql_db).await;

            let start = Instant::now();
            // Bulk lookup selected users
            match dir.batch_lookup(&labels).await {
                Err(error) => panic!("Error batch looking up user information {:?}", error),
                Ok((proofs, root_hash)) => {
                    assert_eq!(labels.len(), proofs.len());

                    let vrf_pk = dir.get_public_key().await.unwrap();
                    for i in 0..proofs.len() {
                        let label = labels[i].clone();
                        let proof = proofs[i].clone();
                        if let Err(error) = akd::client::lookup_verify::<TC>(
                            vrf_pk.as_bytes(),
                            root_hash.hash(),
                            root_hash.epoch(),
                            label,
                            proof,
                        ) {
                            panic!("Batch lookup failed to verify for index {} {:?}", i, error);
                        }
                    }
                }
            }
            log::warn!(
                "Bulk {} lookups took {}ms.",
                num_lookups,
                start.elapsed().as_millis()
            );

            log::warn!("Metrics after lookup proofs: ");
            reset_mysql_db::<S>(mysql_db).await;
        }
    }
}

// Reset MySQL database by logging metrics which resets the metrics, and flushing cache.
// These allow us to accurately assess the additional efficiency of
// bulk lookup proofs.
async fn reset_mysql_db<S: Database>(mysql_db: &StorageManager<S>) {
    mysql_db.log_metrics(Level::Warn).await;
    mysql_db.flush_cache().await;
}

// ================== Test Suite Utilities ================== //

/// The suite of tests to run against a fully-instantated and storage-backed directory.
/// This will publish 3 epochs of ```num_users``` records and
/// perform 10 random lookup proofs + 2 random history proofs + and audit proof from epochs 1u64 -> 2u64
pub(crate) async fn directory_test_suite<
    TC: Configuration,
    S: Database + 'static,
    V: VRFKeyStorage,
>(
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
                            root_hash.epoch(),
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
