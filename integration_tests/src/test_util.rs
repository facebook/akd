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

use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
type Blake3 = Blake3_256<BaseElement>;

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
                panic!("Error initializing multi-logger {}", error);
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
                format!(" ({}:{})", target_str, line)
            } else {
                format!(" ({})", target_str)
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
    let _ = writeln!(io, "{}", msg);
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

// FIXME: We actually probably want to use this. Figure out later.
/// The suite of tests to run against a fully-instantated and storage-backed directory.
/// This will publish 3 epochs of ```num_users``` records and
/// perform 10 random lookup proofs + 2 random history proofs + and audit proof from epochs 1u64 -> 2u64
#[allow(unused)]
pub(crate) async fn directory_test_suite<
    S: akd::storage::Storage + Sync + Send,
    V: VRFKeyStorage,
>(
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
            info!("AKD Directory started. Beginning tests");

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
                } else {
                    info!("Published epoch {}", i);
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
            info!("10 random lookup proofs passed");

            // Perform 2 random history proofs on the published material
            for user in users.iter().choose_multiple(&mut rng, 2) {
                let key = AkdLabel::from_utf8_str(user);
                match dir.key_history::<Blake3>(&key).await {
                    Err(error) => panic!("Error performing key history retrieval {:?}", error),
                    Ok(proof) => {
                        let (root_hash, current_epoch) =
                            akd::directory::get_directory_root_hash_and_ep::<_, Blake3, V>(&dir)
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

            info!("2 random history proofs passed");

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
            info!("Audit proof from 1u64 -> 2u64 passed");
        }
    }
}

pub(crate) async fn test_lookups<S: akd::storage::Storage + Sync + Send, V: VRFKeyStorage>(
    mysql_db: &S,
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
    let maybe_dir = Directory::<_, _>::new::<Blake3>(mysql_db, vrf, false).await;
    match maybe_dir {
        Err(akd_error) => panic!("Error initializing directory: {:?}", akd_error),
        Ok(dir) => {
            info!("AKD Directory started. Beginning tests");

            // Publish `num_epochs` epochs of user material
            for i in 1..=num_epochs {
                let mut data = Vec::new();
                for value in users.iter() {
                    data.push((
                        AkdLabel::from_utf8_str(value),
                        AkdValue(format!("{}", i).as_bytes().to_vec()),
                    ));
                }

                if let Err(error) = dir.publish::<Blake3>(data).await {
                    panic!("Error publishing batch {:?}", error);
                } else {
                    info!("Published epoch {}", i);
                }
            }

            // Perform `num_lookup` random lookup proofs on the published users
            let azks = dir.retrieve_current_azks().await.unwrap();
            let root_hash = dir.get_root_hash::<Blake3>(&azks).await.unwrap();

            // Pick a set of users to lookup
            let mut labels = Vec::new();
            for user in users.iter().choose_multiple(&mut rng, num_lookups) {
                let label = AkdLabel::from_utf8_str(user);
                labels.push(label);
            }

            println!("Metrics after publish(es).");
            reset_mysql_db::<S>(mysql_db).await;

            let start = Instant::now();
            // Lookup selected users one by one
            for label in labels.clone() {
                match dir.lookup::<Blake3>(label.clone()).await {
                    Err(error) => panic!("Error looking up user information {:?}", error),
                    Ok(proof) => {
                        let vrf_pk = dir.get_public_key().await.unwrap();
                        if let Err(error) =
                            akd::client::lookup_verify::<Blake3>(&vrf_pk, root_hash, label, proof)
                        {
                            panic!("Lookup proof failed to verify {:?}", error);
                        }
                    }
                }
            }
            println!(
                "Individual {} lookups took {}ms.",
                num_lookups,
                start.elapsed().as_millis()
            );

            println!("Metrics after individual lookups:");
            reset_mysql_db::<S>(mysql_db).await;

            let start = Instant::now();
            // Bulk lookup selected users
            match dir.batch_lookup::<Blake3>(&labels).await {
                Err(error) => panic!("Error batch looking up user information {:?}", error),
                Ok(proofs) => {
                    assert_eq!(labels.len(), proofs.len());

                    let vrf_pk = dir.get_public_key().await.unwrap();
                    for i in 0..proofs.len() {
                        let label = labels[i].clone();
                        let proof = proofs[i].clone();
                        if let Err(error) =
                            akd::client::lookup_verify::<Blake3>(&vrf_pk, root_hash, label, proof)
                        {
                            panic!("Batch lookup failed to verify for index {} {:?}", i, error);
                        }
                    }
                }
            }
            println!(
                "Bulk {} lookups took {}ms.",
                num_lookups,
                start.elapsed().as_millis()
            );

            println!("Metrics after lookup proofs: ");
            reset_mysql_db::<S>(mysql_db).await;
        }
    }
}

// Reset MySQL database by logging metrics which resets the metrics, and flushing cache.
// These allow us to accurately assess the additional efficiency of
// bulk lookup proofs.
async fn reset_mysql_db<S: akd::storage::Storage + Sync + Send>(mysql_db: &S) {
    mysql_db.log_metrics(Level::Trace).await;
    mysql_db.flush_cache().await;
}
