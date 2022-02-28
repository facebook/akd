extern crate thread_id;

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use akd::directory::Directory;
use akd::primitives::akd_vrf::AkdVRF;
use akd::storage::types::{AkdLabel, AkdValue};
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

/// The suite of tests to run against a fully-instantated and storage-backed directory.
/// This will publish 3 epochs of ```num_users``` records and
/// perform 10 random lookup proofs + 2 random history proofs + and audit proof from epochs 1u64 -> 2u64
pub(crate) async fn directory_test_suite<S: akd::storage::Storage + Sync + Send, V: AkdVRF>(
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
                    data.push((AkdLabel(value.clone()), AkdValue(format!("{}", i))));
                }

                if let Err(error) = dir.publish::<Blake3>(data, true).await {
                    panic!("Error publishing batch {:?}", error);
                } else {
                    info!("Published epoch {}", i);
                }
            }

            // Perform 10 random lookup proofs on the published users
            let azks = dir.retrieve_current_azks().await.unwrap();
            let root_hash = dir.get_root_hash::<Blake3>(&azks).await.unwrap();

            for user in users.iter().choose_multiple(&mut rng, 10) {
                let key = AkdLabel(user.clone());
                match dir.lookup::<Blake3>(key.clone()).await {
                    Err(error) => panic!("Error looking up user information {:?}", error),
                    Ok(proof) => {
                        let vrf_pk = dir.get_public_key().unwrap();
                        if let Err(error) =
                            akd::client::lookup_verify::<Blake3, V>(vrf_pk, root_hash, key, proof)
                        {
                            panic!("Lookup proof failed to verify {:?}", error);
                        }
                    }
                }
            }
            info!("10 random lookup proofs passed");

            // Perform 2 random history proofs on the published material
            for user in users.iter().choose_multiple(&mut rng, 2) {
                let key = AkdLabel(user.clone());
                match dir.key_history::<Blake3>(&key).await {
                    Err(error) => panic!("Error performing key history retrieval {:?}", error),
                    Ok(proof) => {
                        let (root_hashes, previous_root_hashes) =
                            akd::directory::get_key_history_hashes::<_, Blake3, V>(&dir, &proof)
                                .await
                                .unwrap();
                        let vrf_pk = dir.get_public_key().unwrap();
                        if let Err(error) = akd::client::key_history_verify::<Blake3, V>(
                            vrf_pk,
                            root_hashes,
                            previous_root_hashes,
                            key,
                            proof,
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
                    let start_root_hash = dir.get_root_hash_at_epoch::<Blake3>(&azks, 1u64).await;
                    let end_root_hash = dir.get_root_hash_at_epoch::<Blake3>(&azks, 2u64).await;
                    match (start_root_hash, end_root_hash) {
                        (Ok(start), Ok(end)) => {
                            if let Err(error) = akd::auditor::audit_verify(start, end, proof).await
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
