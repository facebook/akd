// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Directory initialisation and user-entry construction for the basic_lookup example.

use super::AkdDir;
use akd::append_only_zks::AzksParallelismConfig;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue, EpochHash};
use anyhow::Result;

/// Fixed pool of example user accounts. In production, labels would be account
/// identifiers (phone numbers, usernames) and values would be raw public-key bytes
/// exported from a device's secure enclave or key-management system.
const USER_POOL: &[(&str, &str)] = &[
    ("alice@example.com", "alice_public_key_v1"),
    ("bob@example.com", "bob_public_key_v1"),
    ("carol@example.com", "carol_public_key_v1"),
    ("dave@example.com", "dave_public_key_v1"),
    ("erin@example.com", "erin_public_key_v1"),
    ("frank@example.com", "frank_public_key_v1"),
    ("grace@example.com", "grace_public_key_v1"),
    ("heidi@example.com", "heidi_public_key_v1"),
    ("ivan@example.com", "ivan_public_key_v1"),
    ("judy@example.com", "judy_public_key_v1"),
];

/// Initialises an in-memory AKD directory with the WhatsApp v1 configuration.
///
/// `AsyncInMemoryDatabase` stores all Merkle tree nodes in a process-local
/// hash map — sufficient for examples and tests. Replace with a durable
/// `Database` implementation for production (e.g. MySQL, RocksDB).
///
/// `HardCodedAkdVRF` uses a private key compiled into the binary. **Never ship
/// this in production.** Implement `VRFKeyStorage` backed by a secrets manager
/// (AWS KMS, HashiCorp Vault, etc.) instead.
pub(super) async fn init_directory() -> Result<AkdDir> {
    let storage_manager = StorageManager::new_no_cache(AsyncInMemoryDatabase::new());
    let vrf = HardCodedAkdVRF {};
    let akd = AkdDir::new(storage_manager, vrf, AzksParallelismConfig::default()).await?;
    Ok(akd)
}

/// Returns the first `count` users from the pool as:
///   - a `Vec<String>` of label strings (for validation and display)
///   - a `Vec<(AkdLabel, AkdValue)>` ready to pass to `Directory::publish`
pub(super) fn build_entries(count: u8) -> (Vec<String>, Vec<(AkdLabel, AkdValue)>) {
    let labels: Vec<String> = USER_POOL
        .iter()
        .take(count as usize)
        .map(|(label, _)| label.to_string())
        .collect();

    let entries: Vec<(AkdLabel, AkdValue)> = USER_POOL
        .iter()
        .take(count as usize)
        .map(|(label, value)| (AkdLabel::from(*label), AkdValue::from(*value)))
        .collect();

    (labels, entries)
}

/// Publishes `entries` as a single atomic epoch and returns the resulting
/// `EpochHash`. All supplied pairs are committed together, so the returned
/// root hash is a commitment to the entire directory state at that moment.
pub(super) async fn publish_batch(
    akd: &AkdDir,
    entries: Vec<(AkdLabel, AkdValue)>,
) -> Result<EpochHash> {
    let epoch_hash = akd.publish(entries).await?;
    Ok(epoch_hash)
}
