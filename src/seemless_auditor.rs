// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use rand::rngs::OsRng;
use winter_crypto::Hasher;

use crate::{append_only_zks::Azks, storage::Storage, AppendOnlyProof, AzksError, SeemlessError};

pub fn audit_verify<H: Hasher>(
    start_hash: H::Digest,
    end_hash: H::Digest,
    proof: AppendOnlyProof<H>,
) -> Result<(), SeemlessError> {
    verify_append_only::<H>(proof, start_hash, end_hash)
}

pub fn verify_append_only<H: Hasher>(
    proof: AppendOnlyProof<H>,
    start_hash: H::Digest,
    end_hash: H::Digest,
) -> Result<(), SeemlessError> {
    let unchanged_nodes = proof.unchanged_nodes;
    let inserted = proof.inserted;
    let mut rng = OsRng;

    use crate::errors::StorageError;
    use std::collections::HashMap;
    use std::sync::Mutex;

    lazy_static::lazy_static! {
        static ref HASHMAP: Mutex<HashMap<String, String>> = {
            let m = HashMap::new();
            Mutex::new(m)
        };
    }

    struct TempDb;
    impl Storage for TempDb {
        fn set(pos: String, value: String) -> Result<(), StorageError> {
            let mut hashmap = HASHMAP.lock().unwrap();
            hashmap.insert(pos, value);
            Ok(())
        }

        fn get(pos: String) -> Result<String, StorageError> {
            let hashmap = HASHMAP.lock().unwrap();
            hashmap.get(&pos).cloned().ok_or(StorageError::GetError)
        }
    }

    let mut azks = Azks::<H, TempDb>::new(&mut rng)?;
    azks.batch_insert_leaves_helper(unchanged_nodes, true)?;
    let computed_start_root_hash: H::Digest = azks.get_root_hash()?;
    let mut verified = computed_start_root_hash == start_hash;
    azks.batch_insert_leaves_helper(inserted, true)?;
    let computed_end_root_hash: H::Digest = azks.get_root_hash()?;
    verified = verified && (computed_end_root_hash == end_hash);
    if !verified {
        return Err(SeemlessError::AzksErr(
            AzksError::AppendOnlyProofDidNotVerify,
        ));
    }
    Ok(())
}
