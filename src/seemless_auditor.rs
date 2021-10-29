use rand::rngs::OsRng;
use winter_crypto::Hasher;

use crate::{
    append_only_zks::Azks,
    errors::{AzksError, SeemlessError},
    proof_structs::AppendOnlyProof,
    storage::Storage,
};

/// This function is simply a wrapper around the function [`verify_append_only`],
/// to audit the transition from the starting epoch to the ending epoch, to ensure that
/// no previously committed items were removed from the tree.
pub fn audit_verify<H: Hasher>(
    start_hash: H::Digest,
    end_hash: H::Digest,
    proof: AppendOnlyProof<H>,
) -> Result<(), SeemlessError> {
    verify_append_only::<H>(proof, start_hash, end_hash)
}

/// This function verifies an append only proof by constructing,
/// first, an [`Azks`], using the roots of unchanged trees from the starting epoch
/// and then inserting the leaves that were purportedly inserted up until the ending epoch.
/// The `start_hash` and `end_hash` are the root hashes for `start_epoch` and `end_epoch`
/// respectively. The `start_hash` must equal the root of the purported initial tree and
/// the `end_hash` the root of the final tree.
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
            Ok(hashmap
                .get(&pos)
                .map(|v| v.clone())
                .ok_or(StorageError::GetError)?)
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
