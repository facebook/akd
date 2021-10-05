use rand::rngs::OsRng;
use winter_crypto::Hasher;

use crate::{
    append_only_zks::Azks,
    seemless_client::{verify_membership, verify_nonmembership},
    seemless_directory::{get_marker_version, Username},
    storage::Storage,
    AppendOnlyProof, AzksError, LookupProof, SeemlessError,
};

pub fn lookup_verify<H: Hasher>(
    root_hash: H::Digest,
    _uname: Username,
    proof: LookupProof<H>,
) -> Result<(), SeemlessError> {
    let _epoch = proof.epoch;

    let _plaintext_value = proof.plaintext_value;
    let version = proof.version;

    let _marker_version = 1 << get_marker_version(version);
    let existence_proof = proof.existence_proof;
    let marker_proof = proof.marker_proof;
    let freshness_proof = proof.freshness_proof;
    /*
    // These need to be changed to VRF verifications later.
    let existence_label = SeemlessDirectory::<S, H>::get_nodelabel(&uname, false, version);
    if existence_label != existence_proof.label {
        return Err(SeemlessError::SeemlessDirectoryErr(
            SeemlessDirectoryError::LookupVerificationErr(
                "Existence proof label does not match computed label".to_string(),
            ),
        ));
    }
    let non_existence_label = SeemlessDirectory::<S, H>::get_nodelabel(&uname, true, version);
    if non_existence_label != freshness_proof.label {
        return Err(SeemlessError::SeemlessDirectoryErr(
            SeemlessDirectoryError::LookupVerificationErr(
                "Freshness proof label does not match computed label".to_string(),
            ),
        ));
    }
    let marker_label = SeemlessDirectory::<S, H>::get_nodelabel(&uname, false, marker_version);
    if marker_label != marker_proof.label {
        return Err(SeemlessError::SeemlessDirectoryErr(
            SeemlessDirectoryError::LookupVerificationErr(
                "Marker proof label does not match computed label".to_string(),
            ),
        ));
    }
    */
    verify_membership::<H>(root_hash, &existence_proof)?;
    verify_membership::<H>(root_hash, &marker_proof)?;

    verify_nonmembership::<H>(root_hash, &freshness_proof)?;

    Ok(())
}

pub fn audit_verify<H: Hasher, S: Storage>(
    start_hash: H::Digest,
    end_hash: H::Digest,
    proof: AppendOnlyProof<H>,
) -> Result<(), SeemlessError> {
    verify_append_only::<H, S>(proof, start_hash, end_hash)
}

pub fn verify_append_only<H: Hasher, S: Storage>(
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
