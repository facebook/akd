// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implementation of a auditable key directory

use crate::append_only_zks::Azks;

use crate::node_state::{Node, NodeLabel};
use crate::primitives::akd_vrf::AkdVRF;
use crate::proof_structs::*;

use crate::errors::{AkdError, DirectoryError, HistoryTreeNodeError, StorageError};

use crate::serialization::from_digest;
use crate::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
use crate::storage::Storage;

use log::{debug, error, info};
use rand::{CryptoRng, RngCore};

use std::collections::HashMap;
use std::marker::{Send, Sync};
use std::sync::Arc;
use winter_crypto::Hasher;

/// Root hash of the tree and its associated epoch
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct EpochHash<H: Hasher>(pub u64, pub H::Digest);

impl AkdValue {
    /// Gets a random value for a AKD
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(get_random_str(rng))
    }
}

impl AkdLabel {
    /// Creates a random key for a AKD
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(get_random_str(rng))
    }
}

/// The representation of a auditable key directory
#[derive(Clone)]
pub struct Directory<S, V> {
    storage: S,
    vrf: V,
    read_only: bool,
    /// The cache lock guarantees that the cache is not
    /// flushed mid-proof generation. We allow multiple proof generations
    /// to occur (RwLock.read() operations can have multiple) but we want
    /// to make sure no generations are underway when a cache flush occurs
    /// (in this case we do utilize the write() lock which can only occur 1
    /// at a time and gates further read() locks being acquired during write()).
    cache_lock: Arc<tokio::sync::RwLock<()>>,
}

impl<S: Storage + Sync + Send, V: AkdVRF> Directory<S, V> {
    /// Creates a new (stateless) instance of a auditable key directory.
    /// Takes as input a pointer to the storage being used for this instance.
    /// The state is stored in the storage.
    pub async fn new<H: Hasher>(storage: &S, vrf: &V, read_only: bool) -> Result<Self, AkdError> {
        let azks = Directory::<S, V>::get_azks_from_storage(storage, false).await;

        if read_only && azks.is_err() {
            return Err(AkdError::Directory(DirectoryError::Storage(
                StorageError::GetData(
                    "AZKS record not found and Directory constructed in read-only mode".to_string(),
                ),
            )));
        } else if azks.is_err() {
            // generate a new azks if one is not found
            let azks = Azks::new::<_, H>(storage).await?;
            // store it
            storage.set(DbRecord::Azks(azks.clone())).await?;
        }

        Ok(Directory {
            storage: storage.clone(),
            read_only,
            cache_lock: Arc::new(tokio::sync::RwLock::new(())),
            vrf: vrf.clone(),
        })
    }

    /// Updates the directory to include the updated key-value pairs.
    pub async fn publish<H: Hasher>(
        &self,
        updates: Vec<(AkdLabel, AkdValue)>,
        use_transaction: bool,
    ) -> Result<EpochHash<H>, AkdError> {
        if self.read_only {
            return Err(AkdError::Directory(DirectoryError::Storage(
                StorageError::SetData(
                    "Directory cannot publish when created in read-only mode!".to_string(),
                ),
            )));
        }

        // The guard will be dropped at the end of the publish
        let _guard = self.cache_lock.read().await;

        let mut update_set = Vec::<Node<H>>::new();
        let mut user_data_update_set = Vec::<ValueState>::new();

        let mut current_azks = self.retrieve_current_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let next_epoch = current_epoch + 1;

        let mut keys: Vec<AkdLabel> = updates.iter().map(|(uname, _val)| uname.clone()).collect();
        // sort the keys, as inserting in primary-key order is more efficient for MySQL
        keys.sort_by(|a, b| a.0.cmp(&b.0));

        // we're only using the maximum "version" of the user's state at the last epoch
        // they were seen in the directory. Therefore we've minimized the call to only
        // return a hashmap of AkdLabel => u64 and not retrieving the other data which is not
        // read (i.e. the actual _data_ payload).
        let all_user_versions_retrieved = self
            .storage
            .get_user_state_versions(&keys, ValueStateRetrievalFlag::LeqEpoch(current_epoch))
            .await?;

        info!(
            "Retrieved {} previous user versions of {} requested",
            all_user_versions_retrieved.len(),
            keys.len()
        );

        for (uname, val) in updates {
            match all_user_versions_retrieved.get(&uname) {
                None => {
                    // no data found for the user
                    let latest_version = 1;
                    let label = self.get_nodelabel::<H>(&uname, false, latest_version)?;
                    // Currently there's no blinding factor for the commitment.
                    // We'd want to change this later.
                    let value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push(Node::<H> {
                        label,
                        hash: value_to_add,
                    });
                    let latest_state =
                        ValueState::new(uname, val, latest_version, label, next_epoch);
                    user_data_update_set.push(latest_state);
                }
                Some(previous_version) => {
                    // Data found for the given user
                    let latest_version = *previous_version + 1;
                    let stale_label = self.get_nodelabel::<H>(&uname, true, *previous_version)?;
                    let fresh_label = self.get_nodelabel::<H>(&uname, false, latest_version)?;
                    let stale_value_to_add = H::hash(&[0u8]);
                    let fresh_value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push(Node::<H> {
                        label: stale_label,
                        hash: stale_value_to_add,
                    });
                    update_set.push(Node::<H> {
                        label: fresh_label,
                        hash: fresh_value_to_add,
                    });
                    let new_state =
                        ValueState::new(uname, val, latest_version, fresh_label, next_epoch);
                    user_data_update_set.push(new_state);
                }
            }
        }
        let insertion_set: Vec<Node<H>> = update_set.to_vec();

        if use_transaction {
            if let false = self.storage.begin_transaction().await {
                error!("Transaction is already active");
                return Err(AkdError::HistoryTreeNode(HistoryTreeNodeError::Storage(
                    StorageError::SetData("Transaction is already active".to_string()),
                )));
            }
        }
        info!("Starting database insertion");

        current_azks
            .batch_insert_leaves::<_, H>(&self.storage, insertion_set)
            .await?;

        // batch all the inserts into a single transactional write to storage
        let mut updates = vec![DbRecord::Azks(current_azks.clone())];
        for update in user_data_update_set.into_iter() {
            updates.push(DbRecord::ValueState(update));
        }
        self.storage.batch_set(updates).await?;
        if use_transaction {
            debug!("Committing transaction");
            if let Err(err) = self.storage.commit_transaction().await {
                // ignore any rollback error(s)
                let _ = self.storage.rollback_transaction().await;
                return Err(AkdError::HistoryTreeNode(HistoryTreeNodeError::Storage(
                    err,
                )));
            } else {
                debug!("Transaction committed");
            }
        }

        let root_hash = current_azks
            .get_root_hash_at_epoch::<_, H>(&self.storage, next_epoch)
            .await?;

        self.storage.log_metrics(log::Level::Info).await;

        Ok(EpochHash(current_epoch, root_hash))
        // At the moment the tree root is not being written anywhere. Eventually we
        // want to change this to call a write operation to post to a blockchain or some such thing
    }

    /// Provides proof for correctness of latest version
    pub async fn lookup<H: Hasher>(&self, uname: AkdLabel) -> Result<LookupProof<H>, AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_current_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        match self
            .storage
            .get_user_state(&uname, ValueStateRetrievalFlag::LeqEpoch(current_epoch))
            .await
        {
            Err(_) => {
                // Need to throw an error
                Err(AkdError::Directory(DirectoryError::NonExistentUser(
                    uname.0,
                    current_epoch,
                )))
            }
            Ok(latest_st) => {
                // Need to account for the case where the latest state is
                // added but the database is in the middle of an update
                let current_version = latest_st.version;
                let marker_version = 1 << get_marker_version(current_version);
                let existent_label = self.get_nodelabel::<H>(&uname, false, current_version)?;
                let marker_label = self.get_nodelabel::<H>(&uname, false, marker_version)?;
                let non_existent_label = self.get_nodelabel::<H>(&uname, true, current_version)?;
                let current_azks = self.retrieve_current_azks().await?;
                Ok(LookupProof {
                    epoch: current_epoch,
                    plaintext_value: latest_st.plaintext_val,
                    version: current_version,
                    exisitence_vrf_proof: self.get_label_proof::<H>(
                        &uname,
                        false,
                        current_version,
                    )?,
                    existence_proof: current_azks
                        .get_membership_proof(&self.storage, existent_label, current_epoch)
                        .await?,
                    marker_vrf_proof: self.get_label_proof::<H>(&uname, false, marker_version)?,
                    marker_proof: current_azks
                        .get_membership_proof(&self.storage, marker_label, current_epoch)
                        .await?,
                    freshness_vrf_proof: self.get_label_proof::<H>(
                        &uname,
                        true,
                        current_version,
                    )?,
                    freshness_proof: current_azks
                        .get_non_membership_proof(&self.storage, non_existent_label, current_epoch)
                        .await?,
                })
            }
        }
    }

    /// Takes in the current state of the server and a label.
    /// If the label is present in the current state,
    /// this function returns all the values ever associated with it,
    /// and the epoch at which each value was first committed to the server state.
    /// It also returns the proof of the latest version being served at all times.
    pub async fn key_history<H: Hasher>(
        &self,
        uname: &AkdLabel,
    ) -> Result<HistoryProof<H>, AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let username = uname.0.to_string();
        let current_azks = self.retrieve_current_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        if let Ok(this_user_data) = self.storage.get_user_data(uname).await {
            let mut proofs = Vec::<UpdateProof<H>>::new();
            for user_state in &this_user_data.states {
                // Ignore states in storage that are ahead of current directory epoch
                if user_state.epoch <= current_epoch {
                    let proof = self.create_single_update_proof(uname, user_state).await?;
                    proofs.push(proof);
                }
            }
            Ok(HistoryProof { proofs })
        } else {
            Err(AkdError::Directory(DirectoryError::NonExistentUser(
                username,
                current_epoch,
            )))
        }
    }

    /// Poll for changes in the epoch number of the AZKS struct
    /// stored in the storage layer. If an epoch change is detected,
    /// the object cache (if present) is flushed immediately so
    /// that new objects are retrieved from the storage layer against
    /// the "latest" epoch. There is a "special" flow in the storage layer
    /// to do a storage-layer retrieval which ignores the cache
    pub async fn poll_for_azks_changes(
        &self,
        period: tokio::time::Duration,
        change_detected: Option<tokio::sync::mpsc::Sender<()>>,
    ) -> Result<(), AkdError> {
        // Retrieve the same AZKS that all the other calls see (i.e. the version that could be cached
        // at this point). We'll compare this via an uncached call when a change is notified
        let mut last = Directory::<S, V>::get_azks_from_storage(&self.storage, false).await?;

        loop {
            // loop forever polling for changes
            tokio::time::sleep(period).await;

            let latest = Directory::<S, V>::get_azks_from_storage(&self.storage, true).await?;
            if latest.latest_epoch > last.latest_epoch {
                {
                    // acquire a singleton lock prior to flushing the cache to assert that no
                    // cache accesses are underway (i.e. publish/proof generations/etc)
                    let _guard = self.cache_lock.write().await;
                    // flush the cache in its entirety
                    self.storage.flush_cache().await;
                    // re-fetch the azks to load it into cache so when we release the cache lock
                    // others will see the new AZKS loaded up and ready
                    last = Directory::<S, V>::get_azks_from_storage(&self.storage, false).await?;

                    // notify change occurred
                    if let Some(channel) = &change_detected {
                        channel.send(()).await.map_err(|send_err| AkdError::Directory(DirectoryError::Storage(StorageError::Connection(format!("Tokio MPSC sender failed to publish notification with error {:?}", send_err)))))?;
                    }
                    // drop the guard
                }
            }
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    /// Returns an AppendOnlyProof for the leaves inserted into the underlying tree between
    /// the epochs audit_start_ep and audit_end_ep.
    pub async fn audit<H: Hasher>(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<AppendOnlyProof<H>, AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_current_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        if audit_start_ep >= audit_end_ep {
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "Start epoch {} is greater than or equal the end epoch {}",
                audit_start_ep, audit_end_ep
            ))))
        } else if current_epoch < audit_end_ep {
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "End epoch {} is greater than the current epoch {}",
                audit_end_ep, current_epoch
            ))))
        } else {
            current_azks
                .get_append_only_proof::<_, H>(&self.storage, audit_start_ep, audit_end_ep)
                .await
        }
    }

    /// Retrieves the current azks
    pub async fn retrieve_current_azks(&self) -> Result<Azks, crate::errors::AkdError> {
        Directory::<S, V>::get_azks_from_storage(&self.storage, false).await
    }

    async fn get_azks_from_storage(
        storage: &S,
        ignore_cache: bool,
    ) -> Result<Azks, crate::errors::AkdError> {
        let got = if ignore_cache {
            storage
                .get_direct::<Azks>(crate::append_only_zks::DEFAULT_AZKS_KEY)
                .await?
        } else {
            storage
                .get::<Azks>(crate::append_only_zks::DEFAULT_AZKS_KEY)
                .await?
        };
        match got {
            DbRecord::Azks(azks) => Ok(azks),
            _ => {
                error!("No AZKS can be found. You should re-initialize the directory to create a new one");
                Err(crate::errors::AkdError::AzksNotFound(String::from(
                    "AZKS not found in storage.",
                )))
            }
        }
    }

    /// HELPERS ///

    #[allow(unused)]
    fn username_to_nodelabel(_uname: &AkdLabel) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    // FIXME: we need to make this only work on the server, use a VRF and have another function
    // that verifies nodelabel.
    /// Returns the tree nodelabel that corresponds to a version of the akdkey argument.
    /// The stale boolean here is to indicate whether we are getting the nodelabel for a fresh version,
    /// or a version that we are retiring.
    pub(crate) fn get_nodelabel<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<NodeLabel, DirectoryError> {
        // Get the VRF secret key from the AkdVRF
        let secret_key = self.vrf.get_secret_key()?;

        let name_hash_bytes = H::hash(uname.0.as_bytes());
        let mut stale_bytes = &[1u8];
        if stale {
            stale_bytes = &[0u8];
        }

        let hashed_label = H::merge(&[
            name_hash_bytes,
            H::merge_with_int(H::hash(stale_bytes), version),
        ]);
        let message_vec = from_digest::<H>(hashed_label).unwrap();
        let message: &[u8] = message_vec.as_slice();

        // VRF proof and hash output
        let pi = V::prove(secret_key, message)?;
        let hash = vec_to_u8_arr(V::vrf_to_hash(&pi, message)?);

        Ok(NodeLabel::new(hash, 256u32))
    }

    pub(crate) fn get_label_proof<H: Hasher>(
        &self,
        uname: &AkdLabel,
        stale: bool,
        version: u64,
    ) -> Result<Vec<u8>, DirectoryError> {
        // Get the VRF secret key from the AkdVRF
        let secret_key = self.vrf.get_secret_key()?;

        let name_hash_bytes = H::hash(uname.0.as_bytes());
        let mut stale_bytes = &[1u8];
        if stale {
            stale_bytes = &[0u8];
        }

        let hashed_label = H::merge(&[
            name_hash_bytes,
            H::merge_with_int(H::hash(stale_bytes), version),
        ]);

        let message_vec = from_digest::<H>(hashed_label).unwrap();
        let message: &[u8] = message_vec.as_slice();

        // VRF proof
        Ok(V::prove(secret_key, message)?)
    }

    /// Use this function to retrieve the VRF public key for this AKD.
    pub fn get_public_key(&self) -> Result<V::PK, DirectoryError> {
        Ok(self.vrf.get_public_key()?)
    }

    // FIXME: Make a real commitment here, alongwith a blinding factor. See issue #123
    /// Gets the bytes for a value.
    pub fn value_to_bytes(_value: &AkdValue) -> [u8; 64] {
        [0u8; 64]
        // unimplemented!()
    }

    async fn create_single_update_proof<H: Hasher>(
        &self,
        uname: &AkdLabel,
        user_state: &ValueState,
    ) -> Result<UpdateProof<H>, AkdError> {
        let epoch = user_state.epoch;
        let plaintext_value = &user_state.plaintext_val;
        let version = &user_state.version;

        let label_at_ep = self.get_nodelabel::<H>(uname, false, *version)?;

        let current_azks = self.retrieve_current_azks().await?;
        let existence_vrf_proof = self.get_label_proof::<H>(uname, false, *version)?;
        let existence_at_ep = current_azks
            .get_membership_proof(&self.storage, label_at_ep, epoch)
            .await?;
        let mut previous_val_stale_at_ep = Option::None;
        let mut previous_val_vrf_proof = Option::None;
        if *version > 1 {
            let prev_label_at_ep = self.get_nodelabel::<H>(uname, true, *version - 1)?;
            previous_val_stale_at_ep = Option::Some(
                current_azks
                    .get_membership_proof(&self.storage, prev_label_at_ep, epoch)
                    .await?,
            );
            previous_val_vrf_proof =
                Option::Some(self.get_label_proof::<H>(uname, true, *version - 1)?);
        }
        let mut non_existence_before_ep = Option::None;
        if epoch != 0 {
            non_existence_before_ep = Option::Some(
                current_azks
                    .get_non_membership_proof(&self.storage, label_at_ep, epoch - 1)
                    .await?,
            );
        }

        let next_marker = get_marker_version(*version) + 1;
        let final_marker = get_marker_version(epoch);

        let mut next_few_vrf_proofs = Vec::<Vec<u8>>::new();
        let mut non_existence_of_next_few = Vec::<NonMembershipProof<H>>::new();

        for ver in version + 1..(1 << next_marker) {
            let label_for_ver = self.get_nodelabel::<H>(uname, false, ver)?;
            let non_existence_of_ver = current_azks
                .get_non_membership_proof(&self.storage, label_for_ver, epoch)
                .await?;
            non_existence_of_next_few.push(non_existence_of_ver);
            next_few_vrf_proofs.push(self.get_label_proof::<H>(uname, false, ver)?);
        }

        let mut future_marker_vrf_proofs = Vec::<Vec<u8>>::new();
        let mut non_existence_of_future_markers = Vec::<NonMembershipProof<H>>::new();

        for marker_power in next_marker..final_marker + 1 {
            let ver = 1 << marker_power;
            let label_for_ver = self.get_nodelabel::<H>(uname, false, ver)?;
            let non_existence_of_ver = current_azks
                .get_non_membership_proof(&self.storage, label_for_ver, epoch)
                .await?;
            non_existence_of_future_markers.push(non_existence_of_ver);
            future_marker_vrf_proofs.push(self.get_label_proof::<H>(uname, false, ver)?);
        }

        Ok(UpdateProof {
            epoch,
            plaintext_value: plaintext_value.clone(),
            version: *version,
            existence_vrf_proof,
            existence_at_ep,
            previous_val_vrf_proof,
            previous_val_stale_at_ep,
            non_existence_before_ep,
            next_few_vrf_proofs,
            non_existence_of_next_few,
            future_marker_vrf_proofs,
            non_existence_of_future_markers,
        })
    }

    /// Gets the azks root hash at the provided epoch. Note that the root hash should exist at any epoch
    /// that the azks existed, so as long as epoch >= 0, we should be fine.
    pub async fn get_root_hash_at_epoch<H: Hasher>(
        &self,
        current_azks: &Azks,
        epoch: u64,
    ) -> Result<H::Digest, AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        Ok(current_azks
            .get_root_hash_at_epoch::<_, H>(&self.storage, epoch)
            .await?)
    }

    /// Gets the azks root hash at the current epoch.
    pub async fn get_root_hash<H: Hasher>(
        &self,
        current_azks: &Azks,
    ) -> Result<H::Digest, AkdError> {
        self.get_root_hash_at_epoch::<H>(current_azks, current_azks.get_latest_epoch())
            .await
    }
}

/// Helpers

pub(crate) fn get_marker_version(version: u64) -> u64 {
    (64 - version.leading_zeros() - 1).into()
}

fn get_random_str<R: RngCore + CryptoRng>(rng: &mut R) -> String {
    let mut byte_str = [0u8; 32];
    rng.fill_bytes(&mut byte_str);
    format!("{:?}", &byte_str)
}

type KeyHistoryHelper<D> = (Vec<D>, Vec<Option<D>>);

/// Gets hashes for key history proofs
pub async fn get_key_history_hashes<S: Storage + Sync + Send, H: Hasher, V: AkdVRF>(
    akd_dir: &Directory<S, V>,
    history_proof: &HistoryProof<H>,
) -> Result<KeyHistoryHelper<H::Digest>, AkdError> {
    let mut epoch_hash_map: HashMap<u64, H::Digest> = HashMap::new();

    let mut root_hashes = Vec::<H::Digest>::new();
    let mut previous_root_hashes = Vec::<Option<H::Digest>>::new();
    let current_azks = akd_dir.retrieve_current_azks().await?;
    for proof in &history_proof.proofs {
        let hash = akd_dir
            .get_root_hash_at_epoch::<H>(&current_azks, proof.epoch)
            .await?;
        epoch_hash_map.insert(proof.epoch, hash);
        root_hashes.push(hash);
    }

    for proof in &history_proof.proofs {
        let epoch_in_question = proof.epoch - 1;
        if epoch_in_question == 0 {
            // edge condition
            previous_root_hashes.push(None);
        } else if let Some(hash) = epoch_hash_map.get(&epoch_in_question) {
            // cache hit
            previous_root_hashes.push(Some(*hash));
        } else {
            // cache miss, fetch it
            let hash = akd_dir
                .get_root_hash_at_epoch::<H>(&current_azks, proof.epoch - 1)
                .await?;
            previous_root_hashes.push(Some(hash));
        }
    }

    Ok((root_hashes, previous_root_hashes))
}

// Note that this is the truncating version, since the only thing being
// verified where this is called is the final hash.
// If the hash function's output is too large, truncating it should be ok.
// tl;dr TRUNCATES!
fn vec_to_u8_arr(vector_u8: Vec<u8>) -> [u8; 32] {
    let mut out_arr = [0u8; 32];
    out_arr[..vector_u8.len()].clone_from_slice(&vector_u8[..32]);
    out_arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auditor::audit_verify,
        client::{key_history_verify, lookup_verify},
        primitives::{
            akd_vrf::HardCodedAkdVRF,
            client_vrf::{ClientVRF, HardCodedClientVRF},
        },
        storage::memory::AsyncInMemoryDatabase,
    };
    use winter_crypto::{hashers::Blake3_256, Digest};
    use winter_math::fields::f128::BaseElement;
    type Blake3 = Blake3_256<BaseElement>;

    #[tokio::test]
    async fn test_empty_tree_root_hash() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3_256<BaseElement>>(&db, &vrf, false).await?;

        let current_azks = akd.retrieve_current_azks().await?;
        let hash = akd
            .get_root_hash::<Blake3_256<BaseElement>>(&current_azks)
            .await?;

        // Ensuring that the root hash of an empty tree is equal to the following constant
        assert_eq!(
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            hex::encode(hash.as_bytes())
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_simple_publish() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        akd.publish::<Blake3>(
            vec![(AkdLabel("hello".to_string()), AkdValue("world".to_string()))],
            false,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_simple_lookup() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        akd.publish::<Blake3>(
            vec![
                (AkdLabel("hello".to_string()), AkdValue("world".to_string())),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        let lookup_proof = akd.lookup(AkdLabel("hello".to_string())).await?;
        let current_azks = akd.retrieve_current_azks().await?;
        let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
        let vrf_pk = akd.get_public_key()?;
        lookup_verify::<Blake3, HardCodedClientVRF>(
            vrf_pk,
            root_hash,
            AkdLabel("hello".to_string()),
            lookup_proof,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_simple_key_history() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        akd.publish::<Blake3>(
            vec![
                (AkdLabel("hello".to_string()), AkdValue("world".to_string())),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (AkdLabel("hello".to_string()), AkdValue("world".to_string())),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello".to_string()),
                    AkdValue("world3".to_string()),
                ),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world4".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello3".to_string()),
                    AkdValue("world".to_string()),
                ),
                (
                    AkdLabel("hello4".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![(
                AkdLabel("hello".to_string()),
                AkdValue("world_updated".to_string()),
            )],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello3".to_string()),
                    AkdValue("world6".to_string()),
                ),
                (
                    AkdLabel("hello4".to_string()),
                    AkdValue("world12".to_string()),
                ),
            ],
            false,
        )
        .await?;

        let history_proof = akd.key_history(&AkdLabel("hello".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        let vrf_pk = akd.get_public_key()?;
        key_history_verify::<Blake3, HardCodedClientVRF>(
            vrf_pk.clone(),
            root_hashes,
            previous_root_hashes,
            AkdLabel("hello".to_string()),
            history_proof,
        )?;

        let history_proof = akd.key_history(&AkdLabel("hello2".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3, HardCodedClientVRF>(
            vrf_pk.clone(),
            root_hashes,
            previous_root_hashes,
            AkdLabel("hello2".to_string()),
            history_proof,
        )?;

        let history_proof = akd.key_history(&AkdLabel("hello3".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3, HardCodedClientVRF>(
            vrf_pk.clone(),
            root_hashes,
            previous_root_hashes,
            AkdLabel("hello3".to_string()),
            history_proof,
        )?;

        let history_proof = akd.key_history(&AkdLabel("hello4".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3, HardCodedClientVRF>(
            vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel("hello4".to_string()),
            history_proof,
        )?;

        Ok(())
    }

    #[allow(unused)]
    #[tokio::test]
    async fn test_simple_audit() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let mut akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        akd.publish::<Blake3>(
            vec![
                (AkdLabel("hello".to_string()), AkdValue("world".to_string())),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (AkdLabel("hello".to_string()), AkdValue("world".to_string())),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello".to_string()),
                    AkdValue("world3".to_string()),
                ),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world4".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello3".to_string()),
                    AkdValue("world".to_string()),
                ),
                (
                    AkdLabel("hello4".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![(
                AkdLabel("hello".to_string()),
                AkdValue("world_updated".to_string()),
            )],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello3".to_string()),
                    AkdValue("world6".to_string()),
                ),
                (
                    AkdLabel("hello4".to_string()),
                    AkdValue("world12".to_string()),
                ),
            ],
            false,
        )
        .await?;

        let current_azks = akd.retrieve_current_azks().await?;

        let audit_proof_1 = akd.audit(1, 2).await?;
        audit_verify::<Blake3>(
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 1)
                .await?,
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 2)
                .await?,
            audit_proof_1,
        )
        .await?;

        let audit_proof_2 = akd.audit(1, 3).await?;
        audit_verify::<Blake3>(
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 1)
                .await?,
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 3)
                .await?,
            audit_proof_2,
        )
        .await?;

        let audit_proof_3 = akd.audit(1, 4).await?;
        audit_verify::<Blake3>(
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 1)
                .await?,
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 4)
                .await?,
            audit_proof_3,
        )
        .await?;

        let audit_proof_4 = akd.audit(1, 5).await?;
        audit_verify::<Blake3>(
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 1)
                .await?,
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 5)
                .await?,
            audit_proof_4,
        )
        .await?;

        let audit_proof_5 = akd.audit(2, 3).await?;
        audit_verify::<Blake3>(
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 2)
                .await?,
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 3)
                .await?,
            audit_proof_5,
        )
        .await?;

        let audit_proof_6 = akd.audit(2, 4).await?;
        audit_verify::<Blake3>(
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 2)
                .await?,
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 4)
                .await?,
            audit_proof_6,
        )
        .await?;

        let invalid_audit = akd.audit::<Blake3>(3, 3).await;
        assert!(matches!(invalid_audit, Err(_)));

        let invalid_audit = akd.audit::<Blake3>(3, 2).await;
        assert!(matches!(invalid_audit, Err(_)));

        let invalid_audit = akd.audit::<Blake3>(6, 7).await;
        assert!(matches!(invalid_audit, Err(_)));

        Ok(())
    }

    #[tokio::test]
    async fn test_read_during_publish() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        // Publish twice
        akd.publish::<Blake3>(
            vec![
                (AkdLabel("hello".to_string()), AkdValue("world".to_string())),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello".to_string()),
                    AkdValue("world_2".to_string()),
                ),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2_2".to_string()),
                ),
            ],
            false,
        )
        .await?;

        // Make the current azks a "checkpoint" to reset to later
        let checkpoint_azks = akd.retrieve_current_azks().await.unwrap();

        // Publish for the third time
        akd.publish::<Blake3>(
            vec![
                (
                    AkdLabel("hello".to_string()),
                    AkdValue("world_3".to_string()),
                ),
                (
                    AkdLabel("hello2".to_string()),
                    AkdValue("world2_3".to_string()),
                ),
            ],
            false,
        )
        .await?;

        // Reset the azks record back to previous epoch, to emulate an akd reader
        // communicating with storage that is in the middle of a publish operation
        db.set(DbRecord::Azks(checkpoint_azks))
            .await
            .expect("Error resetting directory to previous epoch");
        let current_azks = akd.retrieve_current_azks().await?;
        let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;

        // History proof should not contain the third epoch's update but still verify
        let history_proof = akd
            .key_history::<Blake3>(&AkdLabel("hello".to_string()))
            .await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        assert_eq!(2, root_hashes.len());
        let vrf_pk = vrf.get_public_key()?;

        key_history_verify::<Blake3, HardCodedClientVRF>(
            vrf_pk.clone(),
            root_hashes,
            previous_root_hashes,
            AkdLabel("hello".to_string()),
            history_proof,
        )?;

        // Lookup proof should contain the checkpoint epoch's value and still verify
        let lookup_proof = akd.lookup::<Blake3>(AkdLabel("hello".to_string())).await?;
        assert_eq!(
            AkdValue("world_2".to_string()),
            lookup_proof.plaintext_value
        );
        lookup_verify::<Blake3, HardCodedClientVRF>(
            vrf_pk,
            root_hash,
            AkdLabel("hello".to_string()),
            lookup_proof,
        )?;

        // Audit proof should only work up until checkpoint's epoch
        let audit_proof = akd.audit(1, 2).await?;
        audit_verify::<Blake3>(
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 1)
                .await?,
            akd.get_root_hash_at_epoch::<Blake3>(&current_azks, 2)
                .await?,
            audit_proof,
        )
        .await?;

        let invalid_audit = akd.audit::<Blake3>(2, 3).await;
        assert!(matches!(invalid_audit, Err(_)));

        Ok(())
    }

    #[tokio::test]
    async fn test_directory_read_only_mode() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        // There is no AZKS object in the storage layer, directory construction should fail
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, true).await;
        assert!(matches!(akd, Err(_)));

        // now create the AZKS
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await;
        assert!(matches!(akd, Ok(_)));

        // create another read-only dir now that the AZKS exists in the storage layer, and try to publish which should fail
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, true).await?;
        assert!(matches!(akd.publish::<Blake3>(vec![], true).await, Err(_)));

        Ok(())
    }

    #[tokio::test]
    async fn test_directory_polling_azks_change() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        // writer will write the AZKS record
        let writer = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        writer
            .publish::<Blake3>(
                vec![
                    (AkdLabel("hello".to_string()), AkdValue("world".to_string())),
                    (
                        AkdLabel("hello2".to_string()),
                        AkdValue("world2".to_string()),
                    ),
                ],
                false,
            )
            .await?;

        // reader will not write the AZKS but will be "polling" for AZKS changes
        let reader = Directory::<_, _>::new::<Blake3>(&db, &vrf, true).await?;

        // start the poller
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let reader_clone = reader.clone();
        let _join_handle = tokio::task::spawn(async move {
            reader_clone
                .poll_for_azks_changes(tokio::time::Duration::from_millis(100), Some(tx))
                .await
        });

        // verify a lookup proof, which will populate the cache
        async_poll_helper_proof(&vrf, &reader, AkdValue("world".to_string())).await?;

        // publish epoch 2
        writer
            .publish::<Blake3>(
                vec![
                    (
                        AkdLabel("hello".to_string()),
                        AkdValue("world_2".to_string()),
                    ),
                    (
                        AkdLabel("hello2".to_string()),
                        AkdValue("world2_2".to_string()),
                    ),
                ],
                false,
            )
            .await?;

        // assert that the change is picked up in a reasonable time-frame and the cache is flushed
        let notification =
            tokio::time::timeout(tokio::time::Duration::from_secs(10), rx.recv()).await;
        assert!(matches!(notification, Ok(Some(()))));

        async_poll_helper_proof(&vrf, &reader, AkdValue("world_2".to_string())).await?;

        Ok(())
    }

    /*
    =========== Test Helpers ===========
    */

    async fn async_poll_helper_proof<T: Storage + Sync + Send, V: AkdVRF>(
        vrf: &V,
        reader: &Directory<T, V>,
        value: AkdValue,
    ) -> Result<(), AkdError> {
        // reader should read "hello" and this will populate the "cache" a log
        let lookup_proof = reader.lookup(AkdLabel("hello".to_string())).await?;
        assert_eq!(value, lookup_proof.plaintext_value);
        let current_azks = reader.retrieve_current_azks().await?;
        let root_hash = reader.get_root_hash::<Blake3>(&current_azks).await?;
        let pk = vrf.get_public_key()?;
        lookup_verify::<Blake3, V>(pk, root_hash, AkdLabel("hello".to_string()), lookup_proof)?;
        Ok(())
    }
}
