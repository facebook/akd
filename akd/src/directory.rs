// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implementation of a auditable key directory

use crate::append_only_zks::Azks;

use crate::ecvrf::{VRFKeyStorage, VRFPublicKey};
use crate::node_state::Node;
use crate::proof_structs::*;

use crate::errors::{AkdError, DirectoryError, StorageError};

use crate::storage::types::{AkdLabel, AkdValue, DbRecord, ValueState, ValueStateRetrievalFlag};
use crate::storage::Storage;

use log::{debug, error, info};
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};

use crate::node_state::NodeLabel;
use std::collections::HashMap;
use std::marker::{Send, Sync};
use std::sync::Arc;
use winter_crypto::Hasher;

/// Root hash of the tree and its associated epoch
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct EpochHash<H: Hasher>(pub u64, pub H::Digest);

#[derive(Clone)]
/// Info needed for a lookup of a user for an epoch
pub struct LookupInfo {
    value_state: ValueState,
    marker_version: u64,
    existent_label: NodeLabel,
    marker_label: NodeLabel,
    non_existent_label: NodeLabel,
}

#[cfg(feature = "rand")]
impl AkdValue {
    /// Gets a random value for a AKD
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_utf8_str(&get_random_str(rng))
    }
}

#[cfg(feature = "rand")]
impl AkdLabel {
    /// Creates a random key for a AKD
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_utf8_str(&get_random_str(rng))
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

impl<S: Storage + Sync + Send, V: VRFKeyStorage> Directory<S, V> {
    /// Creates a new (stateless) instance of a auditable key directory.
    /// Takes as input a pointer to the storage being used for this instance.
    /// The state is stored in the storage.
    pub async fn new<H: Hasher>(storage: &S, vrf: &V, read_only: bool) -> Result<Self, AkdError> {
        let azks = Directory::<S, V>::get_azks_from_storage(storage, false).await;

        if read_only && azks.is_err() {
            return Err(AkdError::Directory(DirectoryError::ReadOnlyDirectory(
                "Cannot start directory in read-only mode when AZKS is missing".to_string(),
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
    ) -> Result<EpochHash<H>, AkdError> {
        if self.read_only {
            return Err(AkdError::Directory(DirectoryError::ReadOnlyDirectory(
                "Cannot publish while in read-only mode".to_string(),
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
        keys.sort_by(|a, b| a.cmp(b));

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
                    let label = self
                        .vrf
                        .get_node_label::<H>(&uname, false, latest_version)
                        .await?;
                    // Currently there's no blinding factor for the commitment.
                    // We'd want to change this later.
                    let value_to_add = crate::utils::value_to_bytes::<H>(&val);
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
                    let stale_label = self
                        .vrf
                        .get_node_label::<H>(&uname, true, *previous_version)
                        .await?;
                    let fresh_label = self
                        .vrf
                        .get_node_label::<H>(&uname, false, latest_version)
                        .await?;
                    let stale_value_to_add = H::hash(&[0u8]);
                    let fresh_value_to_add = crate::utils::value_to_bytes::<H>(&val);
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

        if let false = self.storage.begin_transaction().await {
            error!("Transaction is already active");
            return Err(AkdError::Storage(StorageError::Transaction(
                "Transaction is already active".to_string(),
            )));
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

        // now commit the transaction
        debug!("Committing transaction");
        if let Err(err) = self.storage.commit_transaction().await {
            // ignore any rollback error(s)
            let _ = self.storage.rollback_transaction().await;
            return Err(AkdError::Storage(err));
        } else {
            debug!("Transaction committed");
        }

        let root_hash = current_azks
            .get_root_hash_at_epoch::<_, H>(&self.storage, next_epoch)
            .await?;

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
        let lookup_info = self
            .get_lookup_info::<H>(uname.clone(), current_epoch)
            .await?;
        let lookup_proof = self
            .lookup_with_info::<H>(uname, &current_azks, current_epoch, lookup_info)
            .await;
        lookup_proof
    }

    async fn lookup_with_info<H: Hasher>(
        &self,
        uname: AkdLabel,
        current_azks: &Azks,
        current_epoch: u64,
        lookup_info: LookupInfo,
    ) -> Result<LookupProof<H>, AkdError> {
        let current_version = lookup_info.value_state.version;

        let lookup_proof = LookupProof {
            epoch: current_epoch,
            plaintext_value: lookup_info.value_state.plaintext_val,
            version: lookup_info.value_state.version,
            exisitence_vrf_proof: self
                .vrf
                .get_label_proof::<H>(&uname, false, current_version)
                .await?
                .to_bytes()
                .to_vec(),
            existence_proof: current_azks
                .get_membership_proof(&self.storage, lookup_info.existent_label, current_epoch)
                .await?,
            marker_vrf_proof: self
                .vrf
                .get_label_proof::<H>(&uname, false, lookup_info.marker_version)
                .await?
                .to_bytes()
                .to_vec(),
            marker_proof: current_azks
                .get_membership_proof(&self.storage, lookup_info.marker_label, current_epoch)
                .await?,
            freshness_vrf_proof: self
                .vrf
                .get_label_proof::<H>(&uname, true, current_version)
                .await?
                .to_bytes()
                .to_vec(),
            freshness_proof: current_azks
                .get_non_membership_proof(
                    &self.storage,
                    lookup_info.non_existent_label,
                    current_epoch,
                )
                .await?,
        };

        Ok(lookup_proof)
    }

    // TODO(eoz): Call proof generations async
    /// Allows efficient batch lookups by preloading necessary nodes for the lookups.
    pub async fn batch_lookup<H: Hasher>(
        &self,
        unames: &[AkdLabel],
    ) -> Result<Vec<LookupProof<H>>, AkdError> {
        let current_azks = self.retrieve_current_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        // Take a union of the labels we will need proofs of for each lookup.
        let mut lookup_labels = Vec::new();
        let mut lookup_infos = Vec::new();
        for uname in unames {
            // Save lookup info for later use.
            let lookup_info = self
                .get_lookup_info::<H>(uname.clone(), current_epoch)
                .await?;
            lookup_infos.push(lookup_info.clone());

            // A lookup proofs consists of the proofs for the following labels.
            lookup_labels.push(lookup_info.existent_label);
            lookup_labels.push(lookup_info.marker_label);
            lookup_labels.push(lookup_info.non_existent_label);
        }

        // Create a union of set of prefixes we will need for lookups.
        let lookup_prefixes_set = crate::utils::build_lookup_prefixes_set(&lookup_labels);

        // Load nodes.
        current_azks
            .bfs_preload_nodes::<_, H>(&self.storage, lookup_prefixes_set)
            .await?;

        // Ensure we have got all lookup infos needed.
        assert_eq!(unames.len(), lookup_infos.len());

        let mut lookup_proofs = Vec::new();
        for i in 0..unames.len() {
            lookup_proofs.push(
                self.lookup_with_info::<H>(
                    unames[i].clone(),
                    &current_azks,
                    current_epoch,
                    lookup_infos[i].clone(),
                )
                .await?,
            );
        }

        Ok(lookup_proofs)
    }

    async fn get_lookup_info<H: Hasher>(
        &self,
        uname: AkdLabel,
        epoch: u64,
    ) -> Result<LookupInfo, AkdError> {
        match self
            .storage
            .get_user_state(&uname, ValueStateRetrievalFlag::LeqEpoch(epoch))
            .await
        {
            Err(_) => {
                // Need to throw an error
                match std::str::from_utf8(&uname) {
                    Ok(name) => Err(AkdError::Storage(StorageError::NotFound(format!(
                        "User {} at epoch {}",
                        name, epoch
                    )))),
                    _ => Err(AkdError::Storage(StorageError::NotFound(format!(
                        "User {:?} at epoch {}",
                        uname, epoch
                    )))),
                }
            }
            Ok(latest_st) => {
                // Need to account for the case where the latest state is
                // added but the database is in the middle of an update
                let version = latest_st.version;
                let marker_version = 1 << get_marker_version(version);
                let existent_label = self.vrf.get_node_label::<H>(&uname, false, version).await?;
                let marker_label = self
                    .vrf
                    .get_node_label::<H>(&uname, false, marker_version)
                    .await?;
                let non_existent_label =
                    self.vrf.get_node_label::<H>(&uname, true, version).await?;
                Ok(LookupInfo {
                    value_state: latest_st,
                    marker_version,
                    existent_label,
                    marker_label,
                    non_existent_label,
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

        let username = uname.to_vec();
        let current_azks = self.retrieve_current_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        if let Ok(this_user_data) = self.storage.get_user_data(uname).await {
            let mut user_data = this_user_data.states;
            // reverse sort from highest epoch to lowest
            user_data.sort_by(|a, b| b.epoch.partial_cmp(&a.epoch).unwrap());

            let mut proofs = Vec::<UpdateProof<H>>::new();
            for user_state in user_data {
                // Ignore states in storage that are ahead of current directory epoch
                if user_state.epoch <= current_epoch {
                    let proof = self.create_single_update_proof(uname, &user_state).await?;
                    proofs.push(proof);
                }
            }
            Ok(HistoryProof { proofs })
        } else {
            match std::str::from_utf8(&username) {
                Ok(name) => Err(AkdError::Storage(StorageError::NotFound(format!(
                    "User {} at epoch {}",
                    name, current_epoch
                )))),
                _ => Err(AkdError::Storage(StorageError::NotFound(format!(
                    "User {:?} at epoch {}",
                    username, current_epoch
                )))),
            }
        }
    }

    /// Takes in the current state of the server and a label along with
    /// a "top" number of key updates to generate a proof for.
    ///
    /// If the label is present in the current state,
    /// this function returns all the values & proof of validity
    /// up to `top_n_updates` results.
    pub async fn limited_key_history<H: Hasher>(
        &self,
        top_n_updates: usize,
        uname: &AkdLabel,
    ) -> Result<HistoryProof<H>, AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_current_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        let mut user_data = self.storage.get_user_data(uname).await?.states;
        // reverse sort from highest epoch to lowest
        user_data.sort_by(|a, b| b.epoch.partial_cmp(&a.epoch).unwrap());

        let limited_history = user_data
            .into_iter()
            .take(top_n_updates)
            .collect::<Vec<_>>();

        if limited_history.is_empty() {
            let msg = if let Ok(username_str) = std::str::from_utf8(uname) {
                format!("User {}", username_str)
            } else {
                format!("User {:?}", uname)
            };
            Err(AkdError::Storage(StorageError::NotFound(msg)))
        } else {
            let mut proofs = Vec::<UpdateProof<H>>::new();
            for user_state in limited_history {
                // Ignore states in storage that are ahead of current directory epoch
                if user_state.epoch <= current_epoch {
                    let proof = self.create_single_update_proof(uname, &user_state).await?;
                    proofs.push(proof);
                }
            }
            Ok(HistoryProof { proofs })
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
                        channel.send(()).await.map_err(|send_err| {
                            AkdError::Storage(StorageError::Connection(format!(
                                "Tokio MPSC sender failed to publish notification with error {:?}",
                                send_err
                            )))
                        })?;
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
                .get_direct::<Azks>(&crate::append_only_zks::DEFAULT_AZKS_KEY)
                .await?
        } else {
            storage
                .get::<Azks>(&crate::append_only_zks::DEFAULT_AZKS_KEY)
                .await?
        };
        match got {
            DbRecord::Azks(azks) => Ok(azks),
            _ => {
                error!("No AZKS can be found. You should re-initialize the directory to create a new one");
                Err(AkdError::Storage(StorageError::NotFound(
                    "AZKS not found".to_string(),
                )))
            }
        }
    }

    /// HELPERS ///

    /// Use this function to retrieve the VRF public key for this AKD.
    pub async fn get_public_key(&self) -> Result<VRFPublicKey, AkdError> {
        Ok(self.vrf.get_vrf_public_key().await?)
    }

    async fn create_single_update_proof<H: Hasher>(
        &self,
        uname: &AkdLabel,
        user_state: &ValueState,
    ) -> Result<UpdateProof<H>, AkdError> {
        let epoch = user_state.epoch;
        let plaintext_value = &user_state.plaintext_val;
        let version = &user_state.version;

        let label_at_ep = self.vrf.get_node_label::<H>(uname, false, *version).await?;

        let current_azks = self.retrieve_current_azks().await?;
        let existence_vrf_proof = self
            .vrf
            .get_label_proof::<H>(uname, false, *version)
            .await?
            .to_bytes()
            .to_vec();
        let existence_at_ep = current_azks
            .get_membership_proof(&self.storage, label_at_ep, epoch)
            .await?;
        let mut previous_val_stale_at_ep = Option::None;
        let mut previous_val_vrf_proof = Option::None;
        if *version > 1 {
            let prev_label_at_ep = self
                .vrf
                .get_node_label::<H>(uname, true, *version - 1)
                .await?;
            previous_val_stale_at_ep = Option::Some(
                current_azks
                    .get_membership_proof(&self.storage, prev_label_at_ep, epoch)
                    .await?,
            );
            previous_val_vrf_proof = Option::Some(
                self.vrf
                    .get_label_proof::<H>(uname, true, *version - 1)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
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
            let label_for_ver = self.vrf.get_node_label::<H>(uname, false, ver).await?;
            let non_existence_of_ver = current_azks
                .get_non_membership_proof(&self.storage, label_for_ver, epoch)
                .await?;
            non_existence_of_next_few.push(non_existence_of_ver);
            next_few_vrf_proofs.push(
                self.vrf
                    .get_label_proof::<H>(uname, false, ver)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
        }

        let mut future_marker_vrf_proofs = Vec::<Vec<u8>>::new();
        let mut non_existence_of_future_markers = Vec::<NonMembershipProof<H>>::new();

        for marker_power in next_marker..final_marker + 1 {
            let ver = 1 << marker_power;
            let label_for_ver = self.vrf.get_node_label::<H>(uname, false, ver).await?;
            let non_existence_of_ver = current_azks
                .get_non_membership_proof(&self.storage, label_for_ver, epoch)
                .await?;
            non_existence_of_future_markers.push(non_existence_of_ver);
            future_marker_vrf_proofs.push(
                self.vrf
                    .get_label_proof::<H>(uname, false, ver)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
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

#[cfg(feature = "rand")]
fn get_random_str<R: RngCore + CryptoRng>(rng: &mut R) -> String {
    let mut byte_str = [0u8; 32];
    rng.fill_bytes(&mut byte_str);
    format!("{:?}", &byte_str)
}

type KeyHistoryHelper<D> = (Vec<D>, Vec<Option<D>>);

/// Gets hashes for key history proofs
pub async fn get_key_history_hashes<S: Storage + Sync + Send, H: Hasher, V: VRFKeyStorage>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auditor::audit_verify,
        client::{key_history_verify, lookup_verify},
        ecvrf::HardCodedAkdVRF,
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

        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world"),
        )])
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_simple_lookup() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        let lookup_proof = akd.lookup(AkdLabel::from_utf8_str("hello")).await?;
        let current_azks = akd.retrieve_current_azks().await?;
        let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;
        let vrf_pk = akd.get_public_key().await?;
        lookup_verify::<Blake3_256<BaseElement>>(
            &vrf_pk,
            root_hash,
            AkdLabel::from_utf8_str("hello"),
            lookup_proof,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_simple_key_history() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world3"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world4"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_updated"),
        )])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world6"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world12"),
            ),
        ])
        .await?;

        let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello")).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        let vrf_pk = akd.get_public_key().await?;
        key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello"),
            history_proof,
            false,
        )?;

        let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello2")).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello2"),
            history_proof,
            false,
        )?;

        let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello3")).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello3"),
            history_proof,
            false,
        )?;

        let history_proof = akd.key_history(&AkdLabel::from_utf8_str("hello4")).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello4"),
            history_proof,
            false,
        )?;

        Ok(())
    }

    #[allow(unused)]
    #[tokio::test]
    async fn test_simple_audit() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        let mut akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world3"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world4"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_updated"),
        )])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world6"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world12"),
            ),
        ])
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
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world_2"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2_2"),
            ),
        ])
        .await?;

        // Make the current azks a "checkpoint" to reset to later
        let checkpoint_azks = akd.retrieve_current_azks().await.unwrap();

        // Publish for the third time
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world_3"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2_3"),
            ),
        ])
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
            .key_history::<Blake3>(&AkdLabel::from_utf8_str("hello"))
            .await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        assert_eq!(2, root_hashes.len());
        let vrf_pk = akd.get_public_key().await?;
        key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello"),
            history_proof,
            false,
        )?;

        // Lookup proof should contain the checkpoint epoch's value and still verify
        let lookup_proof = akd
            .lookup::<Blake3>(AkdLabel::from_utf8_str("hello"))
            .await?;
        assert_eq!(
            AkdValue::from_utf8_str("world_2"),
            lookup_proof.plaintext_value
        );
        lookup_verify::<Blake3>(
            &vrf_pk,
            root_hash,
            AkdLabel::from_utf8_str("hello"),
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
        assert!(matches!(akd.publish::<Blake3>(vec![]).await, Err(_)));

        Ok(())
    }

    #[tokio::test]
    async fn test_directory_polling_azks_change() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        // writer will write the AZKS record
        let writer = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        writer
            .publish::<Blake3>(vec![
                (
                    AkdLabel::from_utf8_str("hello"),
                    AkdValue::from_utf8_str("world"),
                ),
                (
                    AkdLabel::from_utf8_str("hello2"),
                    AkdValue::from_utf8_str("world2"),
                ),
            ])
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
        async_poll_helper_proof(&reader, AkdValue::from_utf8_str("world")).await?;

        // publish epoch 2
        writer
            .publish::<Blake3>(vec![
                (
                    AkdLabel::from_utf8_str("hello"),
                    AkdValue::from_utf8_str("world_2"),
                ),
                (
                    AkdLabel::from_utf8_str("hello2"),
                    AkdValue::from_utf8_str("world2_2"),
                ),
            ])
            .await?;

        // assert that the change is picked up in a reasonable time-frame and the cache is flushed
        let notification =
            tokio::time::timeout(tokio::time::Duration::from_secs(10), rx.recv()).await;
        assert!(matches!(notification, Ok(Some(()))));

        async_poll_helper_proof(&reader, AkdValue::from_utf8_str("world_2")).await?;

        Ok(())
    }

    /*
    =========== Test Helpers ===========
    */

    async fn async_poll_helper_proof<T: Storage + Sync + Send, V: VRFKeyStorage>(
        reader: &Directory<T, V>,
        value: AkdValue,
    ) -> Result<(), AkdError> {
        // reader should read "hello" and this will populate the "cache" a log
        let lookup_proof = reader.lookup(AkdLabel::from_utf8_str("hello")).await?;
        assert_eq!(value, lookup_proof.plaintext_value);
        let current_azks = reader.retrieve_current_azks().await?;
        let root_hash = reader.get_root_hash::<Blake3>(&current_azks).await?;
        let pk = reader.get_public_key().await?;
        lookup_verify::<Blake3>(
            &pk,
            root_hash,
            AkdLabel::from_utf8_str("hello"),
            lookup_proof,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_limited_key_history() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        // epoch 0
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        // epoch 1
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        // epoch 2
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        // epoch 3
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello"),
                AkdValue::from_utf8_str("world3"),
            ),
            (
                AkdLabel::from_utf8_str("hello2"),
                AkdValue::from_utf8_str("world4"),
            ),
        ])
        .await?;

        // epoch 4
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world2"),
            ),
        ])
        .await?;

        // epoch 5
        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world_updated"),
        )])
        .await?;

        // epoch 6
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world6"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world12"),
            ),
        ])
        .await?;

        // epoch 7
        akd.publish::<Blake3>(vec![
            (
                AkdLabel::from_utf8_str("hello3"),
                AkdValue::from_utf8_str("world7"),
            ),
            (
                AkdLabel::from_utf8_str("hello4"),
                AkdValue::from_utf8_str("world13"),
            ),
        ])
        .await?;

        let vrf_pk = akd.get_public_key().await?;

        // "hello" was updated in epochs 1,2,3,5. Pull the latest item from the history (i.e. a lookup proof)
        let history_proof = akd
            .limited_key_history::<Blake3>(1, &AkdLabel::from_utf8_str("hello"))
            .await?;
        assert_eq!(1, history_proof.proofs.len());
        assert_eq!(5, history_proof.proofs[0].epoch);

        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello"),
            history_proof,
            false,
        )?;

        // Take the top 3 results, and check that we're getting the right epoch updates
        let history_proof = akd
            .limited_key_history::<Blake3>(3, &AkdLabel::from_utf8_str("hello"))
            .await?;
        assert_eq!(3, history_proof.proofs.len());
        assert_eq!(5, history_proof.proofs[0].epoch);
        assert_eq!(3, history_proof.proofs[1].epoch);
        assert_eq!(2, history_proof.proofs[2].epoch);

        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello"),
            history_proof,
            false,
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn test_tombstoned_key_history() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let vrf = HardCodedAkdVRF {};
        // epoch 0
        let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

        // epoch 1
        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world"),
        )])
        .await?;

        // epoch 2
        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world2"),
        )])
        .await?;

        // epoch 3
        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world3"),
        )])
        .await?;

        // epoch 4
        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world4"),
        )])
        .await?;

        // epoch 5
        akd.publish::<Blake3>(vec![(
            AkdLabel::from_utf8_str("hello"),
            AkdValue::from_utf8_str("world5"),
        )])
        .await?;

        // Epochs 1-5, we're going to tombstone 1 & 2
        let vrf_pk = akd.get_public_key().await?;

        // tombstone epochs 1 & 2
        let tombstones = [
            crate::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 1u64),
            crate::storage::types::ValueStateKey("hello".as_bytes().to_vec(), 2u64),
        ];
        db.tombstone_value_states(&tombstones).await?;

        let history_proof = akd
            .key_history::<Blake3>(&AkdLabel::from_utf8_str("hello"))
            .await?;
        assert_eq!(5, history_proof.proofs.len());
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;

        // If we request a proof with tombstones but without saying we're OK with tombstones, throw an err
        let tombstones = key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes.clone(),
            previous_root_hashes.clone(),
            AkdLabel::from_utf8_str("hello"),
            history_proof.clone(),
            false,
        );
        assert!(matches!(tombstones, Err(_)));

        // We should be able to verify tombstones assuming the client is accepting
        // of tombstoned states
        let tombstones = key_history_verify::<Blake3>(
            &vrf_pk,
            root_hashes,
            previous_root_hashes,
            AkdLabel::from_utf8_str("hello"),
            history_proof,
            true,
        )?;
        assert_eq!(false, tombstones[0]);
        assert_eq!(false, tombstones[1]);
        assert_eq!(false, tombstones[2]);
        assert_eq!(true, tombstones[3]);
        assert_eq!(true, tombstones[4]);

        Ok(())
    }

    // // Test coverage on issue #144, verification failures with small trees (<4 nodes)
    // #[tokio::test]
    // async fn test_simple_lookup_for_small_tree() -> Result<(), AkdError> {
    //     let db = AsyncInMemoryDatabase::new();
    //     let vrf = HardCodedAkdVRF {};
    //     // epoch 0
    //     let akd = Directory::<_, _>::new::<Blake3>(&db, &vrf, false).await?;

    //     let mut updates = vec![];
    //     for i in 0..1 {
    //         updates.push((
    //             AkdLabel(format!("hello{}", i).as_bytes().to_vec()),
    //             AkdValue(format!("hello{}", i).as_bytes().to_vec()),
    //         ));
    //     }

    //     akd.publish::<Blake3>(updates).await?;

    //     let target_label = AkdLabel(format!("hello{}", 0).as_bytes().to_vec());

    //     // retrieve the lookup proof
    //     let lookup_proof = akd.lookup(target_label.clone()).await?;
    //     // retrieve the root hash
    //     let current_azks = akd.retrieve_current_azks().await?;
    //     let root_hash = akd.get_root_hash::<Blake3>(&current_azks).await?;

    //     let vrf_pk = vrf.get_vrf_public_key().await?;

    //     // perform the "traditional" AKD verification
    //     let akd_result = crate::client::lookup_verify::<Blake3>(
    //         &vrf_pk,
    //         root_hash,
    //         target_label.clone(),
    //         lookup_proof,
    //     );

    //     // check the two results to make sure they both verify
    //     assert!(matches!(akd_result, Ok(())));

    //     Ok(())
    // }
}
