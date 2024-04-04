// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Implementation of an auditable key directory

use crate::append_only_zks::{Azks, InsertMode};
use crate::ecvrf::{VRFKeyStorage, VRFPublicKey};
use crate::errors::{AkdError, DirectoryError, StorageError};
use crate::helper_structs::LookupInfo;
use crate::storage::manager::StorageManager;
use crate::storage::types::{DbRecord, ValueState, ValueStateRetrievalFlag};
use crate::storage::Database;
use crate::{
    AkdLabel, AkdValue, AppendOnlyProof, AzksElement, Digest, EpochHash, HistoryProof, LookupProof,
    NonMembershipProof, UpdateProof,
};

use crate::VersionFreshness;
use akd_core::configuration::Configuration;
use log::{error, info};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The representation of a auditable key directory
pub struct Directory<TC, S: Database, V> {
    storage: StorageManager<S>,
    vrf: V,
    /// The cache lock guarantees that the cache is not
    /// flushed mid-proof generation. We allow multiple proof generations
    /// to occur (RwLock.read() operations can have multiple) but we want
    /// to make sure no generations are underway when a cache flush occurs
    /// (in this case we do utilize the write() lock which can only occur 1
    /// at a time and gates further read() locks being acquired during write()).
    cache_lock: Arc<RwLock<()>>,
    tc: PhantomData<TC>,
}

// Manual implementation of Clone, see: https://github.com/rust-lang/rust/issues/41481
impl<TC, S: Database, V: VRFKeyStorage> Clone for Directory<TC, S, V> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            vrf: self.vrf.clone(),
            cache_lock: self.cache_lock.clone(),
            tc: PhantomData,
        }
    }
}

impl<TC, S, V> Directory<TC, S, V>
where
    TC: Configuration,
    S: Database + 'static,
    V: VRFKeyStorage,
{
    /// Creates a new (stateless) instance of a auditable key directory.
    /// Takes as input a pointer to the storage being used for this instance.
    /// The state is stored in the storage.
    pub async fn new(storage: StorageManager<S>, vrf: V) -> Result<Self, AkdError> {
        let azks = Directory::<TC, S, V>::get_azks_from_storage(&storage, false).await;

        if let Err(AkdError::Storage(StorageError::NotFound(e))) = azks {
            info!("No aZKS was found in storage: {e}. Creating a new aZKS!");
            // generate + store a new azks only if one is not found
            let new_azks = Azks::new::<TC, _>(&storage).await?;
            storage.set(DbRecord::Azks(new_azks)).await?;
        } else {
            // If the value is `Ok`, we drop it since we're not using it below
            // In all other `Err` cases, we propagate the error to the caller
            let _res = azks?;
        }

        Ok(Directory {
            storage,
            cache_lock: Arc::new(RwLock::new(())),
            vrf,
            tc: PhantomData,
        })
    }

    /// Updates the directory to include the input label-value pairs.
    ///
    /// Note that the vector of label-value pairs should not contain any entries with duplicate labels. This
    /// condition is explicitly checked, and an error will be returned if this is the case.
    pub async fn publish(&self, updates: Vec<(AkdLabel, AkdValue)>) -> Result<EpochHash, AkdError> {
        // The guard will be dropped at the end of the publish
        let _guard = self.cache_lock.read().await;

        // Check for duplicate labels and return an error if any are encountered
        let distinct_set: HashSet<AkdLabel> =
            updates.iter().map(|(label, _)| label.clone()).collect();
        if distinct_set.len() != updates.len() {
            return Err(AkdError::Directory(DirectoryError::Publish(
                "Cannot publish with a set of entries that contain duplicate labels".to_string(),
            )));
        }

        let mut update_set = Vec::<AzksElement>::new();
        let mut user_data_update_set = Vec::<ValueState>::new();

        let mut current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let next_epoch = current_epoch + 1;

        let mut keys: Vec<AkdLabel> = updates
            .iter()
            .map(|(akd_label, _val)| akd_label.clone())
            .collect();

        // sort the keys, as inserting in primary-key order is more efficient for MySQL
        keys.sort();

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

        let vrf_computations = updates
            .iter()
            .flat_map(
                |(akd_label, akd_value)| match all_user_versions_retrieved.get(akd_label) {
                    None => vec![(
                        akd_label.clone(),
                        VersionFreshness::Fresh,
                        1u64,
                        akd_value.clone(),
                    )],
                    Some((latest_version, existing_akd_value)) => {
                        if existing_akd_value == akd_value {
                            // Skip this because the user is trying to re-publish the same value
                            return vec![];
                        }
                        vec![
                            (
                                akd_label.clone(),
                                VersionFreshness::Stale,
                                *latest_version,
                                akd_value.clone(),
                            ),
                            (
                                akd_label.clone(),
                                VersionFreshness::Fresh,
                                *latest_version + 1,
                                akd_value.clone(),
                            ),
                        ]
                    }
                },
            )
            .collect::<Vec<_>>();

        let vrf_map = self
            .vrf
            .get_node_labels::<TC>(&vrf_computations)
            .await?
            .into_iter()
            .collect::<HashMap<_, _>>();

        let commitment_key = self.derive_commitment_key().await?;

        for ((akd_label, freshness, version, akd_value), node_label) in vrf_map {
            let azks_value = match freshness {
                VersionFreshness::Stale => TC::stale_azks_value(),
                VersionFreshness::Fresh => {
                    TC::compute_fresh_azks_value(&commitment_key, &node_label, version, &akd_value)
                }
            };
            update_set.push(AzksElement {
                label: node_label,
                value: azks_value,
            });

            if freshness == VersionFreshness::Fresh {
                let latest_state =
                    ValueState::new(akd_label, akd_value, version, node_label, next_epoch);
                user_data_update_set.push(latest_state);
            }
        }

        if update_set.is_empty() {
            info!("After filtering for duplicated user information, there is no publish which is necessary (0 updates)");
            // The AZKS has not been updated/mutated at this point, so we can just return the root hash from before
            let root_hash = current_azks.get_root_hash::<TC, _>(&self.storage).await?;
            return Ok(EpochHash(current_epoch, root_hash));
        }

        if !self.storage.begin_transaction() {
            error!("Transaction is already active");
            return Err(AkdError::Storage(StorageError::Transaction(
                "Transaction is already active".to_string(),
            )));
        }
        info!("Starting inserting new leaves");

        if let Err(err) = current_azks
            .batch_insert_nodes::<TC, _>(&self.storage, update_set, InsertMode::Directory)
            .await
        {
            // If we fail to do the batch-leaf insert, we should rollback the transaction so we can try again cleanly.
            // Only fails if transaction is not currently active.
            let _ = self.storage.rollback_transaction();
            // bubble up the err
            return Err(err);
        }

        // batch all the inserts into a single write to storage (in this case it insert's into the transaction log)
        let mut updates = vec![DbRecord::Azks(current_azks.clone())];
        for update in user_data_update_set.into_iter() {
            updates.push(DbRecord::ValueState(update));
        }
        self.storage.batch_set(updates).await?;

        // Commit the transaction
        info!("Committing transaction");
        match self.storage.commit_transaction().await {
            Ok(num_records) => {
                info!("Transaction committed ({} records)", num_records);
            }
            Err(err) => {
                error!("Failed to commit transaction, rolling back");
                let _ = self.storage.rollback_transaction();
                return Err(AkdError::Storage(err));
            }
        };

        let root_hash = current_azks
            .get_root_hash_safe::<TC, _>(&self.storage, next_epoch)
            .await?;

        Ok(EpochHash(next_epoch, root_hash))
    }

    /// Provides proof for correctness of latest version
    ///
    /// * `akd_label`: The target label to generate a lookup proof for
    ///
    /// Returns [Ok((LookupProof, EpochHash))] upon successful generation for the latest version
    /// of the target label's state. [Err(_)] otherwise
    pub async fn lookup(&self, akd_label: AkdLabel) -> Result<(LookupProof, EpochHash), AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let lookup_info = self.get_lookup_info(akd_label, current_epoch).await?;

        let root_hash = EpochHash(
            current_epoch,
            current_azks.get_root_hash::<TC, _>(&self.storage).await?,
        );
        let proof = self
            .lookup_with_info(&current_azks, lookup_info, false)
            .await?;
        Ok((proof, root_hash))
    }

    /// Generate a lookup proof with the provided target information
    ///
    /// * `current_azks`: The current [Azks] element
    /// * `lookup_info`: The information to target in the lookup request. Includes all
    /// necessary information to build the proof
    /// * `skip_preload`: Denotes if we should not preload as part of this optimization. Enabled
    /// from bulk lookup proof generation, as it has its own preloading operation
    ///
    /// Returns [Ok(LookupProof)] if the proof generation succeeded, [Err(_)] otherwise
    async fn lookup_with_info(
        &self,
        current_azks: &Azks,
        lookup_info: LookupInfo,
        skip_preload: bool,
    ) -> Result<LookupProof, AkdError> {
        if !skip_preload {
            // Preload nodes needed for lookup.
            #[cfg(feature = "greedy_lookup_preload")]
            {
                current_azks
                    .greedy_preload_lookup_nodes(&self.storage, lookup_info.clone())
                    .await?;
            }
            #[cfg(not(feature = "greedy_lookup_preload"))]
            {
                current_azks
                    .preload_lookup_nodes(&self.storage, &vec![lookup_info.clone()])
                    .await?;
            }
        }
        let label = &lookup_info.value_state.username;
        let current_version = lookup_info.value_state.version;
        let commitment_key = self.derive_commitment_key().await?;
        let plaintext_value = lookup_info.value_state.value;
        let existence_vrf = self
            .vrf
            .get_label_proof::<TC>(label, VersionFreshness::Fresh, current_version)
            .await?;
        let commitment_label = self.vrf.get_node_label_from_vrf_proof(existence_vrf).await;
        let lookup_proof = LookupProof {
            epoch: lookup_info.value_state.epoch,
            value: plaintext_value.clone(),
            version: lookup_info.value_state.version,
            existence_vrf_proof: existence_vrf.to_bytes().to_vec(),
            existence_proof: current_azks
                .get_membership_proof::<TC, _>(&self.storage, lookup_info.existent_label)
                .await?,
            marker_vrf_proof: self
                .vrf
                .get_label_proof::<TC>(label, VersionFreshness::Fresh, lookup_info.marker_version)
                .await?
                .to_bytes()
                .to_vec(),
            marker_proof: current_azks
                .get_membership_proof::<TC, _>(&self.storage, lookup_info.marker_label)
                .await?,
            freshness_vrf_proof: self
                .vrf
                .get_label_proof::<TC>(label, VersionFreshness::Stale, current_version)
                .await?
                .to_bytes()
                .to_vec(),
            freshness_proof: current_azks
                .get_non_membership_proof::<TC, _>(&self.storage, lookup_info.non_existent_label)
                .await?,
            commitment_nonce: TC::get_commitment_nonce(
                &commitment_key,
                &commitment_label,
                lookup_info.value_state.version,
                &plaintext_value,
            )
            .to_vec(),
        };

        Ok(lookup_proof)
    }

    // TODO(eoz): Call proof generations async
    /// Allows efficient batch lookups by preloading necessary nodes for the lookups.
    pub async fn batch_lookup(
        &self,
        akd_labels: &[AkdLabel],
    ) -> Result<(Vec<LookupProof>, EpochHash), AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        // Take a union of the labels we will need proofs of for each lookup.
        let mut lookup_infos = Vec::new();
        for akd_label in akd_labels {
            // Save lookup info for later use.
            let lookup_info = self
                .get_lookup_info(akd_label.clone(), current_epoch)
                .await?;
            lookup_infos.push(lookup_info.clone());
        }

        // Load nodes needed using the lookup infos.
        current_azks
            .preload_lookup_nodes(&self.storage, &lookup_infos)
            .await?;

        // Ensure we have got all lookup infos needed.
        assert_eq!(akd_labels.len(), lookup_infos.len());

        let root_hash = EpochHash(
            current_epoch,
            current_azks.get_root_hash::<TC, _>(&self.storage).await?,
        );

        let mut lookup_proofs = Vec::new();
        for info in lookup_infos.into_iter() {
            lookup_proofs.push(self.lookup_with_info(&current_azks, info, true).await?);
        }

        Ok((lookup_proofs, root_hash))
    }

    async fn build_lookup_info(&self, latest_st: &ValueState) -> Result<LookupInfo, AkdError> {
        let akd_label = &latest_st.username;
        // Need to account for the case where the latest state is
        // added but the database is in the middle of an update
        let version = latest_st.version;
        let marker_version = 1 << get_marker_version(version);
        let existent_label = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, version)
            .await?;
        let marker_label = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, marker_version)
            .await?;
        let non_existent_label = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Stale, version)
            .await?;
        Ok(LookupInfo {
            value_state: latest_st.clone(),
            marker_version,
            existent_label,
            marker_label,
            non_existent_label,
        })
    }

    async fn get_lookup_info(
        &self,
        akd_label: AkdLabel,
        epoch: u64,
    ) -> Result<LookupInfo, AkdError> {
        match self
            .storage
            .get_user_state(&akd_label, ValueStateRetrievalFlag::LeqEpoch(epoch))
            .await
        {
            Err(_) => {
                // Need to throw an error
                match std::str::from_utf8(&akd_label) {
                    Ok(name) => Err(AkdError::Storage(StorageError::NotFound(format!(
                        "User {name} at epoch {epoch}"
                    )))),
                    _ => Err(AkdError::Storage(StorageError::NotFound(format!(
                        "User {akd_label:?} at epoch {epoch}"
                    )))),
                }
            }
            Ok(latest_st) => self.build_lookup_info(&latest_st).await,
        }
    }

    /// Takes in the current state of the server and a label.
    /// If the label is present in the current state,
    /// this function returns all the values ever associated with it,
    /// and the epoch at which each value was first committed to the server state.
    /// It also returns the proof of the latest version being served at all times.
    pub async fn key_history(
        &self,
        akd_label: &AkdLabel,
        params: HistoryParams,
    ) -> Result<(HistoryProof, EpochHash), AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let mut user_data = self.storage.get_user_data(akd_label).await?.states;

        // reverse sort from highest epoch to lowest
        user_data.sort_by(|a, b| b.epoch.cmp(&a.epoch));

        // apply filters specified by HistoryParams struct
        user_data = match params {
            HistoryParams::Complete => user_data,
            HistoryParams::MostRecentInsecure(n) => {
                user_data.into_iter().take(n).collect::<Vec<_>>()
            }
            HistoryParams::SinceEpochInsecure(epoch) => {
                user_data = user_data
                    .into_iter()
                    .filter(|val| val.epoch >= epoch)
                    .collect::<Vec<_>>();
                // Ordering should be maintained after filtering, but let's re-sort just in case
                user_data.sort_by(|a, b| b.epoch.cmp(&a.epoch));
                user_data
            }
        };

        if user_data.is_empty() {
            let msg = if let Ok(username_str) = std::str::from_utf8(akd_label) {
                format!("User {username_str}")
            } else {
                format!("User {akd_label:?}")
            };
            return Err(AkdError::Storage(StorageError::NotFound(msg)));
        }

        #[cfg(feature = "preload_history")]
        {
            let mut lookup_infos = vec![];
            for ud in user_data.iter() {
                if let Ok(lo) = self.build_lookup_info(ud).await {
                    lookup_infos.push(lo);
                }
            }
            current_azks
                .preload_lookup_nodes(&self.storage, &lookup_infos)
                .await?;
        }

        let mut update_proofs = Vec::<UpdateProof>::new();
        let mut last_version = 0;
        for user_state in user_data {
            // Ignore states in storage that are ahead of current directory epoch
            if user_state.epoch <= current_epoch {
                let proof = self
                    .create_single_update_proof(akd_label, &user_state)
                    .await?;
                update_proofs.push(proof);
                last_version = if user_state.version > last_version {
                    user_state.version
                } else {
                    last_version
                };
            }
        }
        let next_marker = get_marker_version(last_version) + 1;
        let final_marker = get_marker_version(current_epoch);

        let mut until_marker_vrf_proofs = Vec::<Vec<u8>>::new();
        let mut non_existence_until_marker_proofs = Vec::<NonMembershipProof>::new();

        for ver in last_version + 1..(1 << next_marker) {
            let label_for_ver = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, ver)
                .await?;
            let non_existence_of_ver = current_azks
                .get_non_membership_proof::<TC, _>(&self.storage, label_for_ver)
                .await?;
            non_existence_until_marker_proofs.push(non_existence_of_ver);
            until_marker_vrf_proofs.push(
                self.vrf
                    .get_label_proof::<TC>(akd_label, VersionFreshness::Fresh, ver)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
        }

        let mut future_marker_vrf_proofs = Vec::<Vec<u8>>::new();
        let mut non_existence_of_future_marker_proofs = Vec::<NonMembershipProof>::new();

        for marker_power in next_marker..final_marker + 1 {
            let ver = 1 << marker_power;
            let label_for_ver = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, ver)
                .await?;
            let non_existence_of_ver = current_azks
                .get_non_membership_proof::<TC, _>(&self.storage, label_for_ver)
                .await?;
            non_existence_of_future_marker_proofs.push(non_existence_of_ver);
            future_marker_vrf_proofs.push(
                self.vrf
                    .get_label_proof::<TC>(akd_label, VersionFreshness::Fresh, ver)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
        }

        let root_hash = EpochHash(
            current_epoch,
            current_azks.get_root_hash::<TC, _>(&self.storage).await?,
        );

        Ok((
            HistoryProof {
                update_proofs,
                until_marker_vrf_proofs,
                non_existence_until_marker_proofs,
                future_marker_vrf_proofs,
                non_existence_of_future_marker_proofs,
            },
            root_hash,
        ))
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
        let mut last = Directory::<TC, S, V>::get_azks_from_storage(&self.storage, false).await?;

        loop {
            // loop forever polling for changes
            tokio::time::sleep(period).await;

            let latest = Directory::<TC, S, V>::get_azks_from_storage(&self.storage, true).await?;
            if latest.latest_epoch > last.latest_epoch {
                {
                    // acquire a singleton lock prior to flushing the cache to assert that no
                    // cache accesses are underway (i.e. publish/proof generations/etc)
                    let _guard = self.cache_lock.write().await;
                    // flush the cache in its entirety
                    self.storage.flush_cache().await;
                    // re-fetch the azks to load it into cache so when we release the cache lock
                    // others will see the new AZKS loaded up and ready
                    last =
                        Directory::<TC, S, V>::get_azks_from_storage(&self.storage, false).await?;

                    // notify change occurred
                    if let Some(channel) = &change_detected {
                        channel.send(()).await.map_err(|send_err| {
                            AkdError::Storage(StorageError::Connection(format!(
                                "Tokio MPSC sender failed to publish notification with error {send_err:?}"
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

    /// Returns an [AppendOnlyProof] for the leaves inserted into the underlying tree between
    /// the epochs `audit_start_ep` and `audit_end_ep`.
    pub async fn audit(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<AppendOnlyProof, AkdError> {
        // The guard will be dropped at the end of the proof generation
        let _guard = self.cache_lock.read().await;

        let current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();

        if audit_start_ep >= audit_end_ep {
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "Start epoch {audit_start_ep} is greater than or equal the end epoch {audit_end_ep}"
            ))))
        } else if current_epoch < audit_end_ep {
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "End epoch {audit_end_ep} is greater than the current epoch {current_epoch}"
            ))))
        } else {
            self.storage.disable_cache_cleaning();
            let result = current_azks
                .get_append_only_proof::<TC, _>(&self.storage, audit_start_ep, audit_end_ep)
                .await;
            self.storage.enable_cache_cleaning();
            result
        }
    }

    /// Retrieves the [Azks]
    pub(crate) async fn retrieve_azks(&self) -> Result<Azks, crate::errors::AkdError> {
        Directory::<TC, S, V>::get_azks_from_storage(&self.storage, false).await
    }

    async fn get_azks_from_storage(
        storage: &StorageManager<S>,
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

    /// Use this function to retrieve the [VRFPublicKey] for this AKD.
    pub async fn get_public_key(&self) -> Result<VRFPublicKey, AkdError> {
        Ok(self.vrf.get_vrf_public_key().await?)
    }

    async fn create_single_update_proof(
        &self,
        akd_label: &AkdLabel,
        user_state: &ValueState,
    ) -> Result<UpdateProof, AkdError> {
        let epoch = user_state.epoch;
        let value = &user_state.value;
        let version = user_state.version;

        let label_at_ep = self
            .vrf
            .get_node_label::<TC>(akd_label, VersionFreshness::Fresh, version)
            .await?;

        let current_azks = self.retrieve_azks().await?;
        let existence_vrf = self
            .vrf
            .get_label_proof::<TC>(akd_label, VersionFreshness::Fresh, version)
            .await?;
        let existence_vrf_proof = existence_vrf.to_bytes().to_vec();
        let existence_label = self.vrf.get_node_label_from_vrf_proof(existence_vrf).await;
        let existence_proof = current_azks
            .get_membership_proof::<TC, _>(&self.storage, label_at_ep)
            .await?;
        let mut previous_version_proof = Option::None;
        let mut previous_version_vrf_proof = Option::None;
        if version > 1 {
            let prev_label_at_ep = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Stale, version - 1)
                .await?;
            previous_version_proof = Option::Some(
                current_azks
                    .get_membership_proof::<TC, _>(&self.storage, prev_label_at_ep)
                    .await?,
            );
            previous_version_vrf_proof = Option::Some(
                self.vrf
                    .get_label_proof::<TC>(akd_label, VersionFreshness::Stale, version - 1)
                    .await?
                    .to_bytes()
                    .to_vec(),
            );
        }

        let commitment_key = self.derive_commitment_key().await?;
        let commitment_nonce =
            TC::get_commitment_nonce(&commitment_key, &existence_label, version, value).to_vec();

        Ok(UpdateProof {
            epoch,
            version,
            value: value.clone(),
            existence_vrf_proof,
            existence_proof,
            previous_version_vrf_proof,
            previous_version_proof,
            commitment_nonce,
        })
    }

    /// Gets the root hash at the current epoch.
    pub async fn get_epoch_hash(&self) -> Result<EpochHash, AkdError> {
        let current_azks = self.retrieve_azks().await?;
        let latest_epoch = current_azks.get_latest_epoch();
        let root_hash = current_azks.get_root_hash::<TC, _>(&self.storage).await?;
        Ok(EpochHash(latest_epoch, root_hash))
    }

    // We simply hash the VRF private key to derive the commitment key
    async fn derive_commitment_key(&self) -> Result<Digest, AkdError> {
        let raw_key = self.vrf.retrieve().await?;
        let commitment_key = TC::hash(&raw_key);
        Ok(commitment_key)
    }
}

/// A thin newtype which offers read-only interactivity with a [Directory].
#[derive(Clone)]
pub struct ReadOnlyDirectory<TC, S, V>(Directory<TC, S, V>)
where
    TC: Configuration,
    S: Database + Sync + Send,
    V: VRFKeyStorage;

impl<TC, S, V> ReadOnlyDirectory<TC, S, V>
where
    TC: Configuration,
    S: Database + 'static,
    V: VRFKeyStorage,
{
    /// Constructs a new instance of [ReadOnlyDirectory]. In the event that an [Azks]
    /// does not exist in the storage, or we're unable to retrieve it from storage, then
    /// a [DirectoryError] will be returned.
    pub async fn new(storage: StorageManager<S>, vrf: V) -> Result<Self, AkdError> {
        let azks = Directory::<TC, S, V>::get_azks_from_storage(&storage, false).await;

        if azks.is_err() {
            return Err(AkdError::Directory(DirectoryError::ReadOnlyDirectory(
                format!(
                    "Cannot start directory in read-only mode when AZKS is missing, error: {:?}",
                    azks.err().take()
                ),
            )));
        }

        Ok(Self(Directory {
            storage,
            cache_lock: Arc::new(RwLock::new(())),
            vrf,
            tc: PhantomData,
        }))
    }

    /// Read-only access to [Directory::lookup](Directory::lookup).
    pub async fn lookup(&self, uname: AkdLabel) -> Result<(LookupProof, EpochHash), AkdError> {
        self.0.lookup(uname).await
    }

    /// Read-only access to [Directory::batch_lookup](Directory::batch_lookup).
    pub async fn batch_lookup(
        &self,
        unames: &[AkdLabel],
    ) -> Result<(Vec<LookupProof>, EpochHash), AkdError> {
        self.0.batch_lookup(unames).await
    }

    /// Read-only access to [Directory::key_history](Directory::key_history).
    pub async fn key_history(
        &self,
        uname: &AkdLabel,
        params: HistoryParams,
    ) -> Result<(HistoryProof, EpochHash), AkdError> {
        self.0.key_history(uname, params).await
    }

    /// Read-only access to [Directory::poll_for_azks_changes](Directory::poll_for_azks_changes).
    pub async fn poll_for_azks_changes(
        &self,
        period: tokio::time::Duration,
        change_detected: Option<tokio::sync::mpsc::Sender<()>>,
    ) -> Result<(), AkdError> {
        self.0.poll_for_azks_changes(period, change_detected).await
    }

    /// Read-only access to [Directory::audit](Directory::audit).
    pub async fn audit(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<AppendOnlyProof, AkdError> {
        self.0.audit(audit_start_ep, audit_end_ep).await
    }

    /// Read-only access to [Directory::get_epoch_hash].
    pub async fn get_epoch_hash(&self) -> Result<EpochHash, AkdError> {
        self.0.get_epoch_hash().await
    }

    /// Read-only access to [Directory::get_public_key](Directory::get_public_key).
    pub async fn get_public_key(&self) -> Result<VRFPublicKey, AkdError> {
        self.0.get_public_key().await
    }
}

/// The parameters that dictate how much of the history proof to return to the consumer
/// (either a complete history, or some limited form).
#[derive(Copy, Clone)]
pub enum HistoryParams {
    /// Returns a complete history for a label
    Complete,
    /// Returns up to the most recent N updates for a label. This is not secure, and
    /// should not be used in a production environment.
    MostRecentInsecure(usize),
    /// Returns all updates since a specified epoch (inclusive). This is not secure, and
    /// should not be used in a production environment.
    SinceEpochInsecure(u64),
}

impl Default for HistoryParams {
    /// By default, we return a complete history
    fn default() -> Self {
        Self::Complete
    }
}

/// Helpers

pub(crate) fn get_marker_version(version: u64) -> u64 {
    (64 - version.leading_zeros() - 1).into()
}

/// Helpers for testing

/// This enum is meant to insert corruptions into a malicious publish function.
#[derive(Debug, Clone)]
pub enum PublishCorruption {
    /// Indicates to the malicious publish function to not mark a stale version
    UnmarkedStaleVersion(AkdLabel),
    /// Indicates to the malicious publish to mark a certain version for a username as stale.
    MarkVersionStale(AkdLabel, u64),
}

#[cfg(test)]
impl<TC: Configuration, S: Database + 'static, V: VRFKeyStorage> Directory<TC, S, V> {
    /// Updates the directory to include the updated key-value pairs with possible issues.
    pub(crate) async fn publish_malicious_update(
        &self,
        updates: Vec<(AkdLabel, AkdValue)>,
        corruption: PublishCorruption,
    ) -> Result<EpochHash, AkdError> {
        // The guard will be dropped at the end of the publish
        let _guard = self.cache_lock.read().await;

        let mut update_set = Vec::<AzksElement>::new();

        if let PublishCorruption::MarkVersionStale(ref akd_label, version_number) = corruption {
            // In the malicious case, sometimes the server may not mark the old version stale immediately.
            // If this is the case, it may want to do this marking at a later time.
            let stale_label = self
                .vrf
                .get_node_label::<TC>(akd_label, VersionFreshness::Stale, version_number)
                .await?;
            let stale_value_to_add = TC::stale_azks_value();
            update_set.push(AzksElement {
                label: stale_label,
                value: stale_value_to_add,
            })
        };

        let mut user_data_update_set = Vec::<ValueState>::new();

        let mut current_azks = self.retrieve_azks().await?;
        let current_epoch = current_azks.get_latest_epoch();
        let next_epoch = current_epoch + 1;

        let mut keys: Vec<AkdLabel> = updates
            .iter()
            .map(|(akd_label, _val)| akd_label.clone())
            .collect();
        // sort the keys, as inserting in primary-key order is more efficient for MySQL
        keys.sort();

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

        let commitment_key = self.derive_commitment_key().await?;

        for (akd_label, val) in updates {
            match all_user_versions_retrieved.get(&akd_label) {
                None => {
                    // no data found for the user
                    let latest_version = 1;
                    let label = self
                        .vrf
                        .get_node_label::<TC>(&akd_label, VersionFreshness::Fresh, latest_version)
                        .await?;

                    let value_to_add =
                        TC::compute_fresh_azks_value(&commitment_key, &label, latest_version, &val);
                    update_set.push(AzksElement {
                        label,
                        value: value_to_add,
                    });
                    let latest_state =
                        ValueState::new(akd_label, val, latest_version, label, next_epoch);
                    user_data_update_set.push(latest_state);
                }
                Some((_, previous_value)) if val == *previous_value => {
                    // skip this version because the user is trying to re-publish the already most recent value
                    // Issue #197: https://github.com/facebook/akd/issues/197
                }
                Some((previous_version, _)) => {
                    // Data found for the given user
                    let latest_version = *previous_version + 1;
                    let stale_label = self
                        .vrf
                        .get_node_label::<TC>(
                            &akd_label,
                            VersionFreshness::Stale,
                            *previous_version,
                        )
                        .await?;
                    let fresh_label = self
                        .vrf
                        .get_node_label::<TC>(&akd_label, VersionFreshness::Fresh, latest_version)
                        .await?;
                    let stale_value_to_add = TC::stale_azks_value();
                    let fresh_value_to_add = TC::compute_fresh_azks_value(
                        &commitment_key,
                        &fresh_label,
                        latest_version,
                        &val,
                    );
                    match &corruption {
                        // Some malicious server might not want to mark an old and compromised key as stale.
                        // Thus, you only push the key if either the corruption is for some other username,
                        // or the corruption is not of the type that asks you to delay marking a stale value correctly.
                        PublishCorruption::UnmarkedStaleVersion(target_akd_label) => {
                            if *target_akd_label != akd_label {
                                update_set.push(AzksElement {
                                    label: stale_label,
                                    value: stale_value_to_add,
                                })
                            }
                        }
                        _ => update_set.push(AzksElement {
                            label: stale_label,
                            value: stale_value_to_add,
                        }),
                    };

                    update_set.push(AzksElement {
                        label: fresh_label,
                        value: fresh_value_to_add,
                    });
                    let new_state =
                        ValueState::new(akd_label, val, latest_version, fresh_label, next_epoch);
                    user_data_update_set.push(new_state);
                }
            }
        }
        let azks_element_set: Vec<AzksElement> = update_set.to_vec();

        if azks_element_set.is_empty() {
            info!("After filtering for duplicated user information, there is no publish which is necessary (0 updates)");
            // The AZKS has not been updated/mutated at this point, so we can just return the root hash from before
            let root_hash = current_azks.get_root_hash::<TC, _>(&self.storage).await?;
            return Ok(EpochHash(current_epoch, root_hash));
        }

        if let false = self.storage.begin_transaction() {
            error!("Transaction is already active");
            return Err(AkdError::Storage(StorageError::Transaction(
                "Transaction is already active".to_string(),
            )));
        }
        info!("Starting database insertion");

        current_azks
            .batch_insert_nodes::<TC, _>(&self.storage, azks_element_set, InsertMode::Directory)
            .await?;

        // batch all the inserts into a single transactional write to storage
        let mut updates = vec![DbRecord::Azks(current_azks.clone())];
        for update in user_data_update_set.into_iter() {
            updates.push(DbRecord::ValueState(update));
        }
        self.storage.batch_set(updates).await?;

        // now commit the transaction
        if let Err(err) = self.storage.commit_transaction().await {
            // ignore any rollback error(s)
            let _ = self.storage.rollback_transaction();
            return Err(AkdError::Storage(err));
        }

        let root_hash = current_azks
            .get_root_hash_safe::<TC, _>(&self.storage, next_epoch)
            .await?;

        Ok(EpochHash(next_epoch, root_hash))
        // At the moment the tree root is not being written anywhere. Eventually we
        // want to change this to call a write operation to post to a blockchain or some such thing
    }
}
