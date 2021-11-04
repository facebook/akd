// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implementation of a verifiable key directory

use crate::append_only_zks::Azks;

use crate::node_state::NodeLabel;
use crate::proof_structs::*;

use crate::errors::{AkdError, DirectoryError};

use crate::storage::types::{AkdKey, DbRecord, ValueState, ValueStateRetrievalFlag, Values};
use crate::storage::V2Storage;

use rand::{CryptoRng, RngCore};

use std::collections::HashMap;
use std::marker::{PhantomData, Send, Sync};
use winter_crypto::Hasher;

impl Values {
    /// Gets a random value for a VKD
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(get_random_str(rng))
    }
}

impl AkdKey {
    /// Creates a random key for a VKD
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(get_random_str(rng))
    }
}

/// The representation of a verifiable key directory
pub struct Directory<S, H> {
    current_epoch: u64,
    storage: S,
    _h: PhantomData<H>,
}

impl<S: V2Storage + Sync + Send, H: Hasher + Send + Sync> Directory<S, H> {
    /// Creates a new (stateless) instance of a verifiable key directory.
    /// Takes as input a pointer to the storage being used for this instance.
    /// The state is stored in the storage.
    pub async fn new(storage: &S) -> Result<Self, AkdError> {
        let azks = {
            if let Ok(azks) = Directory::get_azks_from_storage(storage).await {
                azks
            } else {
                // generate a new one
                let azks = Azks::<H>::new(storage).await?;
                // store it
                storage.set::<H>(DbRecord::Azks(azks.clone())).await?;
                azks
            }
        };
        Ok(Directory {
            current_epoch: azks.get_latest_epoch(),
            _h: PhantomData::<H>,
            storage: storage.clone(),
        })
    }

    /// Updates the directory to inclulde the updated key-value pairs.
    pub async fn publish(&mut self, updates: Vec<(AkdKey, Values)>) -> Result<(), AkdError> {
        let mut update_set = Vec::<(NodeLabel, H::Digest)>::new();
        let mut user_data_update_set = Vec::<ValueState>::new();
        let next_epoch = self.current_epoch + 1;
        for (uname, val) in updates {
            match self
                .storage
                .get_user_state::<H>(&uname, ValueStateRetrievalFlag::MaxEpoch)
                .await
            {
                Err(_) => {
                    // No data found for the user
                    let latest_version = 1;
                    let label = Self::get_nodelabel(&uname, false, latest_version);
                    // Currently there's no blinding factor for the commitment.
                    // We'd want to change this later.
                    let value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push((label, value_to_add));
                    let latest_state =
                        ValueState::new(uname, val, latest_version, label, next_epoch);
                    user_data_update_set.push(latest_state);
                }
                Ok(max_user_state) => {
                    // Data found for the given user
                    let latest_st = max_user_state;
                    let previous_version = latest_st.version;
                    let latest_version = previous_version + 1;
                    let stale_label = Self::get_nodelabel(&uname, true, previous_version);
                    let fresh_label = Self::get_nodelabel(&uname, false, latest_version);
                    let stale_value_to_add = H::hash(&[0u8]);
                    let fresh_value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push((stale_label, stale_value_to_add));
                    update_set.push((fresh_label, fresh_value_to_add));
                    let new_state =
                        ValueState::new(uname, val, latest_version, fresh_label, next_epoch);
                    user_data_update_set.push(new_state);
                }
            }
        }
        let insertion_set = update_set.iter().map(|(x, y)| (*x, *y)).collect();
        // ideally the azks and the state would be updated together.
        // It may also make sense to have a temp version of the server's database
        let mut current_azks = self.retrieve_current_azks().await?;
        let output = current_azks
            .batch_insert_leaves(&self.storage, insertion_set)
            .await;
        self.storage
            .set::<H>(DbRecord::Azks(current_azks.clone()))
            .await?;
        self.storage
            .append_user_states::<H>(user_data_update_set)
            .await?;
        self.current_epoch = next_epoch;
        output
        // At the moment the tree root is not being written anywhere. Eventually we
        // want to change this to call a write operation to post to a blockchain or some such thing
    }

    /// Provides proof for correctness of latest version
    pub async fn lookup(&self, uname: AkdKey) -> Result<LookupProof<H>, AkdError> {
        match self
            .storage
            .get_user_state::<H>(&uname, ValueStateRetrievalFlag::MaxEpoch)
            .await
        {
            Err(_) => {
                // Need to throw an error
                Err(AkdError::DirectoryErr(
                    DirectoryError::LookedUpNonExistentUser(uname.0, self.current_epoch),
                ))
            }
            Ok(latest_st) => {
                // Need to account for the case where the latest state is
                // added but the database is in the middle of an update
                let current_version = latest_st.version;
                let marker_version = 1 << get_marker_version(current_version);
                let existent_label = Self::get_nodelabel(&uname, false, current_version);
                let non_existent_label = Self::get_nodelabel(&uname, true, current_version);
                let marker_label = Self::get_nodelabel(&uname, false, marker_version);
                let current_azks = self.retrieve_current_azks().await?;
                Ok(LookupProof {
                    epoch: self.current_epoch,
                    plaintext_value: latest_st.plaintext_val,
                    version: current_version,
                    existence_proof: current_azks
                        .get_membership_proof(&self.storage, existent_label, self.current_epoch)
                        .await?,
                    marker_proof: current_azks
                        .get_membership_proof(&self.storage, marker_label, self.current_epoch)
                        .await?,
                    freshness_proof: current_azks
                        .get_non_membership_proof(
                            &self.storage,
                            non_existent_label,
                            self.current_epoch,
                        )
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
    pub async fn key_history(&self, uname: &AkdKey) -> Result<HistoryProof<H>, AkdError> {
        let username = uname.0.to_string();
        if let Ok(this_user_data) = self.storage.get_user_data::<H>(uname).await {
            let mut proofs = Vec::<UpdateProof<H>>::new();
            for user_state in &this_user_data.states {
                let proof = self.create_single_update_proof(uname, user_state).await?;
                proofs.push(proof);
            }
            Ok(HistoryProof { proofs })
        } else {
            Err(AkdError::DirectoryErr(
                DirectoryError::LookedUpNonExistentUser(username, self.current_epoch),
            ))
        }
    }

    /// Returns an AppendOnlyProof for the leaves inseted into the underlying tree between
    /// the epochs audit_start_ep and audit_end_ep.
    pub async fn audit(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<AppendOnlyProof<H>, AkdError> {
        let current_azks = self.retrieve_current_azks().await?;
        current_azks
            .get_append_only_proof(&self.storage, audit_start_ep, audit_end_ep)
            .await
    }

    /// Retrieves the current azks
    pub async fn retrieve_current_azks(&self) -> Result<Azks<H>, crate::errors::StorageError> {
        Directory::get_azks_from_storage(&self.storage).await
    }

    async fn get_azks_from_storage(storage: &S) -> Result<Azks<H>, crate::errors::StorageError> {
        let got = storage
            .get::<H, Azks<H>>(crate::append_only_zks::DEFAULT_AZKS_KEY)
            .await?;
        match got {
            DbRecord::Azks(azks) => Ok(azks),
            _ => Err(crate::errors::StorageError::GetError(String::from(
                "Not found",
            ))),
        }
    }

    /// HELPERS ///

    #[allow(unused)]
    fn username_to_nodelabel(_uname: &AkdKey) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    // FIXME: we need to make this only work on the server, use a VRF and have another function
    // that verifies nodelabel.
    /// Returns the tree nodelabel that corresponds to a version of the vkdkey argument.
    /// The stale boolean here is to indicate whether we are getting the nodelabel for a fresh version,
    /// or a version that we are retiring.
    pub(crate) fn get_nodelabel(uname: &AkdKey, stale: bool, version: u64) -> NodeLabel {
        // this function will need to read the VRF key using some function
        let name_hash_bytes = H::hash(uname.0.as_bytes());
        let mut stale_bytes = &[1u8];
        if stale {
            stale_bytes = &[0u8];
        }

        let hashed_label = H::merge(&[
            name_hash_bytes,
            H::merge_with_int(H::hash(stale_bytes), version),
        ]);
        let label_slice = hashed_label.as_ref();
        let hashed_label_bytes = convert_byte_slice_to_array(label_slice);
        NodeLabel::new(u64::from_ne_bytes(hashed_label_bytes), 64u32)
    }

    // FIXME: Make a real commitment here, alongwith a blinding factor.
    /// Gets the bytes for a value.
    pub fn value_to_bytes(_value: &Values) -> [u8; 64] {
        [0u8; 64]
        // unimplemented!()
    }

    async fn create_single_update_proof(
        &self,
        uname: &AkdKey,
        user_state: &ValueState,
    ) -> Result<UpdateProof<H>, AkdError> {
        let epoch = user_state.epoch;
        let plaintext_value = &user_state.plaintext_val;
        let version = &user_state.version;

        let label_at_ep = Self::get_nodelabel(uname, false, *version);

        let current_azks = self.retrieve_current_azks().await?;

        let existence_at_ep = current_azks
            .get_membership_proof(&self.storage, label_at_ep, epoch)
            .await?;
        let mut previous_val_stale_at_ep = Option::None;
        if *version > 1 {
            let prev_label_at_ep = Self::get_nodelabel(uname, true, *version - 1);
            previous_val_stale_at_ep = Option::Some(
                current_azks
                    .get_membership_proof(&self.storage, prev_label_at_ep, epoch)
                    .await?,
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

        let mut non_existence_of_next_few = Vec::<NonMembershipProof<H>>::new();

        for ver in version + 1..(1 << next_marker) {
            let label_for_ver = Self::get_nodelabel(uname, false, ver);
            let non_existence_of_ver = current_azks
                .get_non_membership_proof(&self.storage, label_for_ver, epoch)
                .await?;
            non_existence_of_next_few.push(non_existence_of_ver);
        }

        let mut non_existence_of_future_markers = Vec::<NonMembershipProof<H>>::new();

        for marker_power in next_marker..final_marker + 1 {
            let ver = 1 << marker_power;
            let label_for_ver = Self::get_nodelabel(uname, false, ver);
            let non_existence_of_ver = current_azks
                .get_non_membership_proof(&self.storage, label_for_ver, epoch)
                .await?;
            non_existence_of_future_markers.push(non_existence_of_ver);
        }

        Ok(UpdateProof {
            epoch,
            plaintext_value: plaintext_value.clone(),
            version: *version,
            existence_at_ep,
            previous_val_stale_at_ep,
            non_existence_before_ep,
            non_existence_of_next_few,
            non_existence_of_future_markers,
        })
    }

    /// Gets the azks root hash at the provided epoch. Note that the root hash should exist at any epoch
    /// that the azks existed, so as long as epoch >= 0, we should be fine.
    pub async fn get_root_hash_at_epoch(
        &self,
        current_azks: &Azks<H>,
        epoch: u64,
    ) -> Result<H::Digest, AkdError> {
        Ok(current_azks
            .get_root_hash_at_epoch(&self.storage, epoch)
            .await?)
    }

    /// Gets the azks root hash at the current epoch.
    pub async fn get_root_hash(&self, current_azks: &Azks<H>) -> Result<H::Digest, AkdError> {
        self.get_root_hash_at_epoch(current_azks, self.current_epoch)
            .await
    }
}

/// Helpers

pub(crate) fn get_marker_version(version: u64) -> u64 {
    (64 - version.leading_zeros() - 1).into()
}

/// Converts a slice of u8 to an array of length 8. If the
/// slice is not long enough, just pads with zeros.
fn convert_byte_slice_to_array(slice: &[u8]) -> [u8; 8] {
    let mut out_arr = [0u8; 8];
    for (count, elt) in slice.iter().enumerate() {
        if count < 8 {
            out_arr[count] = *elt;
        } else {
            break;
        }
    }
    out_arr
}

fn get_random_str<R: RngCore + CryptoRng>(rng: &mut R) -> String {
    let mut byte_str = [0u8; 32];
    rng.fill_bytes(&mut byte_str);
    format!("{:?}", &byte_str)
}

type KeyHistoryHelper<D> = (Vec<D>, Vec<Option<D>>);

/// Gets hashes for key history proofs
pub async fn get_key_history_hashes<S: V2Storage + Sync + Send, H: Hasher + Sync + Send>(
    akd_dir: &Directory<S, H>,
    history_proof: &HistoryProof<H>,
) -> Result<KeyHistoryHelper<H::Digest>, AkdError> {
    let mut epoch_hash_map: HashMap<u64, H::Digest> = HashMap::new();

    let mut root_hashes = Vec::<H::Digest>::new();
    let mut previous_root_hashes = Vec::<Option<H::Digest>>::new();
    let current_azks = akd_dir.retrieve_current_azks().await?;
    for proof in &history_proof.proofs {
        let hash = akd_dir
            .get_root_hash_at_epoch(&current_azks, proof.epoch)
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
                .get_root_hash_at_epoch(&current_azks, proof.epoch - 1)
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
        storage::memory::AsyncInMemoryDatabase,
    };
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;

    // FIXME: #[test]
    #[allow(unused)]
    #[actix_rt::test]
    async fn test_simple_publish() -> Result<(), AkdError> {
        let db = crate::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut akd = Directory::<
            crate::storage::V2FromV1StorageWrapper<AsyncInMemoryDatabase>,
            Blake3_256<BaseElement>,
        >::new(&db)
        .await?;

        akd.publish(vec![(
            AkdKey("hello".to_string()),
            Values("world".to_string()),
        )])
        .await?;
        Ok(())
    }

    #[actix_rt::test]
    async fn test_simiple_lookup() -> Result<(), AkdError> {
        let db = crate::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut akd = Directory::<
            crate::storage::V2FromV1StorageWrapper<AsyncInMemoryDatabase>,
            Blake3_256<BaseElement>,
        >::new(&db)
        .await?;

        akd.publish(vec![
            (AkdKey("hello".to_string()), Values("world".to_string())),
            (AkdKey("hello2".to_string()), Values("world2".to_string())),
        ])
        .await?;

        let lookup_proof = akd.lookup(AkdKey("hello".to_string())).await?;
        let current_azks = akd.retrieve_current_azks().await?;
        let root_hash = akd.get_root_hash(&current_azks).await?;
        lookup_verify::<Blake3_256<BaseElement>>(
            root_hash,
            AkdKey("hello".to_string()),
            lookup_proof,
        )?;
        Ok(())
    }

    #[actix_rt::test]
    async fn test_simple_key_history() -> Result<(), AkdError> {
        let db = crate::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut akd = Directory::<
            crate::storage::V2FromV1StorageWrapper<AsyncInMemoryDatabase>,
            Blake3_256<BaseElement>,
        >::new(&db)
        .await?;

        akd.publish(vec![
            (AkdKey("hello".to_string()), Values("world".to_string())),
            (AkdKey("hello2".to_string()), Values("world2".to_string())),
        ])
        .await?;

        akd.publish(vec![
            (AkdKey("hello".to_string()), Values("world".to_string())),
            (AkdKey("hello2".to_string()), Values("world2".to_string())),
        ])
        .await?;

        akd.publish(vec![
            (AkdKey("hello".to_string()), Values("world3".to_string())),
            (AkdKey("hello2".to_string()), Values("world4".to_string())),
        ])
        .await?;

        akd.publish(vec![
            (AkdKey("hello3".to_string()), Values("world".to_string())),
            (AkdKey("hello4".to_string()), Values("world2".to_string())),
        ])
        .await?;

        akd.publish(vec![(
            AkdKey("hello".to_string()),
            Values("world_updated".to_string()),
        )])
        .await?;

        akd.publish(vec![
            (AkdKey("hello3".to_string()), Values("world6".to_string())),
            (AkdKey("hello4".to_string()), Values("world12".to_string())),
        ])
        .await?;

        let history_proof = akd.key_history(&AkdKey("hello".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3_256<BaseElement>>(
            root_hashes,
            previous_root_hashes,
            AkdKey("hello".to_string()),
            history_proof,
        )?;

        let history_proof = akd.key_history(&AkdKey("hello2".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3_256<BaseElement>>(
            root_hashes,
            previous_root_hashes,
            AkdKey("hello2".to_string()),
            history_proof,
        )?;

        let history_proof = akd.key_history(&AkdKey("hello3".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3_256<BaseElement>>(
            root_hashes,
            previous_root_hashes,
            AkdKey("hello3".to_string()),
            history_proof,
        )?;

        let history_proof = akd.key_history(&AkdKey("hello4".to_string())).await?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&akd, &history_proof).await?;
        key_history_verify::<Blake3_256<BaseElement>>(
            root_hashes,
            previous_root_hashes,
            AkdKey("hello4".to_string()),
            history_proof,
        )?;

        Ok(())
    }

    #[allow(unused)]
    #[actix_rt::test]
    async fn test_simple_audit() -> Result<(), AkdError> {
        let db = crate::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut akd = Directory::<
            crate::storage::V2FromV1StorageWrapper<AsyncInMemoryDatabase>,
            Blake3_256<BaseElement>,
        >::new(&db)
        .await?;

        akd.publish(vec![
            (AkdKey("hello".to_string()), Values("world".to_string())),
            (AkdKey("hello2".to_string()), Values("world2".to_string())),
        ])
        .await?;

        akd.publish(vec![
            (AkdKey("hello".to_string()), Values("world".to_string())),
            (AkdKey("hello2".to_string()), Values("world2".to_string())),
        ])
        .await?;

        akd.publish(vec![
            (AkdKey("hello".to_string()), Values("world3".to_string())),
            (AkdKey("hello2".to_string()), Values("world4".to_string())),
        ])
        .await?;

        akd.publish(vec![
            (AkdKey("hello3".to_string()), Values("world".to_string())),
            (AkdKey("hello4".to_string()), Values("world2".to_string())),
        ])
        .await?;

        akd.publish(vec![(
            AkdKey("hello".to_string()),
            Values("world_updated".to_string()),
        )])
        .await?;

        akd.publish(vec![
            (AkdKey("hello3".to_string()), Values("world6".to_string())),
            (AkdKey("hello4".to_string()), Values("world12".to_string())),
        ])
        .await?;

        let current_azks = akd.retrieve_current_azks().await?;

        let audit_proof_1 = akd.audit(1, 2).await?;
        audit_verify::<Blake3_256<BaseElement>>(
            akd.get_root_hash_at_epoch(&current_azks, 1).await?,
            akd.get_root_hash_at_epoch(&current_azks, 2).await?,
            audit_proof_1,
        )
        .await?;

        let audit_proof_2 = akd.audit(1, 3).await?;
        audit_verify::<Blake3_256<BaseElement>>(
            akd.get_root_hash_at_epoch(&current_azks, 1).await?,
            akd.get_root_hash_at_epoch(&current_azks, 3).await?,
            audit_proof_2,
        )
        .await?;

        let audit_proof_3 = akd.audit(1, 4).await?;
        audit_verify::<Blake3_256<BaseElement>>(
            akd.get_root_hash_at_epoch(&current_azks, 1).await?,
            akd.get_root_hash_at_epoch(&current_azks, 4).await?,
            audit_proof_3,
        )
        .await?;

        let audit_proof_4 = akd.audit(1, 5).await?;
        audit_verify::<Blake3_256<BaseElement>>(
            akd.get_root_hash_at_epoch(&current_azks, 1).await?,
            akd.get_root_hash_at_epoch(&current_azks, 5).await?,
            audit_proof_4,
        )
        .await?;

        let audit_proof_5 = akd.audit(2, 3).await?;
        audit_verify::<Blake3_256<BaseElement>>(
            akd.get_root_hash_at_epoch(&current_azks, 2).await?,
            akd.get_root_hash_at_epoch(&current_azks, 3).await?,
            audit_proof_5,
        )
        .await?;

        let audit_proof_6 = akd.audit(2, 4).await?;
        audit_verify::<Blake3_256<BaseElement>>(
            akd.get_root_hash_at_epoch(&current_azks, 2).await?,
            akd.get_root_hash_at_epoch(&current_azks, 4).await?,
            audit_proof_6,
        )
        .await?;

        Ok(())
    }
}
