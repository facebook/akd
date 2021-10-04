// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
use crate::append_only_zks::{Azks, AzksKey};
use crate::errors::{SeemlessDirectoryError, SeemlessError};

use crate::node_state::NodeLabel;
use crate::proof_structs::*;
use crate::storage::{Storable, Storage};

use rand::{prelude::ThreadRng, thread_rng};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::usize;
use winter_crypto::Hasher;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Username(String);

impl Username {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(get_random_str(rng))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct Values(String);

impl Values {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(get_random_str(rng))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct UserState {
    plaintext_val: Values, // This needs to be the plaintext value, to discuss
    version: u64,          // to discuss
    label: NodeLabel,
    epoch: u64,
}

impl UserState {
    pub fn new(plaintext_val: Values, version: u64, label: NodeLabel, epoch: u64) -> Self {
        UserState {
            plaintext_val,
            version,
            label,
            epoch,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct UserData {
    states: Vec<UserState>,
}

impl UserData {
    pub fn new(state: UserState) -> Self {
        UserData {
            states: vec![state],
        }
    }
}

pub struct SeemlessDirectory<S, H> {
    azks_id: Vec<u8>,
    user_data: HashMap<Username, UserData>,
    current_epoch: u64,
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}

impl<S: Storage, H: Hasher> SeemlessDirectory<S, H> {
    pub fn new() -> Result<Self, SeemlessError> {
        let mut rng: ThreadRng = thread_rng();
        let azks = Azks::<H, S>::new(&mut rng)?;
        let azks_id = azks.get_azks_id();

        Azks::store(AzksKey(azks_id.to_vec()), &azks)?;
        Ok(SeemlessDirectory {
            azks_id: azks_id.to_vec(),
            user_data: HashMap::<Username, UserData>::new(),
            current_epoch: 0,
            _s: PhantomData::<S>,
            _h: PhantomData::<H>,
        })
    }

    pub fn publish(&mut self, updates: Vec<(Username, Values)>) -> Result<(), SeemlessError> {
        let mut update_set = Vec::<(NodeLabel, H::Digest)>::new();
        let mut user_data_update_set = Vec::<(Username, UserData)>::new();
        let next_epoch = self.current_epoch + 1;
        for update in updates {
            let (uname, val) = update;
            let data = &self.user_data.get(&uname);
            match data {
                None => {
                    let latest_version = 1;
                    let label = Self::get_nodelabel(&uname, false, latest_version);
                    // Currently there's no blinding factor for the commitment.
                    // We'd want to change this later.
                    let value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push((label, value_to_add));
                    let latest_state = UserState::new(val, latest_version, label, next_epoch);
                    user_data_update_set.push((uname, UserData::new(latest_state)));
                }
                Some(user_data_val) => {
                    let latest_st = user_data_val.states.last().unwrap();
                    let previous_version = latest_st.version;
                    let latest_version = previous_version + 1;
                    let stale_label = Self::get_nodelabel(&uname, true, previous_version);
                    let fresh_label = Self::get_nodelabel(&uname, false, latest_version);
                    let stale_value_to_add = H::hash(&[0u8]);
                    let fresh_value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push((stale_label, stale_value_to_add));
                    update_set.push((fresh_label, fresh_value_to_add));
                    let new_state = UserState::new(val, latest_version, fresh_label, next_epoch);
                    let mut updatable_states = user_data_val.states.clone();
                    updatable_states.push(new_state);
                    user_data_update_set.push((
                        uname,
                        UserData {
                            states: updatable_states,
                        },
                    ));
                }
            }
        }
        let insertion_set = update_set.iter().map(|(x, y)| (*x, *y)).collect();
        // ideally the azks and the state would be updated together.
        // It may also make sense to have a temp version of the server's database
        let mut current_azks = Azks::<H, S>::retrieve(AzksKey(self.azks_id.clone()))?;
        let output = current_azks.batch_insert_leaves(insertion_set);
        Azks::store(AzksKey(self.azks_id.clone()), &current_azks)?;
        // Not sure how to remove clones from here?
        user_data_update_set.iter_mut().for_each(|(x, y)| {
            self.user_data.insert(x.clone(), y.clone());
        });
        self.current_epoch = next_epoch;
        output
        // At the moment the tree root is not being written anywhere. Eventually we
        // want to change this to call a write operation to post to a blockchain or some such thing
    }

    // Provides proof for correctness of latest version
    pub fn lookup(&self, uname: Username) -> Result<LookupProof<H>, SeemlessError> {
        let data = &self.user_data.get(&uname);
        match data {
            None => {
                // Need to throw an error
                Err(SeemlessError::SeemlessDirectoryErr(
                    SeemlessDirectoryError::LookedUpNonExistentUser(uname.0, self.current_epoch),
                ))
            }
            Some(user_data_val) => {
                // Need to account for the case where the latest state is
                // added but the database is in the middle of an update
                let latest_st = user_data_val.states.last().unwrap();
                let plaintext_value = latest_st.plaintext_val.clone();
                let current_version = latest_st.version;
                let marker_version = 1 << Self::get_marker_version(current_version);
                let existent_label = Self::get_nodelabel(&uname, false, current_version);
                let non_existent_label = Self::get_nodelabel(&uname, true, current_version);
                let marker_label = Self::get_nodelabel(&uname, false, marker_version);
                let current_azks = Azks::<H, S>::retrieve(AzksKey(self.azks_id.clone()))?;
                let existence_proof =
                    current_azks.get_membership_proof(existent_label, self.current_epoch)?;
                let freshness_proof = current_azks
                    .get_non_membership_proof(non_existent_label, self.current_epoch)?;
                let marker_proof =
                    current_azks.get_membership_proof(marker_label, self.current_epoch)?;
                Ok(LookupProof {
                    epoch: self.current_epoch,
                    plaintext_value,
                    version: current_version,
                    existence_proof,
                    marker_proof,
                    freshness_proof,
                })
            }
        }
    }

    // pub fn lookup_verify(
    //     &self,
    //     uname: Username,
    //     proof: LookupProof<H>,
    // ) -> Result<(), SeemlessError> {
    //     let epoch = proof.epoch;

    //     let node = HistoryTreeNode::<H, S>::retrieve(NodeKey(self.get_azks_id().to_vec(), 0))?;
    //     let root_node = node.get_value_at_epoch(epoch)?;
    //     let plaintext_value = proof.plaintext_value;
    //     let _curr_value = H::hash(&Self::value_to_bytes(&plaintext_value));
    //     let version = proof.version;

    //     let marker_version = 1 << Self::get_marker_version(version);
    //     let existence_proof = proof.existence_proof;
    //     let marker_proof = proof.marker_proof;
    //     let freshness_proof = proof.freshness_proof;

    //     let existence_label = Self::get_nodelabel(&uname, false, version);
    //     if existence_label != existence_proof.label {
    //         return Err(SeemlessError::SeemlessDirectoryErr(
    //             SeemlessDirectoryError::LookupVerificationErr(
    //                 "Existence proof label does not match computed label".to_string(),
    //             ),
    //         ));
    //     }
    //     let non_existence_label = Self::get_nodelabel(&uname, true, version);
    //     if non_existence_label != freshness_proof.label {
    //         return Err(SeemlessError::SeemlessDirectoryErr(
    //             SeemlessDirectoryError::LookupVerificationErr(
    //                 "Freshness proof label does not match computed label".to_string(),
    //             ),
    //         ));
    //     }
    //     let marker_label = Self::get_nodelabel(&uname, false, marker_version);
    //     if marker_label != marker_proof.label {
    //         return Err(SeemlessError::SeemlessDirectoryErr(
    //             SeemlessDirectoryError::LookupVerificationErr(
    //                 "Marker proof label does not match computed label".to_string(),
    //             ),
    //         ));
    //     }
    //     let current_azks = Azks::<H, S>::retrieve(AzksKey(self.azks_id.clone()))?;
    //     current_azks.verify_membership(root_node, epoch, &existence_proof)?;
    //     current_azks.verify_membership(root_node, epoch, &marker_proof)?;

    //     current_azks.verify_nonmembership(
    //         non_existence_label,
    //         root_node,
    //         epoch,
    //         &freshness_proof,
    //     )?;

    //     Ok(())
    // }

    /// Takes in the current state of the server and a label.
    /// If the label is present in the current state,
    /// this function returns all the values ever associated with it,
    /// and the epoch at which each value was first committed to the server state.
    /// It also returns the proof of the latest version being served at all times.
    pub fn key_history(&self, uname: &Username) -> Result<HistoryProof<H>, SeemlessError> {
        let username = uname.0.to_string();
        let this_user_data =
            self.user_data
                .get(uname)
                .ok_or(SeemlessDirectoryError::LookedUpNonExistentUser(
                    username,
                    self.current_epoch,
                ))?;
        let mut proofs = Vec::<UpdateProof<H>>::new();
        for user_state in &this_user_data.states {
            let proof = self.create_single_update_proof(uname, user_state)?;

            proofs.push(proof);
        }
        Ok(HistoryProof { proofs })
    }

    // Needs error handling in case the epochs are invalid
    pub fn audit(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<AppendOnlyProof<H>, SeemlessError> {
        let current_azks = Azks::<H, S>::retrieve(AzksKey(self.azks_id.clone()))?;
        current_azks.get_append_only_proof(audit_start_ep, audit_end_ep)
    }

    /// HELPERS ///

    #[allow(unused)]
    fn get_azks_id(&self) -> &[u8] {
        &self.azks_id
    }

    #[allow(unused)]
    fn username_to_nodelabel(_uname: &Username) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    // TODO: we need to make this only work on the server and have another function
    // that verifies nodelabel.
    pub(crate) fn get_nodelabel(uname: &Username, stale: bool, version: u64) -> NodeLabel {
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

    pub fn value_to_bytes(_value: &Values) -> [u8; 64] {
        [0u8; 64]
        // unimplemented!()
    }

    pub(crate) fn get_marker_version(version: u64) -> u64 {
        (64 - version.leading_zeros() - 1).into()
    }

    fn create_single_update_proof(
        &self,
        uname: &Username,
        user_state: &UserState,
    ) -> Result<UpdateProof<H>, SeemlessError> {
        let epoch = user_state.epoch;
        let plaintext_value = &user_state.plaintext_val;
        let version = &user_state.version;

        let label_at_ep = Self::get_nodelabel(uname, false, *version);

        let current_azks = Azks::<H, S>::retrieve(AzksKey(self.azks_id.clone()))?;

        let existence_at_ep = current_azks.get_membership_proof(label_at_ep, epoch)?;
        let mut previous_val_stale_at_ep = Option::None;
        if *version > 1 {
            let prev_label_at_ep = Self::get_nodelabel(uname, true, *version - 1);
            previous_val_stale_at_ep =
                Option::Some(current_azks.get_membership_proof(prev_label_at_ep, epoch)?);
        }
        let mut non_existence_before_ep = Option::None;
        if epoch != 0 {
            non_existence_before_ep =
                Option::Some(current_azks.get_non_membership_proof(label_at_ep, epoch - 1)?);
        }

        let next_marker = Self::get_marker_version(*version) + 1;
        let final_marker = Self::get_marker_version(epoch);

        let mut non_existence_of_next_few = Vec::<NonMembershipProof<H>>::new();

        for ver in version + 1..(1 << next_marker) {
            let label_for_ver = Self::get_nodelabel(uname, false, ver);
            let non_existence_of_ver =
                current_azks.get_non_membership_proof(label_for_ver, epoch)?;
            non_existence_of_next_few.push(non_existence_of_ver);
        }

        let mut non_existence_of_future_markers = Vec::<NonMembershipProof<H>>::new();

        for marker_power in next_marker..final_marker + 1 {
            let ver = 1 << marker_power;
            let label_for_ver = Self::get_nodelabel(uname, false, ver);
            let non_existence_of_ver =
                current_azks.get_non_membership_proof(label_for_ver, epoch)?;
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

    // pub fn verify_single_update_proof(
    //     &self,
    //     proof: UpdateProof<H>,
    //     uname: &Username,
    // ) -> Result<(), SeemlessError> {
    //     let epoch = proof.epoch;
    //     let _plaintext_value = &proof.plaintext_value;
    //     let version = proof.version;
    //     let label_at_ep = Self::get_nodelabel(uname, false, version);
    //     let _prev_label_at_ep = Self::get_nodelabel(uname, true, version - 1);
    //     let existence_at_ep_ref = &proof.existence_at_ep;
    //     let existence_at_ep = existence_at_ep_ref;
    //     let existence_at_ep_label = existence_at_ep_ref.label;
    //     let previous_val_stale_at_ep = &proof.previous_val_stale_at_ep;

    //     let current_azks = Azks::<H, S>::retrieve(AzksKey(self.azks_id.clone()))?;

    //     let non_existence_before_ep = &proof.non_existence_before_ep;
    //     let root_hash = current_azks.get_root_hash_at_epoch(epoch)?;

    //     if label_at_ep != existence_at_ep_label {
    //         return Err(SeemlessError::SeemlessDirectoryErr(
    //             SeemlessDirectoryError::KeyHistoryVerificationErr(
    //                 format!("Label of user {:?}'s version {:?} at epoch {:?} does not match the one in the proof",
    //                 uname, version, epoch))));
    //     }
    //     current_azks.verify_membership(root_hash, epoch, existence_at_ep)?;
    //     //     return Err(SeemlessError::SeemlessDirectoryErr(
    //     //         SeemlessDirectoryError::KeyHistoryVerificationErr(format!(
    //     //             "Existence proof of user {:?}'s version {:?} at epoch {:?} does not verify",
    //     //             uname, version, epoch
    //     //         )),
    //     //     ));
    //     // }

    //     // Edge case here! We need to account for version = 1 where the previous version won't have a proof.
    //     if version > 1 {
    //         let err_str = format!(
    //             "Staleness proof of user {:?}'s version {:?} at epoch {:?} is None",
    //             uname,
    //             (version - 1),
    //             epoch
    //         );
    //         let previous_null_err = SeemlessError::SeemlessDirectoryErr(
    //             SeemlessDirectoryError::KeyHistoryVerificationErr(err_str),
    //         );
    //         let previous_val_stale_at_ep =
    //             previous_val_stale_at_ep.as_ref().ok_or(previous_null_err)?;
    //         current_azks.verify_membership(root_hash, epoch, previous_val_stale_at_ep)?;
    //     }

    //     if epoch > 1 {
    //         let root_hash = current_azks.get_root_hash_at_epoch(epoch - 1)?;
    //         current_azks.verify_nonmembership(
    //             label_at_ep,
    //             root_hash,
    //             epoch - 1,
    //             non_existence_before_ep.as_ref().ok_or_else(|| SeemlessError::SeemlessDirectoryErr(SeemlessDirectoryError::KeyHistoryVerificationErr(format!(
    //                 "Non-existence before this epoch proof of user {:?}'s version {:?} at epoch {:?} is None",
    //                 uname,
    //                 version,
    //                 epoch
    //             ))))?
    //         )?;
    //     }

    //     let next_marker = Self::get_marker_version(version) + 1;
    //     let final_marker = Self::get_marker_version(epoch);
    //     for (i, ver) in (version + 1..(1 << next_marker)).enumerate() {
    //         let _label_for_ver = Self::get_nodelabel(uname, false, ver);
    //         let pf = &proof.non_existence_of_next_few[i];
    //         if !current_azks.verify_nonmembership(label_at_ep, root_hash, epoch - 1, pf)? {
    //             return Err(SeemlessError::SeemlessDirectoryErr(
    //                 SeemlessDirectoryError::KeyHistoryVerificationErr(
    //                     format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
    //                     uname, version, epoch-1))));
    //         }
    //     }

    //     for (i, pow) in (next_marker + 1..final_marker).enumerate() {
    //         let ver = 1 << pow;
    //         let _label_for_ver = Self::get_nodelabel(uname, false, ver);
    //         let pf = &proof.non_existence_of_future_markers[i];
    //         if !current_azks.verify_nonmembership(label_at_ep, root_hash, epoch - 1, pf)? {
    //             return Err(SeemlessError::SeemlessDirectoryErr(
    //                 SeemlessDirectoryError::KeyHistoryVerificationErr(
    //                     format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
    //                     uname, version, epoch-1))));
    //         }
    //     }

    //     Ok(())
    // }

    pub fn get_root_hash_at_epoch(&self, epoch: u64) -> Result<H::Digest, SeemlessError> {
        let current_azks = Azks::<H, S>::retrieve(AzksKey(self.azks_id.clone()))?;
        Ok(current_azks.get_root_hash_at_epoch(epoch)?)
    }

    pub fn get_root_hash(&self) -> Result<H::Digest, SeemlessError> {
        self.get_root_hash_at_epoch(self.current_epoch)
    }
}

/// Helpers

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

pub fn get_key_history_hashes<S: Storage, H: Hasher>(
    seemless_dir: &SeemlessDirectory<S, H>,
    history_proof: &HistoryProof<H>,
) -> Result<KeyHistoryHelper<H::Digest>, SeemlessError> {
    let mut root_hashes = Vec::<H::Digest>::new();
    let mut previous_root_hashes = Vec::<Option<H::Digest>>::new();
    for proof in &history_proof.proofs {
        if proof.epoch == 1 {
            previous_root_hashes.push(None);
        } else {
            previous_root_hashes.push(Some(seemless_dir.get_root_hash_at_epoch(proof.epoch - 1)?));
        }
        root_hashes.push(seemless_dir.get_root_hash_at_epoch(proof.epoch)?)
    }
    Ok((root_hashes, previous_root_hashes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        seemless_client::{audit_verify, key_history_verify, lookup_verify},
        tests::InMemoryDb,
    };
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;

    // FIXME: #[test]
    #[allow(unused)]
    #[test]
    fn test_simple_publish() -> Result<(), SeemlessError> {
        let mut seemless = SeemlessDirectory::<InMemoryDb, Blake3_256<BaseElement>>::new()?;

        seemless.publish(vec![(
            Username("hello".to_string()),
            Values("world".to_string()),
        )])?;

        Ok(())
    }

    #[test]
    fn test_simiple_lookup() -> Result<(), SeemlessError> {
        let mut seemless = SeemlessDirectory::<InMemoryDb, Blake3_256<BaseElement>>::new()?;

        seemless.publish(vec![
            (Username("hello".to_string()), Values("world".to_string())),
            (Username("hello2".to_string()), Values("world2".to_string())),
        ])?;

        let lookup_proof = seemless.lookup(Username("hello".to_string()))?;
        let root_hash = seemless.get_root_hash()?;
        lookup_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            root_hash,
            Username("hello".to_string()),
            lookup_proof,
        )?;
        Ok(())
    }

    #[test]
    fn test_simple_key_history() -> Result<(), SeemlessError> {
        let mut seemless = SeemlessDirectory::<InMemoryDb, Blake3_256<BaseElement>>::new()?;

        seemless.publish(vec![
            (Username("hello".to_string()), Values("world".to_string())),
            (Username("hello2".to_string()), Values("world2".to_string())),
        ])?;

        seemless.publish(vec![
            (Username("hello".to_string()), Values("world3".to_string())),
            (Username("hello2".to_string()), Values("world4".to_string())),
        ])?;

        seemless.publish(vec![
            (Username("hello3".to_string()), Values("world".to_string())),
            (Username("hello4".to_string()), Values("world2".to_string())),
        ])?;

        seemless.publish(vec![(
            Username("hello".to_string()),
            Values("world_updated".to_string()),
        )])?;

        seemless.publish(vec![
            (Username("hello3".to_string()), Values("world6".to_string())),
            (
                Username("hello4".to_string()),
                Values("world12".to_string()),
            ),
        ])?;

        let history_proof = seemless.key_history(&Username("hello".to_string()))?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&seemless, &history_proof)?;
        key_history_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            root_hashes,
            previous_root_hashes,
            Username("hello".to_string()),
            history_proof,
        )?;

        let history_proof = seemless.key_history(&Username("hello2".to_string()))?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&seemless, &history_proof)?;
        key_history_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            root_hashes,
            previous_root_hashes,
            Username("hello2".to_string()),
            history_proof,
        )?;

        let history_proof = seemless.key_history(&Username("hello3".to_string()))?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&seemless, &history_proof)?;
        key_history_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            root_hashes,
            previous_root_hashes,
            Username("hello3".to_string()),
            history_proof,
        )?;

        let history_proof = seemless.key_history(&Username("hello4".to_string()))?;
        let (root_hashes, previous_root_hashes) =
            get_key_history_hashes(&seemless, &history_proof)?;
        key_history_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            root_hashes,
            previous_root_hashes,
            Username("hello4".to_string()),
            history_proof,
        )?;

        Ok(())
    }

    #[allow(unused)]
    #[test]
    fn test_simple_audit() -> Result<(), SeemlessError> {
        let mut seemless = SeemlessDirectory::<InMemoryDb, Blake3_256<BaseElement>>::new()?;

        seemless.publish(vec![
            (Username("hello".to_string()), Values("world".to_string())),
            (Username("hello2".to_string()), Values("world2".to_string())),
        ])?;

        seemless.publish(vec![
            (Username("hello".to_string()), Values("world3".to_string())),
            (Username("hello2".to_string()), Values("world4".to_string())),
        ])?;

        seemless.publish(vec![
            (Username("hello3".to_string()), Values("world".to_string())),
            (Username("hello4".to_string()), Values("world2".to_string())),
        ])?;

        seemless.publish(vec![(
            Username("hello".to_string()),
            Values("world_updated".to_string()),
        )])?;

        seemless.publish(vec![
            (Username("hello3".to_string()), Values("world6".to_string())),
            (
                Username("hello4".to_string()),
                Values("world12".to_string()),
            ),
        ])?;

        let audit_proof_1 = seemless.audit(1, 2)?;
        audit_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            seemless.get_root_hash_at_epoch(1)?,
            seemless.get_root_hash_at_epoch(2)?,
            audit_proof_1,
        )?;

        let audit_proof_2 = seemless.audit(1, 3)?;
        audit_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            seemless.get_root_hash_at_epoch(1)?,
            seemless.get_root_hash_at_epoch(3)?,
            audit_proof_2,
        )?;

        let audit_proof_3 = seemless.audit(1, 4)?;
        audit_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            seemless.get_root_hash_at_epoch(1)?,
            seemless.get_root_hash_at_epoch(4)?,
            audit_proof_3,
        )?;

        let audit_proof_4 = seemless.audit(1, 5)?;
        audit_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            seemless.get_root_hash_at_epoch(1)?,
            seemless.get_root_hash_at_epoch(5)?,
            audit_proof_4,
        )?;

        let audit_proof_5 = seemless.audit(2, 3)?;
        audit_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            seemless.get_root_hash_at_epoch(2)?,
            seemless.get_root_hash_at_epoch(3)?,
            audit_proof_5,
        )?;

        let audit_proof_6 = seemless.audit(2, 4)?;
        audit_verify::<Blake3_256<BaseElement>, InMemoryDb>(
            seemless.get_root_hash_at_epoch(2)?,
            seemless.get_root_hash_at_epoch(4)?,
            audit_proof_6,
        )?;

        Ok(())
    }
}
