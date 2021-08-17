// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
use crate::append_only_zks::{AppendOnlyProof, NonMembershipProof};
use crate::append_only_zks::{Azks, MembershipProof};
use crate::errors::{SeemlessDirectoryError, SeemlessError};

use crate::history_tree_node::HistoryTreeNode;

use crate::node_state::NodeLabel;
use crate::storage::{
    IdEnum::{self, *},
    Storage, StorageEnum,
};
use crypto::Hasher;
use rand::{prelude::ThreadRng, thread_rng};
use std::collections::HashMap;
use std::marker::PhantomData;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Username(String);

#[derive(Clone)]
pub struct Values(String);

#[derive(Clone)]
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

#[derive(Clone)]
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

pub struct LookupProof<H: Hasher> {
    epoch: u64,
    plaintext_value: Values,
    version: u64,
    existence_proof: MembershipProof<H>,
    marker_proof: MembershipProof<H>,
    freshness_proof: NonMembershipProof<H>,
}

pub struct UpdateProof<H: Hasher> {
    epoch: u64,
    plaintext_value: Values,
    version: u64,
    existence_at_ep: MembershipProof<H>, // membership proof to show that the key was included in this epoch
    previous_val_stale_at_ep: MembershipProof<H>, // proof that previous value was set to old at this epoch
    non_existence_before_ep: NonMembershipProof<H>, // proof that this value didn't exist prior to this ep
    #[allow(unused)]
    non_existence_of_next_few: Vec<NonMembershipProof<H>>, // proof that the next few values did not exist at this time
    #[allow(unused)]
    non_existence_of_future_markers: Vec<NonMembershipProof<H>>, // proof that future markers did not exist
}

pub struct HistoryProof<H: Hasher> {
    #[allow(unused)]
    proofs: Vec<UpdateProof<H>>,
}


pub struct SeemlessDirectory<S: Storage<StorageEnum<H, S>>, H: Hasher> {
    azks_id: Vec<u8>,
    user_data: HashMap<Username, UserData>,
    current_epoch: u64,
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}


impl<S: Storage<StorageEnum<H, S>>, H: Hasher> SeemlessDirectory<S, H> {
    pub fn new() -> Result<Self, SeemlessError> {
        let mut rng: ThreadRng = thread_rng();
        let azks = Azks::<H, S>::new(&mut rng)?;
        let azks_id = azks.get_azks_id();
        StorageEnum::write_data(IdEnum::AzksId(azks_id), StorageEnum::Azks(azks.clone()))?;
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
        let mut current_azks =
            StorageEnum::<H, S>::to_azks(StorageEnum::read_data("azks", self.get_azks_id_enum()))?;
        let output = current_azks.batch_insert_leaves(insertion_set);
        StorageEnum::write_data(self.get_azks_id_enum(), StorageEnum::Azks(current_azks))?;
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
        // FIXME: restore with: LookupProof<H> {
        // FIXME: this code won't work
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
              
                let current_azks = StorageEnum::<H, S>::to_azks(StorageEnum::read_data(
                    "azks",
                    self.get_azks_id_enum(),
                ))?;
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

    pub fn lookup_verify(
        &self,
        uname: Username,
        proof: LookupProof<H>,
    ) -> Result<(), SeemlessError> {
        let epoch = proof.epoch;
        let node = StorageEnum::<H, S>::to_node(StorageEnum::read_data(
            "history_tree_node",
            NodeLocation(self.get_azks_id(), 0),
        ))?;
        let root_node = node.get_value_at_epoch(epoch)?;
        let plaintext_value = proof.plaintext_value;
        let _curr_value = H::hash(&Self::value_to_bytes(&plaintext_value));
        let version = proof.version;

        let marker_version = 1 << Self::get_marker_version(version);
        let existence_proof = proof.existence_proof;
        let marker_proof = proof.marker_proof;
        let freshness_proof = proof.freshness_proof;

        let existence_label = Self::get_nodelabel(&uname, false, version);
        if existence_label != existence_proof.label {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::LookupVerificationErr(
                    "Existence proof label does not match computed label".to_string(),
                ),
            ));
        }
        let non_existence_label = Self::get_nodelabel(&uname, true, version);
        if non_existence_label != freshness_proof.label {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::LookupVerificationErr(
                    "Freshness proof label does not match computed label".to_string(),
                ),
            ));
        }
        let marker_label = Self::get_nodelabel(&uname, false, marker_version);

        if marker_label != marker_proof.label {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::LookupVerificationErr(
                    "Marker proof label does not match computed label".to_string(),
                ),
            ));
        }
        let current_azks =
            StorageEnum::<H, S>::to_azks(StorageEnum::read_data("azks", self.get_azks_id_enum()))?;
        current_azks.verify_membership(root_node, epoch, existence_proof)?;
        current_azks.verify_membership(root_node, epoch, marker_proof)?;

        current_azks.verify_nonmembership(
            non_existence_label,
            root_node,
            epoch,
            freshness_proof,
        )?;
        Ok(())
    }

    /// Takes in the current state of the server and a label.
    /// If the label is present in the current state,
    /// this function returns all the values ever associated with it,
    /// and the epoch at which each value was first committed to the server state.
    /// It also returns the proof of the latest version being served at all times.
    pub fn key_history(&self, uname: &Username) -> Result<HistoryProof<H>, SeemlessError> {
        // pub struct UpdateProof<H: Hasher> {
        //     epoch: u64,
        //     plaintext_value: Values,
        //     version: u64,
        //     existence_at_ep: MembershipProof<H>, // membership proof to show that the key was included in this epoch
        //     previous_val_stale_at_ep: MembershipProof<H>, // proof that previous value was set to old at this epoch
        //     non_existence_before_ep: NonMembershipProof<H>, // proof that this value didn't exist prior to this ep
        //     non_existence_of_next_few: Vec<NonMembershipProof<H>>, // proof that the next few values did not exist at this time
        //     non_existence_of_future_markers: Vec<NonMembershipProof<H>>, // proof that future markers did not exist
        // }

        // pub struct HistoryProof<H: Hasher> {
        //     proofs: Vec<UpdateProof<H>>,
        // }
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

    pub fn key_history_verify(
        &self,
        _uname: Username,
        _proof: HistoryProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }

    pub fn audit(
        &self,
        _audit_start_ep: u64,
        _audit_end_ep: u64,
    ) -> Result<Vec<AppendOnlyProof<H>>, SeemlessDirectoryError> {
        unimplemented!()
    }

    pub fn audit_verify(
        &self,
        _audit_start_ep: u64,
        _audit_end_ep: u64,
        _proof: HistoryProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }

    /// HELPERS ///

    #[allow(unused)]
    fn get_azks_id_enum(&self) -> IdEnum {
        IdEnum::AzksId(&self.azks_id)
    }

    #[allow(unused)]
    fn get_azks_id(&self) -> &[u8] {
        &self.azks_id
    }

    #[allow(unused)]
    fn username_to_nodelabel(_uname: &Username) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    fn get_nodelabel(uname: &Username, stale: bool, version: u64) -> NodeLabel {
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
        // let (hashed_label_bytes_ref, _) = label_slice.split_at(std::mem::size_of::<u64>());
        let hashed_label_bytes = convert_byte_slice_to_array(label_slice);
        NodeLabel::new(u64::from_ne_bytes(hashed_label_bytes), 64u32)
        // unimplemented!()
    }

    fn value_to_bytes(_value: &Values) -> [u8; 64] {
        [0u8; 64]
        // unimplemented!()
    }

    fn get_marker_version(version: u64) -> u64 {
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
        let prev_label_at_ep = Self::get_nodelabel(uname, true, *version);


        let current_azks =
            StorageEnum::<H, S>::to_azks(StorageEnum::read_data("azks", self.get_azks_id_enum()))?;

        let existence_at_ep = current_azks.get_membership_proof(label_at_ep, epoch)?;
        let previous_val_stale_at_ep =
            current_azks.get_membership_proof(prev_label_at_ep, epoch)?;
        let non_existence_before_ep =
            current_azks.get_non_membership_proof(label_at_ep, epoch - 1)?;


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

    pub fn _verify_single_update_proof(
        &self,
        proof: UpdateProof<H>,
        uname: &Username,
    ) -> Result<(), SeemlessError> {
        let epoch = proof.epoch;
        let _plaintext_value = proof.plaintext_value;
        let version = proof.version;
        let label_at_ep = Self::get_nodelabel(uname, false, version);
        let _prev_label_at_ep = Self::get_nodelabel(uname, true, version);
        let existence_at_ep = proof.existence_at_ep;
        let previous_val_stale_at_ep = proof.previous_val_stale_at_ep;

        let current_azks =
            StorageEnum::<H, S>::to_azks(StorageEnum::read_data("azks", self.get_azks_id_enum()))?;

        let non_existence_before_ep = proof.non_existence_before_ep;
        let root_hash = current_azks.get_root_hash_at_epoch(epoch)?;

        if label_at_ep != existence_at_ep.label {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::KeyHistoryVerificationErr(
                    format!("Label of user {:?}'s version {:?} at epoch {:?} does not match the one in the proof",
                    uname, version, epoch))));
        }
        if !current_azks.verify_membership(root_hash, epoch, existence_at_ep)? {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::KeyHistoryVerificationErr(format!(
                    "Existence proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, version, epoch
                )),
            ));
        }
        // Edge case here! We need to account for version = 1 where the previous version won't have a proof.
        if !current_azks.verify_membership(root_hash, epoch, previous_val_stale_at_ep)? {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::KeyHistoryVerificationErr(format!(
                    "Staleness proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname,
                    version - 1,
                    epoch
                )),
            ));
        }
        if !current_azks.verify_nonmembership(
            label_at_ep,
            root_hash,
            epoch - 1,
            non_existence_before_ep,
        )? {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::KeyHistoryVerificationErr(
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, version, epoch-1))));
        }

        let _next_marker = Self::get_marker_version(version) + 1;
        let _final_marker = Self::get_marker_version(epoch);
        // for (i, ver) in (version + 1..(1 << next_marker)).enumerate() {
        //     let label_for_ver = Self::get_nodelabel(uname, false, ver);
        //     let pf = proof.non_existence_of_next_few[i];
        //     if !self.azks.verify_nonmembership(label_at_ep, root_hash, epoch - 1, pf) {
        //         return Err(SeemlessError::SeemlessDirectoryErr(
        //             SeemlessDirectoryError::KeyHistoryVerificationErr(
        //                 format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
        //                 uname, version, epoch-1))));
        //     }
        // }

        Ok(())
        // unimplemented!()
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
    // unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::InMemoryDb;
    use crypto::hashers::Blake3_256;
    use math::fields::f128::BaseElement;

    // FIXME: #[test]
    #[allow(unused)]
    #[test]
    fn test_simple_publish() -> Result<(), SeemlessError> {
        let mut seemless = SeemlessDirectory::<InMemoryDb, Blake3_256<BaseElement>>::new()?;

        seemless.publish(vec![(
            Username("hello".to_string()),
            Values("world".to_string()),
        )])?;
        // seemless.lookup(Username("hello".to_string()))?;

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
        seemless.lookup_verify(Username("hello".to_string()), lookup_proof)?;
        Ok(())
    }
}
