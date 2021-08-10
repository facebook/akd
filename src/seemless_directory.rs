// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
use crate::append_only_zks::{AppendOnlyProof, NonMembershipProof};
use crate::append_only_zks::{Azks, MembershipProof};
use crate::errors::{SeemlessDirectoryError, SeemlessError};
use crate::node_state::{HistoryNodeState, NodeLabel};
use crate::storage::Storage;
use crypto::Hasher;
use std::collections::HashMap;
use std::marker::PhantomData;
use rand::{prelude::ThreadRng, thread_rng, RngCore};

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Username(String);

// impl PartialEq for Username {
//     fn eq(&self, other: &Self) -> bool {
//         self.0 == other.0
//     }
// }

// impl Eq for Username {}

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
    plaintext_value: Values,
    version: u64,
    existence_proof: MembershipProof<H>,
    marker_proof: MembershipProof<H>,
    freshness_proof: NonMembershipProof<H>,
}

pub struct UpdateProof<H: Hasher> {
    plaintext_value: Values,
    version: u64,
    existence_at_ep: MembershipProof<H>, // membership proof to show that the key was included in this epoch
    previous_val_stale_at_ep: MembershipProof<H>, // proof that previous value was set to old at this epoch
    non_existence_before_ep: NonMembershipProof<H>, // proof that this value didn't exist prior to this ep
    non_existence_of_next_few: Vec<NonMembershipProof<H>>, // proof that the next few values did not exist at this time
    non_existence_of_future_markers: Vec<NonMembershipProof<H>>, // proof that future markers did not exist
}

pub struct HistoryProof<H: Hasher> {
    proofs: Vec<UpdateProof<H>>,
}

pub struct SeemlessDirectory<S: Storage<HistoryNodeState<H>>, H: Hasher> {
    azks: Azks<H, S>,
    user_data: HashMap<Username, UserData>,
    current_epoch: u64,
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}

impl<S: Storage<HistoryNodeState<H>>, H: Hasher> SeemlessDirectory<S, H> {

    pub fn new() -> Self {
        let mut rng: ThreadRng = thread_rng();
        SeemlessDirectory {
            azks: Azks::<H, S>::new(&mut rng),
            user_data: HashMap::<Username, UserData>::new(),
            current_epoch: 0,
            _s: PhantomData::<S>,
            _h: PhantomData::<H>,
        }
    }

    // FIXME: this code won't work
    pub fn publish(&mut self, updates: Vec<(Username, Values)>) -> Result<(), SeemlessError> {
        // for (_key, _val) in updates {
        //     S::set("0".to_string(), HistoryNodeState::new())
        //         .map_err(|_| SeemlessDirectoryError::StorageError)?;
        // }
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
        let output = self.azks.batch_insert_leaves(insertion_set);
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
                Err(SeemlessError::SeemlessDirectoryErr(SeemlessDirectoryError::LookedUpNonExistentUser(uname.0, self.current_epoch)))
            },
            Some(user_data_val) => {
                // pub struct LookupProof<H: Hasher> {
                //     plaintext_value: Values,
                //     version: u64,
                //     existence_proof: MembershipProof<H>,
                //     marker_proof: MembershipProof<H>,
                //     freshness_proof: NonMembershipProof<H>,
                // }
                // Need to account for the case where the latest state is
                // added but the database is in the middle of an update
                let latest_st = user_data_val.states.last().unwrap();
                let plaintext_value = latest_st.plaintext_val.clone();
                let current_version = latest_st.version;
                let marker_version = Self::get_marker_version(current_version);
                let existent_label = Self::get_nodelabel(&uname, false, current_version);
                let non_existent_label = Self::get_nodelabel(&uname, true, current_version);
                let marker_label = Self::get_nodelabel(&uname, true, marker_version);
                let existence_proof = self.azks.get_membership_proof(existent_label, self.current_epoch);
                let freshness_proof = self.azks.get_non_membership_proof(non_existent_label, self.current_epoch);
                let marker_proof = self.azks.get_membership_proof(marker_label, self.current_epoch);
                Ok(
                        LookupProof {
                            plaintext_value,
                            version: current_version,
                            existence_proof,
                            marker_proof,
                            freshness_proof,
                        }
                )

            }
        }
        // unimplemented!()
        // S::get("0".to_string()).unwrap();
        // Ok(())
    }

    pub fn lookup_verify(
        _uname: Username,
        _proof: LookupProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }

    /// Takes in the current state of the server and a label.
    /// If the label is present in the current state,
    /// this function returns all the values ever associated with it,
    /// and the epoch at which each value was first committed to the server state.
    /// It also returns the proof of the latest version being served at all times.
    pub fn key_history(&self, _uname: Username) -> HistoryProof<H> {
        unimplemented!()
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

    fn username_to_nodelabel(_uname: &Username) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    fn get_nodelabel(_uname: &Username, _stale: bool, _version: u64) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    fn value_to_bytes(_value: &Values) -> [u8; 64] {
        unimplemented!()
    }

    fn get_marker_version(version: u64) -> u64 {
        (64 - version.leading_zeros() - 1).into()
    }
}

// #[cfg(test)]
// mod tests {

//     use crypto::hashers::Blake3_256;

//     use math::fields::f128::BaseElement;

//     type Blake3 = Blake3_256<BaseElement>;

//     // #[test]
//     // fn test_simple_publish() -> Result<(), SeemlessDirectoryError> {
//     //     SeemlessDirectory::<InMemoryDb, Blake3>::publish(vec![(
//     //         Username("hello".to_string()),
//     //         Values("world".to_string()),
//     //     )])?;
//     //     SeemlessDirectory::<InMemoryDb, Blake3>::lookup(Username("hello".to_string()))?;

//     //     Ok(())
//     // }
// }
