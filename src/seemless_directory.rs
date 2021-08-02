// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::append_only_zks::{self, Azks, MembershipProof};
use crate::append_only_zks::{AppendOnlyProof, NonMembershipProof};
use crate::errors::SeemlessDirectoryError;
use crate::node_state::{HistoryNodeState, NodeLabel};
use crate::storage::Storage;
use crypto::Hasher;
use std::collections::HashMap;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Username(String);
#[derive(Clone)]
pub struct Values(String);
pub struct SeemlessDirectory<S: Storage<HistoryNodeState<H>>, H: Hasher> {
    commitments: Vec<Azks<H, S>>,
    current_epoch: u64,
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}

#[derive(Clone)]
pub struct UserState {
    plaintext_val: Values, // This needs to be the plaintext value, to discuss
    version: u64,          // to discuss
    label: NodeLabel,
    stale_label: NodeLabel,
}

#[derive(Clone)]
pub struct User {
    username: Username, // to decide
    states: Vec<UserState>,
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

impl<S: Storage<HistoryNodeState<H>>, H: Hasher> SeemlessDirectory<S, H> {
    // FIXME: this code won't work
    pub fn publish(updates: Vec<(Username, Values)>) -> Result<(), SeemlessDirectoryError> {
        for (key, val) in updates {
            S::set("0".to_string(), HistoryNodeState::new())
                .map_err(|_| SeemlessDirectoryError::StorageError)?;
        }

        Ok(())
    }

    // Provides proof for correctness of latest version
    pub fn lookup(uname: Username) -> Result<(), SeemlessDirectoryError> {
        // FIXME: restore with: LookupProof<H> {
        // FIXME: this code won't work
        S::get("0".to_string()).unwrap();
        Ok(())
    }

    pub fn lookup_verify(
        uname: Username,
        proof: LookupProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }

    /// Takes in the current state of the server and a label.
    /// If the label is present in the current state,
    /// this function returns all the values ever associated with it,
    /// and the epoch at which each value was first committed to the server state.
    /// It also returns the proof of the latest version being served at all times.
    pub fn key_history(&self, uname: Username) -> HistoryProof<H> {
        unimplemented!()
    }

    pub fn key_history_verify(
        &self,
        uname: Username,
        proof: HistoryProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }

    pub fn audit(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
    ) -> Result<Vec<AppendOnlyProof<H>>, SeemlessDirectoryError> {
        unimplemented!()
    }

    pub fn audit_verify(
        &self,
        audit_start_ep: u64,
        audit_end_ep: u64,
        proof: HistoryProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::errors::StorageError;
    use crate::tests::InMemoryDb;
    use crypto::hashers::Blake3_256;
    use lazy_static::lazy_static;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type Blake3Digest = <Blake3_256<math::fields::f128::BaseElement> as Hasher>::Digest;

    #[test]
    fn test_simple_publish() -> Result<(), SeemlessDirectoryError> {
        SeemlessDirectory::<InMemoryDb, Blake3>::publish(vec![(
            Username("hello".to_string()),
            Values("world".to_string()),
        )])?;
        SeemlessDirectory::<InMemoryDb, Blake3>::lookup(Username("hello".to_string()));
        Ok(())
    }
}
