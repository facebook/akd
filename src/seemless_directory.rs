// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::append_only_zks::{AppendOnlyProof, NonMembershipProof};
use crate::append_only_zks::{Azks, MembershipProof};
use crate::errors::SeemlessDirectoryError;
use crate::history_tree_node::HistoryTreeNode;
use crate::node_state::NodeLabel;
use crate::storage::Storage;
use crypto::Hasher;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Username(String);
#[derive(Clone)]
pub struct Values(String);
pub struct SeemlessDirectory<S: Storage<HistoryTreeNode<H, S>>, H: Hasher> {
    _commitments: Vec<Azks<H, S>>,
    _current_epoch: u64,
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
    _plaintext_value: Values,
    _version: u64,
    _existence_proof: MembershipProof<H>,
    _marker_proof: MembershipProof<H>,
    _freshness_proof: NonMembershipProof<H>,
}

pub struct UpdateProof<H: Hasher> {
    _plaintext_value: Values,
    _version: u64,
    _existence_at_ep: MembershipProof<H>, // membership proof to show that the key was included in this epoch
    _previous_val_stale_at_ep: MembershipProof<H>, // proof that previous value was set to old at this epoch
    _non_existence_before_ep: NonMembershipProof<H>, // proof that this value didn't exist prior to this ep
    _non_existence_of_next_few: Vec<NonMembershipProof<H>>, // proof that the next few values did not exist at this time
    _non_existence_of_future_markers: Vec<NonMembershipProof<H>>, // proof that future markers did not exist
}

pub struct HistoryProof<H: Hasher> {
    _proofs: Vec<UpdateProof<H>>,
}

impl<S: Storage<HistoryTreeNode<H, S>>, H: Hasher> SeemlessDirectory<S, H> {
    // FIXME: this code won't work
    pub fn publish(updates: Vec<(Username, Values)>) -> Result<(), SeemlessDirectoryError> {
        for (_key, _val) in updates {
            S::set(
                "0".to_string(),
                crate::history_tree_node::get_empty_root(&[], None),
            )
            .map_err(|_| SeemlessDirectoryError::StorageError)?;
        }

        Ok(())
    }

    // Provides proof for correctness of latest version
    pub fn lookup(_uname: Username) -> Result<(), SeemlessDirectoryError> {
        // FIXME: restore with: LookupProof<H> {
        // FIXME: this code won't work
        S::get("0".to_string()).unwrap();
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::InMemoryDb;
    use crypto::hashers::Blake3_256;

    use math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;

    #[test]
    fn test_simple_publish() -> Result<(), SeemlessDirectoryError> {
        SeemlessDirectory::<InMemoryDb, Blake3>::publish(vec![(
            Username("hello".to_string()),
            Values("world".to_string()),
        )])?;
        SeemlessDirectory::<InMemoryDb, Blake3>::lookup(Username("hello".to_string()))?;

        Ok(())
    }
}
