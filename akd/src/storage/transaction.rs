// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! A simple in-memory transaction object to minimize data-layer operations

use crate::errors::StorageError;
use crate::storage::types::DbRecord;
use crate::storage::types::ValueState;
use crate::storage::types::ValueStateRetrievalFlag;
use crate::storage::Storable;

use dashmap::DashMap;
#[cfg(feature = "runtime_metrics")]
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
#[cfg(feature = "runtime_metrics")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Represents an in-memory transaction, keeping a mutable state
/// of the changes. When you "commit" this transaction, you return the
/// collection of values which need to be written to the storage layer
/// including all mutations. Rollback simply empties the transaction state.
#[derive(Clone)]
pub struct Transaction {
    mods: Arc<DashMap<Vec<u8>, DbRecord>>,
    active: Arc<AtomicBool>,

    #[cfg(feature = "runtime_metrics")]
    num_reads: Arc<AtomicU64>,
    #[cfg(feature = "runtime_metrics")]
    num_writes: Arc<AtomicU64>,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a lone transaction")
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    /// Instantiate a new transaction instance
    pub fn new() -> Self {
        Self {
            mods: Arc::new(DashMap::new()),
            active: Arc::new(AtomicBool::new(false)),

            #[cfg(feature = "runtime_metrics")]
            num_reads: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "runtime_metrics")]
            num_writes: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the current number of items currently in the transaction modifications set
    pub fn count(&self) -> usize {
        self.mods.len()
    }

    /// Log metrics about the current transaction instance. Metrics will be cleared after log call
    pub fn log_metrics(&self, _level: log::Level) {
        #[cfg(feature = "runtime_metrics")]
        {
            let r = self.num_reads.swap(0, Ordering::Relaxed);
            let w = self.num_writes.swap(0, Ordering::Relaxed);

            let msg = format!("Transaction writes: {w}, Transaction reads: {r}");

            match _level {
                log::Level::Trace => trace!("{}", msg),
                log::Level::Debug => debug!("{}", msg),
                log::Level::Info => info!("{}", msg),
                log::Level::Warn => warn!("{}", msg),
                _ => error!("{}", msg),
            }
        }
    }

    /// Start a transaction in the storage layer
    pub fn begin_transaction(&self) -> bool {
        !self.active.swap(true, Ordering::Relaxed)
    }

    /// Commit a transaction in the storage layer
    pub fn commit_transaction(&self) -> Result<Vec<DbRecord>, StorageError> {
        if !self.active.load(Ordering::Relaxed) {
            return Err(StorageError::Transaction(
                "Transaction not currently active".to_string(),
            ));
        }

        // copy all the updated values out
        let mut records = self
            .mods
            .iter()
            .map(|p| p.value().clone())
            .collect::<Vec<_>>();

        // sort according to transaction priority
        records.sort_by_key(|r| r.transaction_priority());

        // flush the trans log
        self.mods.clear();

        self.active.store(false, Ordering::Relaxed);
        Ok(records)
    }

    /// Rollback a transaction
    pub fn rollback_transaction(&self) -> Result<(), StorageError> {
        if !self.active.load(Ordering::Relaxed) {
            return Err(StorageError::Transaction(
                "Transaction not currently active".to_string(),
            ));
        }

        // rollback
        self.mods.clear();

        self.active.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Retrieve a flag determining if there is a transaction active
    pub fn is_transaction_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Hit test the current transaction to see if it is currently active
    pub fn get<St: Storable>(&self, key: &St::StorageKey) -> Option<DbRecord> {
        let bin_id = St::get_full_binary_key_id(key);

        let out = self.mods.get(&bin_id).map(|p| p.value().clone());
        #[cfg(feature = "runtime_metrics")]
        if out.is_some() {
            self.num_reads.fetch_add(1, Ordering::Relaxed);
        }
        out
    }

    /// Set a batch of values into the cache
    pub fn batch_set(&self, records: &[DbRecord]) {
        for record in records {
            self.mods
                .insert(record.get_full_binary_id(), record.clone());
        }

        #[cfg(feature = "runtime_metrics")]
        {
            self.num_writes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Set a value in the transaction to be committed at transaction commit time
    pub fn set(&self, record: &DbRecord) {
        let bin_id = record.get_full_binary_id();

        self.mods.insert(bin_id, record.clone());

        #[cfg(feature = "runtime_metrics")]
        {
            self.num_writes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Retrieve all of the user data for a given username
    ///
    /// Note: This is a FULL SCAN operation of the entire transaction log
    pub fn get_users_data(
        &self,
        usernames: &[crate::AkdLabel],
    ) -> HashMap<crate::AkdLabel, Vec<ValueState>> {
        let mut results: HashMap<crate::AkdLabel, Vec<ValueState>> = HashMap::new();

        let mut set = std::collections::HashSet::with_capacity(usernames.len());
        for username in usernames.iter() {
            if !set.contains(username) {
                set.insert(username.clone());
            }
        }

        for pair in self.mods.iter() {
            if let DbRecord::ValueState(value_state) = pair.value() {
                if set.contains(&value_state.username) {
                    if results.contains_key(&value_state.username) {
                        if let Some(item) = results.get_mut(&value_state.username) {
                            item.push(value_state.clone())
                        }
                    } else {
                        results.insert(value_state.username.clone(), vec![value_state.clone()]);
                    }
                }
            }
        }

        // sort all the value lists by epoch
        for (_k, v) in results.iter_mut() {
            v.sort_unstable_by(|a, b| a.epoch.cmp(&b.epoch));
        }

        results
    }

    /// Retrieve the user state given the specified value state retrieval mode
    ///
    /// Note: This is a FULL SCAN operation of the entire transaction log
    #[allow(clippy::let_and_return)]
    pub fn get_user_state(
        &self,
        username: &crate::AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> Option<ValueState> {
        let intermediate = self
            .get_users_data(&[username.clone()])
            .remove(username)
            .unwrap_or_default();
        let out = Self::find_appropriate_item(intermediate, flag);
        #[cfg(feature = "runtime_metrics")]
        if out.is_some() {
            self.num_reads.fetch_add(1, Ordering::Relaxed);
        }
        out
    }

    /// Retrieve the batch of specified users user_state's based on the filtering flag provided
    ///
    /// Note: This is a FULL SCAN operation of the entire transaction log
    pub fn get_users_states(
        &self,
        usernames: &[crate::AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> HashMap<crate::AkdLabel, ValueState> {
        let mut result_map = HashMap::new();
        let intermediate = self.get_users_data(usernames);

        for (key, value_list) in intermediate.into_iter() {
            if let Some(found) = Self::find_appropriate_item(value_list, flag) {
                result_map.insert(key, found);
            }
        }
        #[cfg(feature = "runtime_metrics")]
        {
            self.num_reads.fetch_add(1, Ordering::Relaxed);
        }
        result_map
    }

    /// Find the appropriate item of the cached value states for a given user. This assumes that the incoming vector
    /// is already sorted in ascending epoch order
    fn find_appropriate_item(
        intermediate: Vec<ValueState>,
        flag: ValueStateRetrievalFlag,
    ) -> Option<ValueState> {
        match flag {
            ValueStateRetrievalFlag::SpecificVersion(version) => intermediate
                .into_iter()
                .find(|item| item.version == version),
            ValueStateRetrievalFlag::SpecificEpoch(epoch) => {
                intermediate.into_iter().find(|item| item.epoch == epoch)
            }
            ValueStateRetrievalFlag::LeqEpoch(epoch) => intermediate
                .into_iter()
                .rev()
                .find(|item| item.epoch <= epoch),
            ValueStateRetrievalFlag::MaxEpoch => intermediate.into_iter().last(),
            ValueStateRetrievalFlag::MinEpoch => intermediate.into_iter().next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::append_only_zks::*;
    use crate::node_label::*;
    use crate::storage::types::*;
    use crate::tree_node::*;
    use crate::utils::byte_arr_from_u64;
    use crate::{AkdLabel, AkdValue, AzksValue};
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    #[test]
    fn test_commit_order() -> Result<(), StorageError> {
        let azks = DbRecord::Azks(Azks {
            num_nodes: 0,
            latest_epoch: 0,
        });
        let node1 = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
            label: NodeLabel::new(byte_arr_from_u64(0), 0),
            last_epoch: 1,
            min_descendant_epoch: 1,
            parent: NodeLabel::new(byte_arr_from_u64(0), 0),
            node_type: TreeNodeType::Root,
            left_child: None,
            right_child: None,
            hash: AzksValue(crate::hash::EMPTY_DIGEST),
        }));
        let node2 = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            last_epoch: 1,
            min_descendant_epoch: 1,
            parent: NodeLabel::new(byte_arr_from_u64(0), 0),
            node_type: TreeNodeType::Leaf,
            left_child: None,
            right_child: None,
            hash: AzksValue(crate::hash::EMPTY_DIGEST),
        }));
        let value1 = DbRecord::ValueState(ValueState {
            username: AkdLabel::from("test"),
            epoch: 1,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            version: 1,
            value: AkdValue::from("abc123"),
        });
        let value2 = DbRecord::ValueState(ValueState {
            username: AkdLabel::from("test"),
            epoch: 2,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            version: 2,
            value: AkdValue::from("abc1234"),
        });

        let records = vec![azks, node1, node2, value1, value2];
        let mut rng = StdRng::seed_from_u64(42);

        for _ in 1..10 {
            let txn = Transaction::new();
            txn.begin_transaction();

            // set values in a random order
            let mut shuffled = records.clone();
            shuffled.shuffle(&mut rng);
            for record in shuffled {
                txn.set(&record);
            }

            // ensure that committed records are in ascending priority
            let mut running_priority = 0;
            for record in txn.commit_transaction()? {
                let priority = record.transaction_priority();
                #[allow(clippy::comparison_chain)]
                if priority > running_priority {
                    running_priority = priority;
                } else if priority < running_priority {
                    panic!("Transaction did not obey record priority when committing");
                }
            }
        }

        Ok(())
    }
}
