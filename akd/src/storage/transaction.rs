// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A simple in-memory transaction object to minize data-layer operations

use crate::errors::StorageError;
use crate::storage::types::DbRecord;
use crate::storage::Storable;

use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;

struct TransactionState {
    mods: HashMap<Vec<u8>, DbRecord>,
    active: bool,
}

/// Represents an in-memory transaction, keeping a mutable state
/// of the changes. When you "commit" this transaction, you return the
/// collection of values which need to be written to the storage layer
/// including all mutations. Rollback simply empties the transaction state.
pub struct Transaction {
    state: Arc<tokio::sync::RwLock<TransactionState>>,

    num_reads: Arc<tokio::sync::RwLock<u64>>,
    num_writes: Arc<tokio::sync::RwLock<u64>>,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a lone transaction")
    }
}

impl Transaction {
    /// Instantiate a new transaction instance
    pub fn new() -> Self {
        Self {
            state: Arc::new(tokio::sync::RwLock::new(TransactionState {
                mods: HashMap::new(),
                active: false,
            })),

            num_reads: Arc::new(tokio::sync::RwLock::new(0)),
            num_writes: Arc::new(tokio::sync::RwLock::new(0)),
        }
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    /// Log metrics about the current transaction instance. Metrics will be cleared after log call
    pub async fn log_metrics(&self, level: log::Level) {
        let mut r = self.num_reads.write().await;
        let mut w = self.num_writes.write().await;

        let msg = format!("Transaction writes: {}, Transaction reads: {}", *w, *r);

        *r = 0;
        *w = 0;

        match level {
            log::Level::Trace => trace!("{}", msg),
            log::Level::Debug => debug!("{}", msg),
            log::Level::Info => info!("{}", msg),
            log::Level::Warn => warn!("{}", msg),
            _ => error!("{}", msg),
        }
    }

    /// Start a transaction in the storage layer
    pub async fn begin_transaction(&self) -> bool {
        debug!("BEGIN begin transaction");
        let mut guard = self.state.write().await;
        let out = if (*guard).active {
            false
        } else {
            (*guard).active = true;
            true
        };
        debug!("END begin transaction");
        out
    }

    /// Commit a transaction in the storage layer
    pub async fn commit_transaction(&self) -> Result<Vec<DbRecord>, StorageError> {
        debug!("BEGIN commit transaction");
        let mut guard = self.state.write().await;

        if !(*guard).active {
            return Err(StorageError::Transaction(
                "Transaction not currently active".to_string(),
            ));
        }

        // copy all the updated values out
        let mut records = guard.mods.values().cloned().collect::<Vec<_>>();

        // sort according to transaction priority
        records.sort_by_key(|r| r.transaction_priority());

        // flush the trans log
        (*guard).mods.clear();

        (*guard).active = false;
        debug!("END commit transaction");
        Ok(records)
    }

    /// Rollback a transaction
    pub async fn rollback_transaction(&self) -> Result<(), StorageError> {
        debug!("BEGIN rollback transaction");
        let mut guard = self.state.write().await;

        if !(*guard).active {
            return Err(StorageError::Transaction(
                "Transaction not currently active".to_string(),
            ));
        }

        // rollback
        (*guard).mods.clear();
        (*guard).active = false;

        debug!("END rollback transaction");
        Ok(())
    }

    /// Retrieve a flag determining if there is a transaction active
    pub async fn is_transaction_active(&self) -> bool {
        debug!("BEGIN is transaction active");
        let out = self.state.read().await.active;
        debug!("END is transaction active");
        out
    }

    /// Hit test the current transaction to see if it is currently active
    pub async fn get<St: Storable>(&self, key: &St::Key) -> Option<DbRecord> {
        debug!("BEGIN transaction get {:?}", key);
        let bin_id = St::get_full_binary_key_id(key);

        let guard = self.state.read().await;
        let out = (*guard).mods.get(&bin_id).cloned();
        if out.is_some() {
            *(self.num_reads.write().await) += 1;
        }
        debug!("END transaction get");
        out
    }

    /// Set a value in the transaction to be committed at transaction commit time
    pub async fn set(&self, record: &DbRecord) {
        debug!("BEGIN transaction set");
        let bin_id = record.get_full_binary_id();

        let mut guard = self.state.write().await;
        (*guard).mods.insert(bin_id, record.clone());

        *(self.num_writes.write().await) += 1;
        debug!("END transaction set");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::append_only_zks::*;
    use crate::node_state::*;
    use crate::storage::types::*;
    use crate::tree_node::*;
    use rand::{rngs::OsRng, seq::SliceRandom};

    #[tokio::test]
    async fn test_commit_order() -> Result<(), StorageError> {
        let azks = DbRecord::Azks(Azks {
            num_nodes: 0,
            latest_epoch: 0,
        });
        let node1 = DbRecord::TreeNode(TreeNode {
            label: NodeLabel::new(byte_arr_from_u64(0), 0),
            last_epoch: 1,
            least_descendent_ep: 1,
            parent: NodeLabel::new(byte_arr_from_u64(0), 0),
            node_type: NodeType::Root,
            left_child: None,
            right_child: None,
            hash: [0u8; 32],
        });
        let node2 = DbRecord::TreeNode(TreeNode {
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            last_epoch: 1,
            least_descendent_ep: 1,
            parent: NodeLabel::new(byte_arr_from_u64(0), 0),
            node_type: NodeType::Leaf,
            left_child: None,
            right_child: None,
            hash: [0u8; 32],
        });
        let value1 = DbRecord::ValueState(ValueState {
            username: AkdLabel::from_utf8_str("test"),
            epoch: 1,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            version: 1,
            plaintext_val: AkdValue::from_utf8_str("abc123"),
        });
        let value2 = DbRecord::ValueState(ValueState {
            username: AkdLabel::from_utf8_str("test"),
            epoch: 2,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            version: 2,
            plaintext_val: AkdValue::from_utf8_str("abc1234"),
        });

        let records = vec![azks, node1, node2, value1, value2];
        let mut rng = OsRng;

        for _ in 1..10 {
            let txn = Transaction::new();
            txn.begin_transaction().await;

            // set values in a random order
            let mut shuffled = records.clone();
            shuffled.shuffle(&mut rng);
            for record in shuffled {
                txn.set(&record).await;
            }

            // ensure that committed records are in ascending priority
            let mut running_priority = 0;
            for record in txn.commit_transaction().await? {
                let priority = record.transaction_priority();
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
