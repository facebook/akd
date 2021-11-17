// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Storage module for a auditable key directory

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

/// Represents a transaction in the storage layer
pub struct Transaction {
    state: Arc<tokio::sync::RwLock<TransactionState>>,

    num_reads: Arc<tokio::sync::RwLock<u64>>,
    num_writes: Arc<tokio::sync::RwLock<u64>>,
}

impl Transaction {
    pub(crate) fn new() -> Self {
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

impl Transaction {
    pub(crate) async fn log_metrics(&self, level: log::Level) {
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
    pub(crate) async fn begin_transaction(&mut self) -> bool {
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
    pub(crate) async fn commit_transaction(&mut self) -> Result<Vec<DbRecord>, StorageError> {
        let mut guard = self.state.write().await;

        if !(*guard).active {
            return Err(StorageError::SetError(
                "Transaction not currently active".to_string(),
            ));
        }

        // copy all the updated values out
        let records = guard.mods.values().cloned().collect();
        // flush the trans log
        (*guard).mods.clear();

        (*guard).active = false;
        Ok(records)
    }

    /// Rollback a transaction
    pub(crate) async fn rollback_transaction(&mut self) -> Result<(), StorageError> {
        debug!("BEGIN rollback transaction");
        let mut guard = self.state.write().await;

        if !(*guard).active {
            return Err(StorageError::SetError(
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
    pub(crate) async fn is_transaction_active(&self) -> bool {
        debug!("BEGIN is transaction active");
        let out = self.state.read().await.active;
        debug!("END is transaction active");
        out
    }

    pub(crate) async fn get<St: Storable>(&self, key: &St::Key) -> Option<DbRecord> {
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

    pub(crate) async fn set(&self, record: &DbRecord) {
        debug!("BEGIN transaction set");
        let bin_id = record.get_full_binary_id();

        let mut guard = self.state.write().await;
        (*guard).mods.insert(bin_id, record.clone());

        *(self.num_writes.write().await) += 1;
        debug!("END transaction set");
    }
}
