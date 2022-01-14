// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module provides management for message nonces (incoming & outgoing)

use super::{NodeId, Nonce};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages the state of incoming & outgoing "nonces" per-node,
/// which are effectively message counts to/from each node
pub(crate) struct NonceManager {
    outgoing: Arc<RwLock<HashMap<NodeId, Nonce>>>,
    incoming: Arc<RwLock<HashMap<NodeId, Nonce>>>,
}

impl NonceManager {
    /// Create a new nonce manager instance
    pub(crate) fn new() -> Self {
        Self {
            outgoing: Arc::new(RwLock::new(HashMap::new())),
            incoming: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Retrieve the "next" nonce for message send, will auto-increment the nonce
    /// mapping
    pub(crate) async fn get_next_outgoing_nonce(&self, to: NodeId) -> Nonce {
        let mut guard = self.incoming.write().await;
        let next = guard.get(&to).map_or(0, |a| *a + 1);
        // safe the updated nonce
        guard.insert(to, next);
        next
    }

    /// Validate the incoming nonce from the specified node
    pub(crate) async fn validate_nonce(
        &self,
        from: NodeId,
        nonce: Nonce,
    ) -> Result<(), crate::comms::CommunicationError> {
        if from == u64::MAX {
            // special case for new-node test's
            return Ok(());
        }

        let expected = self.get_expected_nonce(from).await;

        if nonce == expected {
            self.incoming.write().await.insert(from, expected + 1);
            Ok(())
        } else {
            let err = crate::comms::CommunicationError::NonceError(
                from,
                nonce,
                format!(
                    "Nonce mismatch in raft inter-messages: Node {}, Nonce: {}, Expected Nonce: {}",
                    from, nonce, expected
                ),
            );
            Err(err)
        }
    }

    async fn get_expected_nonce(&self, from: NodeId) -> Nonce {
        self.incoming.read().await.get(&from).map_or(0, |v| *v)
    }
}

unsafe impl Sync for NonceManager {}
unsafe impl Send for NonceManager {}
impl Clone for NonceManager {
    fn clone(&self) -> Self {
        Self {
            outgoing: self.outgoing.clone(),
            incoming: self.incoming.clone(),
        }
    }
}
