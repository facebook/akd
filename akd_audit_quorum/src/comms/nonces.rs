// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module provides management for message nonces (incoming & outgoing).
//!
//! The purpose of managing nonces is to protect against replay attacks in inter-node
//! messages. The [`NonceManager`] manages both _expected_ incoming nonces from nodes
//! and the outgoing nonces for messages being sent to nodes.
//!
//! ## Relevant information
//!
//! The nonce reset problem
//! https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.1061.3009&rep=rep1&type=pdf

use super::{NodeId, Nonce};

use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages the state of incoming & outgoing "nonces" per-node,
/// which are effectively message counts to/from each node
pub struct NonceManager {
    outgoing: Arc<RwLock<HashMap<NodeId, Nonce>>>,
    incoming: Arc<RwLock<HashMap<NodeId, Nonce>>>,
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceManager {
    /// Create a new nonce manager instance
    pub fn new() -> Self {
        Self {
            outgoing: Arc::new(RwLock::new(HashMap::new())),
            incoming: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Reset the nonce for a given peer node to a random value
    /// and return the "next" expected nonce for that peer which will
    /// be communicated to that peer for setting their nonce options
    pub async fn reset(&self, from: NodeId) -> Nonce {
        let mut guard = self.incoming.write().await;

        let mut rng = rand::thread_rng();
        let new_nonce: Nonce = rng.gen();

        // we'll be expecting new_nonce + 1, but we transmit new_nonce as
        // the peer's logic will auto-increment it when generating an
        // outgoing nonce
        guard.insert(from, new_nonce + 1);

        new_nonce
    }

    /// Set the outgoing nonce for a given peer, this is in reply to a remote nonce
    /// reset request
    pub async fn set_outgoing_nonce_for_peer(&self, to: NodeId, starting_nonce: Nonce) {
        let mut guard = self.outgoing.write().await;
        guard.insert(to, starting_nonce);
    }

    /// Retrieve the "next" nonce for an outgoing message. Will auto-increment the nonce
    /// mapping
    ///
    /// Returns: Some(nonce) when a valid next nonce was able to be retrieved, None if
    /// no starting/previous nonce was registered for this peer
    pub async fn get_next_outgoing_nonce(&self, to: NodeId) -> Option<Nonce> {
        let mut guard = self.outgoing.write().await;
        let next = guard.get(&to).map(|a| *a + 1);

        if let Some(v) = &next {
            // save the next expected nonce
            guard.insert(to, *v);
        }
        next
    }

    /// Validate the incoming nonce from the specified node
    pub async fn validate_nonce(
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
                    "Nonce mismatch in raft inter-messages: Node {}, Received nonce: {}",
                    from, nonce
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
