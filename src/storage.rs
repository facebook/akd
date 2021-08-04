// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::StorageError;
use crate::history_tree_node::HistoryTreeNode;
use crate::node_state::HistoryNodeState;
use crypto::Hasher;

pub trait Storage<N> {
    fn set(pos: String, node: N) -> Result<(), StorageError>;
    fn get(pos: String) -> Result<N, StorageError>;
}

pub(crate) fn set_state_map<H: Hasher, S: Storage<HistoryNodeState<H>>>(
    node: &mut HistoryTreeNode<H, S>,
    key: &u64,
    val: HistoryNodeState<H>,
) -> Result<(), StorageError> {
    #[cfg(test)]
    {
        node.state_map.insert(*key, val.clone());
        Ok(())
    }

    #[cfg(not(test))]
    {
        let k = format!(
            "azks_id: {}, location: {}, key: {}",
            hex::encode(&node.azks_id),
            node.location,
            key
        );
        S::set(k, val)
    }
}

pub(crate) fn get_state_map<H: Hasher, S: Storage<HistoryNodeState<H>>>(
    node: &HistoryTreeNode<H, S>,
    key: &u64,
) -> Result<HistoryNodeState<H>, StorageError> {
    #[cfg(test)]
    {
        let val = node.state_map.get(key);

        match val {
            Some(v) => Ok(v.clone()),
            None => Err(StorageError::GetError),
        }
    }

    #[cfg(not(test))]
    {
        let k = format!(
            "azks_id: {}, location: {}, key: {}",
            hex::encode(&node.azks_id),
            node.location,
            key
        );
        S::get(k)
    }
}
