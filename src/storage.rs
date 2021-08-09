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

#[allow(unused)]
pub(crate) fn set_node<H: Hasher, S: Storage<HistoryTreeNode<H, S>>>(
    azks_id: &[u8],
    location: usize,
    val: HistoryTreeNode<H, S>,
) -> Result<(), StorageError> {
    let k = format!("azks_id: {}, location: {}", hex::encode(azks_id), location);
    S::set(k, val)
}

#[allow(unused)]
pub(crate) fn get_node<H: Hasher, S: Storage<HistoryTreeNode<H, S>>>(
    azks_id: &[u8],
    location: usize,
) -> Result<HistoryTreeNode<H, S>, StorageError> {
    let k = format!("azks_id: {}, location: {}", hex::encode(azks_id), location);
    S::get(k)
}

pub(crate) fn set_state_map<H: Hasher, S: Storage<HistoryTreeNode<H, S>>>(
    node: &mut HistoryTreeNode<H, S>,
    key: &u64,
    val: HistoryNodeState<H>,
) -> Result<(), StorageError> {
    node.state_map.insert(*key, val);
    Ok(())
}

pub(crate) fn get_state_map<H: Hasher, S: Storage<HistoryTreeNode<H, S>>>(
    node: &HistoryTreeNode<H, S>,
    key: &u64,
) -> Result<HistoryNodeState<H>, StorageError> {
    let val = node.state_map.get(key);

    match val {
        Some(v) => Ok(v.clone()),
        None => Err(StorageError::GetError),
    }
}
