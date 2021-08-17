// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::append_only_zks::Azks;
use crate::errors::StorageError;
use crate::history_tree_node::HistoryTreeNode;
use crate::node_state::HistoryNodeState;
use crypto::Hasher;

#[derive(Debug)]
pub enum StorageEnum<H, S> {
    Node(HistoryTreeNode<H, S>),
    Azks(Azks<H, S>),
}

pub enum IdEnum<'a> {
    NodeLocation(&'a [u8], usize),
    AzksId(&'a [u8]),
}

use serde::{de::DeserializeOwned, Serialize};

pub trait Storable<S: Storage>: Serialize + DeserializeOwned {
    type Key: Serialize;

    fn identifier() -> String;

    fn retrieve(key: Self::Key) -> Result<Self, StorageError> {
        let k = format!(
            "{}:{}",
            Self::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        bincode::deserialize(&hex::decode(S::get(k)?).unwrap()).map_err(|_| StorageError::GetError)
    }

    fn store(key: Self::Key, value: &Self) -> Result<(), StorageError> {
        let k = format!(
            "{}:{}",
            Self::identifier(),
            hex::encode(bincode::serialize(&key).unwrap())
        );
        S::set(k, hex::encode(&bincode::serialize(&value).unwrap()))
    }
}

impl<H: Hasher, S: Storage> Clone for StorageEnum<H, S> {
    fn clone(&self) -> Self {
        match self {
            Self::Node(history_tree_node) => Self::Node(history_tree_node.clone()),
            Self::Azks(azks) => Self::Azks(azks.clone()),
        }
    }
}

pub trait Storage {
    fn set(pos: String, val: String) -> Result<(), StorageError>;
    fn get(pos: String) -> Result<String, StorageError>;
}

pub(crate) fn set_state_map<H: Hasher, S: Storage>(
    node: &mut HistoryTreeNode<H, S>,
    key: &u64,
    val: HistoryNodeState<H>,
) -> Result<(), StorageError> {
    node.state_map.insert(*key, val);
    Ok(())
}

pub(crate) fn get_state_map<H: Hasher, S: Storage>(
    node: &HistoryTreeNode<H, S>,
    key: &u64,
) -> Result<HistoryNodeState<H>, StorageError> {
    let val = node.state_map.get(key);

    match val {
        Some(v) => Ok(v.clone()),
        None => Err(StorageError::GetError),
    }
}
