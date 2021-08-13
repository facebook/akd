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
pub enum StorageEnum<H: Hasher, S: Storage<Self>> {
    Node(HistoryTreeNode<H, S>),
    Azks(Azks<H, S>),
}

pub enum IdEnum<'a> {
    NodeLocation(&'a [u8], usize),
    AzksId(&'a [u8]),
}

impl<H: Hasher, S: Storage<Self>> StorageEnum<H, S> {
    pub(crate) fn read_data(data_type: &str, id: IdEnum) -> Result<Self, StorageError> {
        match data_type {
            "history_tree_node" => match id {
                IdEnum::NodeLocation(azks_id, location) => {
                    let k = format_node_key(azks_id, location);
                    let retrieved = S::get(k)?;
                    match retrieved {
                        Self::Node(retrieved_node) => Ok(Self::Node(retrieved_node)),
                        _ => Err(StorageError::WrongMemoryTypeError),
                    }
                }
                _ => Err(StorageError::WrongIdTypeError),
            },
            "azks" => match id {
                IdEnum::AzksId(azks_id) => {
                    let k = format_azks_id_key(azks_id);
                    let retrieved = S::get(k)?;
                    match retrieved {
                        Self::Azks(azks) => Ok(Self::Azks(azks)),
                        _ => Err(StorageError::WrongMemoryTypeError),
                    }
                }
                _ => Err(StorageError::WrongIdTypeError),
            },
            _ => Err(StorageError::UnsupportedStorageTypeError),
        }
    }
    pub(crate) fn write_data(id: IdEnum, data: Self) -> Result<(), StorageError> {
        match data {
            Self::Node(node) => match id {
                IdEnum::NodeLocation(azks_id, location) => {
                    let k = format_node_key(azks_id, location);
                    let _retrieved = S::set(k, Self::Node(node))?;
                    Ok(())
                }
                _ => Err(StorageError::WrongIdTypeError),
            },
            Self::Azks(azks) => match id {
                IdEnum::AzksId(azks_id) => {
                    let k = format_azks_id_key(azks_id);
                    let _retrieved = S::set(k, Self::Azks(azks))?;
                    Ok(())
                }
                _ => Err(StorageError::WrongIdTypeError),
            },
        }
    }

    pub fn to_node(
        acquired_data: Result<Self, StorageError>,
    ) -> Result<HistoryTreeNode<H, S>, StorageError> {
        match acquired_data {
            Ok(Self::Node(node)) => Ok(node),
            Err(e) => Err(e),
            _ => Err(StorageError::WrongMemoryTypeError),
        }
    }

    pub fn to_azks(acquired_data: Result<Self, StorageError>) -> Result<Azks<H, S>, StorageError> {
        match acquired_data {
            Ok(Self::Azks(azks)) => Ok(azks),
            Err(e) => Err(e),
            _ => Err(StorageError::WrongMemoryTypeError),
        }
    }
}

// impl<H: Hasher, S: Storage<StorageEnum<H, S>>> From<StorageEnum<H, S>> for HistoryTreeNode<H, S> {
//     fn from(node: StorageEnum<H, S>) -> Self {
//         StorageEnum::Node(node_val)

//     }
// }

impl<H: Hasher, S: Storage<StorageEnum<H, S>>> Clone for StorageEnum<H, S> {
    fn clone(&self) -> Self {
        match self {
            Self::Node(history_tree_node) => Self::Node(history_tree_node.clone()),
            Self::Azks(azks) => Self::Azks(azks.clone()),
        }
    }
}

pub trait Storage<N> {
    fn set(pos: String, node: N) -> Result<(), StorageError>;
    fn get(pos: String) -> Result<N, StorageError>;
}

// #[allow(unused)]
// pub(crate) fn set_node<H: Hasher, S: Storage<StorageEnum<H, S>>>(
//     azks_id: &[u8],
//     location: usize,
//     val: StorageEnum<H, S>,
// ) -> Result<(), StorageError> {
//     // let k = format!("azks_id: {}, location: {}", hex::encode(azks_id), location);
//     let k = format_node_key(azks_id, location);
//     S::set(k, val)
// }

#[allow(unused)]
pub(crate) fn get_node<H: Hasher, S: Storage<StorageEnum<H, S>>>(
    azks_id: &[u8],
    location: usize,
) -> Result<StorageEnum<H, S>, StorageError> {
    // let k = format!("azks_id: {}, location: {}", hex::encode(azks_id), location);
    let k = format_node_key(azks_id, location);
    S::get(k)
}

pub(crate) fn format_node_key(azks_id: &[u8], location: usize) -> String {
    format!(
        "HistoryTreeNode: azks_id: {}, location: {}",
        hex::encode(azks_id),
        location
    )
}

pub(crate) fn format_azks_id_key(azks_id: &[u8]) -> String {
    format!("AzksId: {}", hex::encode(azks_id))
}

pub(crate) fn set_state_map<H: Hasher, S: Storage<StorageEnum<H, S>>>(
    node: &mut HistoryTreeNode<H, S>,
    key: &u64,
    val: HistoryNodeState<H>,
) -> Result<(), StorageError> {
    node.state_map.insert(*key, val);
    Ok(())
}

pub(crate) fn get_state_map<H: Hasher, S: Storage<StorageEnum<H, S>>>(
    node: &HistoryTreeNode<H, S>,
    key: &u64,
) -> Result<HistoryNodeState<H>, StorageError> {
    let val = node.state_map.get(key);

    match val {
        Some(v) => Ok(v.clone()),
        None => Err(StorageError::GetError),
    }
}
