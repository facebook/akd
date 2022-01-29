// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements record handling for a simple asynchronized mysql database

use std::convert::TryInto;

use akd::history_tree_node::{HistoryTreeNode, NodeKey};
use akd::storage::types::{DbRecord, StorageType};
use akd::storage::Storable;
use akd::ARITY;
use mysql_async::prelude::*;
use mysql_async::*;

type MySqlError = mysql_async::Error;

pub(crate) const TABLE_AZKS: &str = "azks";
pub(crate) const TABLE_HISTORY_TREE_NODES: &str = "history";
pub(crate) const TABLE_HISTORY_NODE_STATES: &str = "states";
pub(crate) const TABLE_USER: &str = "users";
pub(crate) const TEMP_IDS_TABLE: &str = "temp_ids_table";

const SELECT_AZKS_DATA: &str = "`epoch`, `num_nodes`";
const SELECT_HISTORY_TREE_NODE_DATA: &str =
    "`label_len`, `label_val`, `birth_epoch`, `last_epoch`, `parent_label_len`, `parent_label_val`, `node_type`";
const SELECT_HISTORY_NODE_STATE_DATA: &str =
    "`label_len`, `label_val`, `epoch`, `value`, `child_states`";
const SELECT_USER_DATA: &str =
    "`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`";

pub(crate) trait MySqlStorable {
    fn set_statement(&self) -> String;

    fn set_params(&self) -> mysql_async::Params;

    fn set_batch_statement<St: Storable>(items: usize) -> String;

    fn set_batch_params(items: &[DbRecord]) -> mysql_async::Params;

    fn get_statement<St: Storable>() -> String;

    fn get_batch_create_temp_table<St: Storable>() -> Option<String>;

    fn get_batch_fill_temp_table<St: Storable>(num_items: Option<usize>) -> String;

    fn get_batch_statement<St: Storable>() -> String;

    fn get_specific_statement<St: Storable>() -> String;

    fn get_specific_params<St: Storable>(key: &St::Key) -> Option<mysql_async::Params>;

    fn get_multi_row_specific_params<St: Storable>(keys: &[St::Key])
        -> Option<mysql_async::Params>;

    fn from_row<St: Storable>(row: &mut mysql_async::Row) -> core::result::Result<Self, MySqlError>
    where
        Self: std::marker::Sized;
}

impl MySqlStorable for DbRecord {
    fn set_statement(&self) -> String {
        match &self {
            DbRecord::Azks(_) => format!("INSERT INTO `{}` (`key`, {}) VALUES (:key, :epoch, :num_nodes) ON DUPLICATE KEY UPDATE `epoch` = :epoch, `num_nodes` = :num_nodes", TABLE_AZKS, SELECT_AZKS_DATA),
            DbRecord::HistoryNodeState(_) => format!("INSERT INTO `{}` ({}) VALUES (:label_len, :label_val, :epoch, :value, :child_states) ON DUPLICATE KEY UPDATE `value` = :value, `child_states` = :child_states", TABLE_HISTORY_NODE_STATES, SELECT_HISTORY_NODE_STATE_DATA),
            DbRecord::HistoryTreeNode(_) => format!("INSERT INTO `{}` ({}) VALUES (:label_len, :label_val, :birth_epoch, :last_epoch, :parent_label_len, :parent_label_val, :node_type) ON DUPLICATE KEY UPDATE `label_len` = :label_len, `label_val` = :label_val, `birth_epoch` = :birth_epoch, `last_epoch` = :last_epoch, `parent_label_len` = :parent_label_len, `parent_label_val` = :parent_label_val, `node_type` = :node_type", TABLE_HISTORY_TREE_NODES, SELECT_HISTORY_TREE_NODE_DATA),
            DbRecord::ValueState(_) => format!("INSERT INTO `{}` ({}) VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)", TABLE_USER, SELECT_USER_DATA),
        }
    }

    fn set_params(&self) -> mysql_async::Params {
        match &self {
            DbRecord::Azks(azks) => {
                params! { "key" => 1u8, "epoch" => azks.latest_epoch, "num_nodes" => azks.num_nodes }
            }
            DbRecord::HistoryNodeState(state) => {
                let bin_data = bincode::serialize(&state.child_states).unwrap();
                let id = state.get_id();
                params! { "label_len" => id.0.len, "label_val" => id.0.val, "epoch" => id.1, "value" => state.value.clone(), "child_states" => bin_data }
            }
            DbRecord::HistoryTreeNode(node) => {
                params! { "label_len" => node.label.len, "label_val" => node.label.val, "birth_epoch" => node.birth_epoch, "last_epoch" => node.last_epoch, "parent_label_len" => node.parent.len, "parent_label_val" => node.parent.val, "node_type" => node.node_type as u8 }
            }
            DbRecord::ValueState(state) => {
                params! { "username" => state.get_id().0, "epoch" => state.epoch, "version" => state.version, "node_label_len" => state.label.len, "node_label_val" => state.label.val, "data" => state.plaintext_val.0.clone() }
            }
        }
    }

    fn set_batch_statement<St: Storable>(items: usize) -> String {
        let mut parts = "".to_string();
        for i in 0..items {
            match St::data_type() {
                StorageType::HistoryNodeState => {
                    parts = format!(
                        "{}(:label_len{}, :label_val{}, :epoch{}, :value{}, :child_states{})",
                        parts, i, i, i, i, i
                    );
                }
                StorageType::HistoryTreeNode => {
                    parts = format!(
                        "{}(:label_len{}, :label_val{}, :birth_epoch{}, :last_epoch{}, :parent_label_len{}, :parent_label_val{}, :node_type{})",
                        parts, i, i, i, i, i, i, i
                    );
                }
                StorageType::ValueState => {
                    parts = format!(
                        "{}(:username{}, :epoch{}, :version{}, :node_label_val{}, :node_label_len{}, :data{})",
                        parts, i, i, i, i, i, i
                    );
                }
                _ => {
                    // azks
                }
            }

            if i < items - 1 {
                parts += ", ";
            }
        }

        match St::data_type() {
            StorageType::Azks => format!("INSERT INTO `{}` (`key`, {}) VALUES (:key, :epoch, :num_nodes) as new ON DUPLICATE KEY UPDATE `epoch` = new.epoch, `num_nodes` = new.num_nodes", TABLE_AZKS, SELECT_AZKS_DATA),
            StorageType::HistoryNodeState => format!("INSERT INTO `{}` ({}) VALUES {} as new ON DUPLICATE KEY UPDATE `value` = new.value, `child_states` = new.child_states", TABLE_HISTORY_NODE_STATES, SELECT_HISTORY_NODE_STATE_DATA, parts),
            StorageType::HistoryTreeNode => format!("INSERT INTO `{}` ({}) VALUES {} as new ON DUPLICATE KEY UPDATE `label_len` = new.label_len, `label_val` = new.label_val, `birth_epoch` = new.birth_epoch, `last_epoch` = new.last_epoch, `parent_label_len` = new.parent_label_len, `parent_label_val` = new.parent_label_val, `node_type` = new.node_type", TABLE_HISTORY_TREE_NODES, SELECT_HISTORY_TREE_NODE_DATA, parts),
            StorageType::ValueState => format!("INSERT INTO `{}` ({}) VALUES {}", TABLE_USER, SELECT_USER_DATA, parts),
        }
    }

    fn set_batch_params(items: &[DbRecord]) -> mysql_async::Params {
        let param_batch = items
            .iter()
            .enumerate()
            .map(|(idx, item)| match &item {
                DbRecord::Azks(azks) => {
                    vec![
                        ("key".to_string(), Value::from(1u8)),
                        ("epoch".to_string(), Value::from(azks.latest_epoch)),
                        ("num_nodes".to_string(), Value::from(azks.num_nodes)),
                    ]
                }
                DbRecord::HistoryNodeState(state) => {
                    let bin_data = bincode::serialize(&state.child_states).unwrap();
                    let id = state.get_id();
                    vec![
                        (format!("label_len{}", idx), Value::from(id.0.len)),
                        (format!("label_val{}", idx), Value::from(id.0.val)),
                        (format!("epoch{}", idx), Value::from(id.1)),
                        (format!("value{}", idx), Value::from(state.value.clone())),
                        (format!("child_states{}", idx), Value::from(bin_data)),
                    ]
                }
                DbRecord::HistoryTreeNode(node) => {
                    vec![
                        (format!("label_len{}", idx), Value::from(node.label.len)),
                        (format!("label_val{}", idx), Value::from(node.label.val)),
                        (format!("birth_epoch{}", idx), Value::from(node.birth_epoch)),
                        (format!("last_epoch{}", idx), Value::from(node.last_epoch)),
                        (
                            format!("parent_label_len{}", idx),
                            Value::from(node.parent.len),
                        ),
                        (
                            format!("parent_label_val{}", idx),
                            Value::from(node.parent.val),
                        ),
                        (
                            format!("node_type{}", idx),
                            Value::from(node.node_type as u8),
                        ),
                    ]
                }
                DbRecord::ValueState(state) => {
                    vec![
                        (format!("username{}", idx), Value::from(state.get_id().0)),
                        (format!("epoch{}", idx), Value::from(state.epoch)),
                        (format!("version{}", idx), Value::from(state.version)),
                        (
                            format!("node_label_len{}", idx),
                            Value::from(state.label.len),
                        ),
                        (
                            format!("node_label_val{}", idx),
                            Value::from(state.label.val),
                        ),
                        (
                            format!("data{}", idx),
                            Value::from(state.plaintext_val.0.clone()),
                        ),
                    ]
                }
            })
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        mysql_async::Params::from(param_batch)
    }

    fn get_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => format!("SELECT {} FROM `{}`", SELECT_AZKS_DATA, TABLE_AZKS),
            StorageType::HistoryNodeState => format!(
                "SELECT {} FROM `{}`",
                SELECT_HISTORY_NODE_STATE_DATA, TABLE_HISTORY_NODE_STATES
            ),
            StorageType::HistoryTreeNode => format!(
                "SELECT {} FROM `{}`",
                SELECT_HISTORY_TREE_NODE_DATA, TABLE_HISTORY_TREE_NODES
            ),
            StorageType::ValueState => format!("SELECT {} FROM `{}`", SELECT_USER_DATA, TABLE_USER),
        }
    }

    fn get_batch_create_temp_table<St: Storable>() -> Option<String> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::HistoryNodeState => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{}`(`label_len` INT UNSIGNED NOT NULL, `label_val` BIGINT UNSIGNED NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, PRIMARY KEY(`label_len`, `label_val`, `epoch`))",
                        TEMP_IDS_TABLE
                    )
                )
            },
            StorageType::HistoryTreeNode => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{}`(`label_len` INT UNSIGNED NOT NULL, `label_val` BIGINT UNSIGNED NOT NULL, PRIMARY KEY(`label_len`, `label_val`))",
                        TEMP_IDS_TABLE
                    )
                )
            },
            StorageType::ValueState => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{}`(`username` VARCHAR(256) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, PRIMARY KEY(`username`, `epoch`))",
                        TEMP_IDS_TABLE
                    )
                )
            },
        }
    }

    fn get_batch_fill_temp_table<St: Storable>(num_items: Option<usize>) -> String {
        let mut statement = match St::data_type() {
            StorageType::Azks => "".to_string(),
            StorageType::HistoryNodeState => {
                format!(
                    "INSERT INTO `{}` (`label_len`, `label_val`, `epoch`) VALUES ",
                    TEMP_IDS_TABLE
                )
            }
            StorageType::HistoryTreeNode => {
                format!(
                    "INSERT INTO `{}` (`label_len`, `label_val`) VALUES ",
                    TEMP_IDS_TABLE
                )
            }
            StorageType::ValueState => {
                format!(
                    "INSERT INTO `{}` (`username`, `epoch`) VALUES ",
                    TEMP_IDS_TABLE
                )
            }
        };
        if let Some(item_count) = num_items {
            for i in 0..item_count {
                let append = match St::data_type() {
                    StorageType::Azks => String::from(""),
                    StorageType::HistoryNodeState => {
                        format!("(:label_len{}, :label_val{}, :epoch{})", i, i, i)
                    }
                    StorageType::HistoryTreeNode => {
                        format!("(:label_len{}, :label_val{})", i, i)
                    }
                    StorageType::ValueState => {
                        format!("(:username{}, :epoch{})", i, i)
                    }
                };
                statement = format!("{}{}", statement, append);

                if i < item_count - 1 {
                    // inner-item, append a comma
                    statement += ", ";
                }
            }
        } else {
            statement += match St::data_type() {
                StorageType::Azks => "",
                StorageType::HistoryNodeState => "(:label_len, :label_val, :epoch)",
                StorageType::HistoryTreeNode => "(:label_len, :label_val)",
                StorageType::ValueState => "(:username, :epoch)",
            };
        }
        statement
    }

    fn get_batch_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => {
                format!("SELECT {} FROM `{}` LIMIT 1", SELECT_AZKS_DATA, TABLE_AZKS)
            }
            StorageType::HistoryNodeState => {
                format!(
                    "SELECT a.`label_len`, a.`label_val`, a.`epoch`, a.`value`, a.`child_states` FROM `{}` a INNER JOIN {} ids ON ids.`label_len` = a.`label_len` AND ids.`label_val` = a.`label_val` AND ids.`epoch` = a.`epoch`",
                    TABLE_HISTORY_NODE_STATES,
                    TEMP_IDS_TABLE
                )
            }
            StorageType::HistoryTreeNode => {
                format!(
                    "SELECT a.`label_len`, a.`label_val`, a.`birth_epoch`, a.`last_epoch`, a.`parent_label_len`, a.`parent_label_val`, a.`node_type` FROM `{}` a INNER JOIN {} ids ON ids.`label_len` = a.`label_len` AND ids.`label_val` = a.`label_val`",
                    TABLE_HISTORY_TREE_NODES,
                    TEMP_IDS_TABLE
                )
            }
            StorageType::ValueState => {
                format!(
                    "SELECT a.`username`, a.`epoch`, a.`version`, a.`node_label_val`, a.`node_label_len`, a.`data` FROM `{}` a INNER JOIN {} ids ON ids.`username` = a.`username` AND ids.`epoch` = a.`epoch`",
                    TABLE_USER,
                    TEMP_IDS_TABLE
                )
            }
        }
    }

    fn get_specific_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => format!("SELECT {} FROM `{}` LIMIT 1", SELECT_AZKS_DATA, TABLE_AZKS),
            StorageType::HistoryNodeState => format!("SELECT {} FROM `{}` WHERE `label_len` = :label_len AND `label_val` = :label_val AND `epoch` = :epoch", SELECT_HISTORY_NODE_STATE_DATA, TABLE_HISTORY_NODE_STATES),
            StorageType::HistoryTreeNode => format!("SELECT {} FROM `{}` WHERE `label_len` = :label_len AND `label_val` = :label_val", SELECT_HISTORY_TREE_NODE_DATA, TABLE_HISTORY_TREE_NODES),
            StorageType::ValueState => format!("SELECT {} FROM `{}` WHERE `username` = :username AND `epoch` = :epoch", SELECT_USER_DATA, TABLE_USER),
        }
    }

    fn get_multi_row_specific_params<St: Storable>(
        keys: &[St::Key],
    ) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::HistoryNodeState => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        let back: akd::node_state::NodeStateKey =
                            akd::node_state::HistoryNodeState::key_from_full_binary(&bin).unwrap();
                        vec![
                            (format!("label_len{}", idx), Value::from(back.0.len)),
                            (format!("label_val{}", idx), Value::from(back.0.val)),
                            (format!("epoch{}", idx), Value::from(back.1)),
                        ]
                    })
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                Some(mysql_async::Params::from(pvec))
            }
            StorageType::HistoryTreeNode => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        let back: NodeKey = HistoryTreeNode::key_from_full_binary(&bin).unwrap();
                        vec![
                            (format!("label_len{}", idx), Value::from(back.0.len)),
                            (format!("label_val{}", idx), Value::from(back.0.val)),
                        ]
                    })
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                Some(mysql_async::Params::from(pvec))
            }
            StorageType::ValueState => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        let back: akd::storage::types::ValueStateKey =
                            akd::storage::types::ValueState::key_from_full_binary(&bin).unwrap();
                        vec![
                            (format!("username{}", idx), Value::from(back.0.clone())),
                            (format!("epoch{}", idx), Value::from(back.1)),
                        ]
                    })
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                Some(mysql_async::Params::from(pvec))
            }
        }
    }

    fn get_specific_params<St: Storable>(key: &St::Key) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::HistoryNodeState => {
                let bin = St::get_full_binary_key_id(key);
                let back: akd::node_state::NodeStateKey =
                    akd::node_state::HistoryNodeState::key_from_full_binary(&bin).unwrap();
                Some(params! {
                    "label_len" => back.0.len,
                    "label_val" => back.0.val,
                    "epoch" => back.1
                })
            }
            StorageType::HistoryTreeNode => {
                let bin = St::get_full_binary_key_id(key);
                let back: NodeKey = HistoryTreeNode::key_from_full_binary(&bin).unwrap();
                Some(params! {
                    "label_len" => back.0.len,
                    "label_val" => back.0.val,
                })
            }
            StorageType::ValueState => {
                let bin = St::get_full_binary_key_id(key);
                let back: akd::storage::types::ValueStateKey =
                    akd::storage::types::ValueState::key_from_full_binary(&bin).unwrap();
                Some(params! {
                    "username" => back.0,
                    "epoch" => back.1
                })
            }
        }
    }

    fn from_row<St: Storable>(row: &mut mysql_async::Row) -> core::result::Result<Self, MySqlError>
    where
        Self: std::marker::Sized,
    {
        fn cast_err() -> MySqlError {
            MySqlError::from("Failed to cast label:val into [u8; 32]".to_string())
        }

        match St::data_type() {
            StorageType::Azks => {
                // epoch, num_nodes
                if let (Some(Ok(epoch)), Some(Ok(num_nodes))) = (row.take_opt(0), row.take_opt(1)) {
                    let azks = DbRecord::build_azks(epoch, num_nodes);
                    return Ok(DbRecord::Azks(azks));
                }
            }
            StorageType::HistoryNodeState => {
                // label_len, label_val, epoch, value, child_states
                if let (
                    Some(Ok(label_len)),
                    Some(Ok(label_val)),
                    Some(Ok(epoch)),
                    Some(Ok(value)),
                    Some(Ok(child_states)),
                ) = (
                    row.take_opt(0),
                    row.take_opt(1),
                    row.take_opt(2),
                    row.take_opt(3),
                    row.take_opt(4),
                ) {
                    let label_val_vec: Vec<u8> = label_val;
                    let child_states_bin_vec: Vec<u8> = child_states;
                    let child_states_decoded: [Option<akd::node_state::HistoryChildState>; ARITY] =
                        bincode::deserialize(&child_states_bin_vec).unwrap();
                    let node_state = DbRecord::build_history_node_state(
                        value,
                        child_states_decoded,
                        label_len,
                        label_val_vec.try_into().map_err(|_| cast_err())?,
                        epoch,
                    );
                    return Ok(DbRecord::HistoryNodeState(node_state));
                }
            }
            StorageType::HistoryTreeNode => {
                // `label_len`, `label_val`, `birth_epoch`, `last_epoch`, `parent_label_len`, `parent_label_val`, `node_type`
                if let (
                    Some(Ok(label_len)),
                    Some(Ok(label_val)),
                    Some(Ok(birth_epoch)),
                    Some(Ok(last_epoch)),
                    Some(Ok(parent_label_len)),
                    Some(Ok(parent_label_val)),
                    Some(Ok(node_type)),
                ) = (
                    row.take_opt(0),
                    row.take_opt(1),
                    row.take_opt(2),
                    row.take_opt(3),
                    row.take_opt(4),
                    row.take_opt(5),
                    row.take_opt(6),
                ) {
                    let label_val_vec: Vec<u8> = label_val;
                    let parent_label_val_vec: Vec<u8> = parent_label_val;

                    let node = DbRecord::build_history_tree_node(
                        label_val_vec.try_into().map_err(|_| cast_err())?,
                        label_len,
                        birth_epoch,
                        last_epoch,
                        parent_label_val_vec.try_into().map_err(|_| cast_err())?,
                        parent_label_len,
                        node_type,
                    );
                    return Ok(DbRecord::HistoryTreeNode(node));
                }
            }
            StorageType::ValueState => {
                // `username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`
                if let (
                    Some(Ok(username)),
                    Some(Ok(epoch)),
                    Some(Ok(version)),
                    Some(Ok(node_label_val)),
                    Some(Ok(node_label_len)),
                    Some(Ok(data)),
                ) = (
                    row.take_opt(0),
                    row.take_opt(1),
                    row.take_opt(2),
                    row.take_opt(3),
                    row.take_opt(4),
                    row.take_opt(5),
                ) {
                    let node_label_val_vec: Vec<u8> = node_label_val;
                    let state = DbRecord::build_user_state(
                        username,
                        data,
                        version,
                        node_label_len,
                        node_label_val_vec.try_into().map_err(|_| cast_err())?,
                        epoch,
                    );
                    return Ok(DbRecord::ValueState(state));
                }
            }
        }
        // fallback
        let err = MySqlError::Driver(mysql_async::DriverError::FromRow { row: row.clone() });
        Err(err)
    }
}
