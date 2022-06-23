// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements record handling for a simple asynchronized mysql database

use std::convert::TryInto;

use akd::storage::types::{DbRecord, StorageType};
use akd::storage::Storable;
use akd::tree_node::{NodeKey, TreeNode};
use akd::NodeLabel;
use mysql_async::prelude::*;
use mysql_async::*;

type MySqlError = mysql_async::Error;

pub(crate) const TABLE_AZKS: &str = "azks";
pub(crate) const TABLE_HISTORY_TREE_NODES: &str = "history";
pub(crate) const TABLE_USER: &str = "users";
pub(crate) const TEMP_IDS_TABLE: &str = "temp_ids_table";

const SELECT_AZKS_DATA: &str = "`epoch`, `num_nodes`";
const SELECT_HISTORY_TREE_NODE_DATA: &str =
    "`label_len`, `label_val`, `last_epoch`, `least_descendent_ep`, `parent_label_len`, `parent_label_val`, `node_type`, `left_child_len`, `left_child_label_val`, `right_child_len`, `right_child_label_val`, `hash`";
const SELECT_USER_DATA: &str =
    "`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`";

pub(crate) trait MySqlStorable {
    fn set_statement(&self) -> String;

    fn set_params(&self) -> Option<mysql_async::Params>;

    fn set_batch_statement<St: Storable>(items: usize) -> String;

    fn set_batch_params(items: &[DbRecord]) -> Result<mysql_async::Params>;

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
            DbRecord::TreeNode(_) => format!("INSERT INTO `{}` ({}) VALUES (:label_len, :label_val, :last_epoch, :least_descendent_ep, :parent_label_len, :parent_label_val, :node_type, :left_child_len, :left_child_label_val, :right_child_len, :right_child_label_val, :hash) ON DUPLICATE KEY UPDATE `label_len` = :label_len, `label_val` = :label_val, `last_epoch` = :last_epoch, `least_descendent_ep` = :least_descendent_ep, `parent_label_len` = :parent_label_len, `parent_label_val` = :parent_label_val, `node_type` = :node_type, `left_child_len` = :left_child_len, `left_child_label_val` = :left_child_label_val, `right_child_len` = :right_child_len, `right_child_label_val` = :right_child_label_val, `hash` = :hash", TABLE_HISTORY_TREE_NODES, SELECT_HISTORY_TREE_NODE_DATA),
            DbRecord::ValueState(_) => format!("INSERT INTO `{}` ({}) VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)", TABLE_USER, SELECT_USER_DATA),
        }
    }

    fn set_params(&self) -> Option<mysql_async::Params> {
        match &self {
            DbRecord::Azks(azks) => Some(
                params! { "key" => 1u8, "epoch" => azks.latest_epoch, "num_nodes" => azks.num_nodes },
            ),
            DbRecord::TreeNode(node) => Some(params! {
                "label_len" => node.label.len,
                "label_val" => node.label.val,
                "last_epoch" => node.last_epoch,
                "least_descendent_ep" => node.least_descendent_ep,
                "parent_label_len" => node.parent.len,
                "parent_label_val" => node.parent.val,
                "node_type" => node.node_type as u8,
                "left_child_len" => node.left_child.map(|lc| lc.len),
                "left_child_label_val" => node.left_child.map(|lc| lc.val),
                "right_child_len" => node.right_child.map(|rc| rc.len),
                "right_child_label_val" => node.right_child.map(|rc| rc.val),
                "hash" => node.hash,
            }),
            DbRecord::ValueState(state) => Some(
                params! { "username" => state.get_id().0, "epoch" => state.epoch, "version" => state.version, "node_label_len" => state.label.len, "node_label_val" => state.label.val, "data" => state.plaintext_val.0.clone() },
            ),
        }
    }

    fn set_batch_statement<St: Storable>(items: usize) -> String {
        let mut parts = "".to_string();
        for i in 0..items {
            match St::data_type() {
                StorageType::TreeNode => {
                    parts = format!(
                        "{}(:label_len{}, :label_val{}, :last_epoch{}, :least_descendent_ep{}, :parent_label_len{}, :parent_label_val{}, :node_type{}, :left_child_len{}, :left_child_label_val{}, :right_child_len{}, :right_child_label_val{}, :hash{})",
                        parts, i, i, i, i, i, i, i, i, i, i, i, i
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
            StorageType::TreeNode => format!("INSERT INTO `{}` ({}) VALUES {} as new ON DUPLICATE KEY UPDATE `label_len` = new.label_len, `label_val` = new.label_val, `least_descendent_ep` = new.least_descendent_ep, `last_epoch` = new.last_epoch, `parent_label_len` = new.parent_label_len, `parent_label_val` = new.parent_label_val, `node_type` = new.node_type, `left_child_len` = new.left_child_len, `left_child_label_val` = new.left_child_label_val, `right_child_len` = new.right_child_len, `right_child_label_val` = new.right_child_label_val, `hash` = new.hash", TABLE_HISTORY_TREE_NODES, SELECT_HISTORY_TREE_NODE_DATA, parts),
            StorageType::ValueState => format!("INSERT INTO `{}` ({}) VALUES {} as new ON DUPLICATE KEY UPDATE `data` = new.data, `node_label_val` = new.node_label_val, `node_label_len` = new.node_label_len, `version` = new.version", TABLE_USER, SELECT_USER_DATA, parts),
        }
    }

    fn set_batch_params(items: &[DbRecord]) -> Result<mysql_async::Params> {
        let param_batch = items
            .iter()
            .enumerate()
            .map(|(idx, item)| match &item {
                DbRecord::Azks(azks) => Ok(vec![
                    ("key".to_string(), Value::from(1u8)),
                    ("epoch".to_string(), Value::from(azks.latest_epoch)),
                    ("num_nodes".to_string(), Value::from(azks.num_nodes)),
                ]),
                DbRecord::TreeNode(node) => Ok(vec![
                    (format!("label_len{}", idx), Value::from(node.label.len)),
                    (format!("label_val{}", idx), Value::from(node.label.val)),
                    (format!("last_epoch{}", idx), Value::from(node.last_epoch)),
                    (
                        format!("least_descendent_ep{}", idx),
                        Value::from(node.least_descendent_ep),
                    ),
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
                    (
                        format!("left_child_len{}", idx),
                        Value::from(node.left_child.map(|lc| lc.len)),
                    ),
                    (
                        format!("left_child_label_val{}", idx),
                        Value::from(node.left_child.map(|lc| lc.val)),
                    ),
                    (
                        format!("right_child_len{}", idx),
                        Value::from(node.right_child.map(|rc| rc.len)),
                    ),
                    (
                        format!("right_child_label_val{}", idx),
                        Value::from(node.right_child.map(|rc| rc.val)),
                    ),
                    (format!("hash{}", idx), Value::from(node.hash)),
                ]),
                DbRecord::ValueState(state) => Ok(vec![
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
                ]),
            })
            .into_iter()
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        Ok(mysql_async::Params::from(param_batch))
    }

    fn get_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => format!("SELECT {} FROM `{}`", SELECT_AZKS_DATA, TABLE_AZKS),
            StorageType::TreeNode => format!(
                "SELECT {} FROM `{}`",
                SELECT_HISTORY_TREE_NODE_DATA, TABLE_HISTORY_TREE_NODES
            ),
            StorageType::ValueState => format!("SELECT {} FROM `{}`", SELECT_USER_DATA, TABLE_USER),
        }
    }

    fn get_batch_create_temp_table<St: Storable>() -> Option<String> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::TreeNode => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{}`(`label_len` INT UNSIGNED NOT NULL, `label_val` VARBINARY(32) NOT NULL, PRIMARY KEY(`label_len`, `label_val`))",
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
            StorageType::TreeNode => {
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
                    StorageType::TreeNode => {
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
                StorageType::TreeNode => "(:label_len, :label_val)",
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
            StorageType::TreeNode => {
                format!(
                    "SELECT a.`label_len`, a.`label_val`, a.`last_epoch`, a.`least_descendent_ep`, a.`parent_label_len`, a.`parent_label_val`, a.`node_type`, a.`left_child_len`, a.`left_child_label_val`, a.`right_child_len`, a.`right_child_label_val`, a.`hash` FROM `{}` a INNER JOIN {} ids ON ids.`label_len` = a.`label_len` AND ids.`label_val` = a.`label_val`",
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
            StorageType::Azks => {
                format!("SELECT {} FROM `{}` LIMIT 1", SELECT_AZKS_DATA, TABLE_AZKS)
            }
            StorageType::TreeNode => format!(
                "SELECT {} FROM `{}` WHERE `label_len` = :label_len AND `label_val` = :label_val",
                SELECT_HISTORY_TREE_NODE_DATA, TABLE_HISTORY_TREE_NODES
            ),
            StorageType::ValueState => format!(
                "SELECT {} FROM `{}` WHERE `username` = :username AND `epoch` = :epoch",
                SELECT_USER_DATA, TABLE_USER
            ),
        }
    }

    fn get_specific_params<St: Storable>(key: &St::Key) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::TreeNode => {
                let bin = St::get_full_binary_key_id(key);
                if let Ok(back) = TreeNode::key_from_full_binary(&bin) {
                    Some(params! {
                        "label_len" => back.0.len,
                        "label_val" => back.0.val,
                    })
                } else {
                    None
                }
            }
            StorageType::ValueState => {
                let bin = St::get_full_binary_key_id(key);
                if let Ok(back) = akd::storage::types::ValueState::key_from_full_binary(&bin) {
                    Some(params! {
                        "username" => back.0,
                        "epoch" => back.1
                    })
                } else {
                    None
                }
            }
        }
    }

    fn get_multi_row_specific_params<St: Storable>(
        keys: &[St::Key],
    ) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::TreeNode => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        // Since these are constructed from a safe key, they should never fail
                        // so we'll leave the unwrap to simplify
                        let back: NodeKey = TreeNode::key_from_full_binary(&bin).unwrap();
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
                        // Since these are constructed from a safe key, they should never fail
                        // so we'll leave the unwrap to simplify
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

    fn from_row<St: Storable>(row: &mut mysql_async::Row) -> core::result::Result<Self, MySqlError>
    where
        Self: std::marker::Sized,
    {
        fn cast_err() -> MySqlError {
            MySqlError::from("Failed to cast label:val into [u8; 32]".to_string())
        }

        fn optional_child_label(
            child_val: Option<Value>,
            child_len: Option<Value>,
        ) -> core::result::Result<Option<NodeLabel>, MySqlError> {
            match (child_val, child_len) {
                (Some(Value::NULL), _) => Ok(None),
                (_, Some(Value::NULL)) => Ok(None),
                (None, _) => Ok(None),
                (_, None) => Ok(None),
                (Some(possible_bytes), Some(possible_u32)) => {
                    match (
                        from_value_opt::<u32>(possible_u32),
                        from_value_opt::<Vec<u8>>(possible_bytes),
                    ) {
                        (Ok(len), Ok(val)) => Ok(Some(NodeLabel::new(
                            val.try_into().map_err(|_| cast_err())?,
                            len,
                        ))),
                        (Err(_len_err), _) => Err(Error::from("Error decoding length")),
                        (_, Err(_val_err)) => Err(Error::from("Error decoding value")),
                    }
                }
            }
        }

        match St::data_type() {
            StorageType::Azks => {
                // epoch, num_nodes
                if let (Some(Ok(epoch)), Some(Ok(num_nodes))) = (row.take_opt(0), row.take_opt(1)) {
                    let azks = DbRecord::build_azks(epoch, num_nodes);
                    return Ok(DbRecord::Azks(azks));
                }
            }
            StorageType::TreeNode => {
                // `label_len`, `label_val`, `last_epoch`, `least_descendent_ep`, `parent_label_len`, `parent_label_val`, `node_type`,
                // `left_child_len`, `left_child_label_val`, `right_child_len`, `right_child_label_val`, `hash`
                if let (
                    Some(Ok(label_len)),
                    Some(Ok(label_val)),
                    Some(Ok(last_epoch)),
                    Some(Ok(least_descendent_ep)),
                    Some(Ok(parent_label_len)),
                    Some(Ok(parent_label_val)),
                    Some(Ok(node_type)),
                    left_child_len_res,
                    left_child_val_res,
                    right_child_len_res,
                    right_child_val_res,
                    Some(Ok(hash)),
                ) = (
                    row.take_opt(0),
                    row.take_opt(1),
                    row.take_opt(2),
                    row.take_opt(3),
                    row.take_opt(4),
                    row.take_opt(5),
                    row.take_opt(6),
                    row.take(7),
                    row.take(8),
                    row.take(9),
                    row.take(10),
                    row.take_opt(11),
                ) {
                    let left_child = optional_child_label(left_child_val_res, left_child_len_res)?;
                    let right_child =
                        optional_child_label(right_child_val_res, right_child_len_res)?;

                    let label_val_vec: Vec<u8> = label_val;
                    let parent_label_val_vec: Vec<u8> = parent_label_val;

                    let hash_vec: Vec<u8> = hash;

                    let node = DbRecord::build_history_tree_node(
                        label_val_vec.try_into().map_err(|_| cast_err())?,
                        label_len,
                        last_epoch,
                        least_descendent_ep,
                        parent_label_val_vec.try_into().map_err(|_| cast_err())?,
                        parent_label_len,
                        node_type,
                        left_child,
                        right_child,
                        hash_vec.try_into().map_err(|_| cast_err())?,
                    );
                    return Ok(DbRecord::TreeNode(node));
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
