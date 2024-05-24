// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module implements record handling for a simple asynchronized mysql database

use std::convert::TryInto;

use akd::storage::types::{DbRecord, StorageType};
use akd::storage::Storable;
use akd::tree_node::{NodeKey, TreeNodeWithPreviousValue};
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
    "`label_len`, `label_val`, `last_epoch`, `least_descendant_ep`, `parent_label_len`, `parent_label_val`, `node_type`, `left_child_len`, `left_child_label_val`, `right_child_len`, `right_child_label_val`, `hash`, `p_last_epoch`, `p_least_descendant_ep`, `p_parent_label_len`, `p_parent_label_val`, `p_node_type`, `p_left_child_len`, `p_left_child_label_val`, `p_right_child_len`, `p_right_child_label_val`, `p_hash`";
const SELECT_USER_DATA: &str =
    "`username`, `epoch`, `version`, `node_label_val`, `node_label_len`, `data`";

pub(crate) trait MySqlStorable {
    fn set_statement(&self) -> String;

    fn set_params(&self) -> Option<mysql_async::Params>;

    fn set_batch_statement<St: Storable>(items: usize) -> String;

    fn set_batch_params(items: &[DbRecord]) -> Result<mysql_async::Params>;

    #[allow(dead_code)]
    fn get_statement<St: Storable>() -> String;

    fn get_batch_create_temp_table<St: Storable>() -> Option<String>;

    fn get_batch_fill_temp_table<St: Storable>(num_items: Option<usize>) -> String;

    fn get_batch_statement<St: Storable>() -> String;

    fn get_specific_statement<St: Storable>() -> String;

    fn get_specific_params<St: Storable>(key: &St::StorageKey) -> Option<mysql_async::Params>;

    fn get_multi_row_specific_params<St: Storable>(
        keys: &[St::StorageKey],
    ) -> Option<mysql_async::Params>;

    fn from_row<St: Storable>(row: &mut mysql_async::Row) -> core::result::Result<Self, MySqlError>
    where
        Self: std::marker::Sized;
}

impl MySqlStorable for DbRecord {
    fn set_statement(&self) -> String {
        match &self {
            DbRecord::Azks(_) => format!("INSERT INTO `{TABLE_AZKS}` (`key`, {SELECT_AZKS_DATA})
            VALUES (:key, :epoch, :num_nodes)
            ON DUPLICATE KEY UPDATE
                `epoch` = :epoch
                , `num_nodes` = :num_nodes"),
            DbRecord::TreeNode(_) => format!("INSERT INTO `{TABLE_HISTORY_TREE_NODES}` ({SELECT_HISTORY_TREE_NODE_DATA})
            VALUES (:label_len
                , :label_val
                , :last_epoch
                , :least_descendant_ep
                , :parent_label_len
                , :parent_label_val
                , :node_type
                , :left_child_len
                , :left_child_label_val
                , :right_child_len
                , :right_child_label_val
                , :hash
                , :p_last_epoch
                , :p_least_descendant_ep
                , :p_parent_label_len
                , :p_parent_label_val
                , :p_node_type
                , :p_left_child_len
                , :p_left_child_label_val
                , :p_right_child_len
                , :p_right_child_label_val
                , :p_hash)
            ON DUPLICATE KEY UPDATE
                `label_len` = :label_len
                , `label_val` = :label_val
                , `last_epoch` = :last_epoch
                , `least_descendant_ep` = :least_descendant_ep
                , `parent_label_len` = :parent_label_len
                , `parent_label_val` = :parent_label_val
                , `node_type` = :node_type
                , `left_child_len` = :left_child_len
                , `left_child_label_val` = :left_child_label_val
                , `right_child_len` = :right_child_len
                , `right_child_label_val` = :right_child_label_val
                , `hash` = :hash
                , `p_last_epoch` = :p_last_epoch
                , `p_least_descendant_ep` = :p_least_descendant_ep
                , `p_parent_label_len` = :p_parent_label_len
                , `p_parent_label_val` = :p_parent_label_val
                , `p_node_type` = :p_node_type
                , `p_left_child_len` = :p_left_child_len
                , `p_left_child_label_val` = :p_left_child_label_val
                , `p_right_child_len` = :p_right_child_len
                , `p_right_child_label_val` = :p_right_child_label_val
                , `p_hash` = :p_hash"),
            DbRecord::ValueState(_) => format!("INSERT INTO `{TABLE_USER}` ({SELECT_USER_DATA}) VALUES (:username, :epoch, :version, :node_label_val, :node_label_len, :data)"),
        }
    }

    fn set_params(&self) -> Option<mysql_async::Params> {
        match &self {
            DbRecord::Azks(azks) => Some(
                params! { "key" => 1u8, "epoch" => azks.latest_epoch, "num_nodes" => azks.num_nodes },
            ),
            DbRecord::TreeNode(node) => Some(params! {
                "label_len" => node.label.label_len,
                "label_val" => node.label.label_val,
                // "Latest" node values
                "last_epoch" => node.latest_node.last_epoch,
                "least_descendant_ep" => node.latest_node.min_descendant_epoch,
                "parent_label_len" => node.latest_node.parent.label_len,
                "parent_label_val" => node.latest_node.parent.label_val,
                "node_type" => node.latest_node.node_type as u8,
                "left_child_len" => node.latest_node.left_child.map(|lc| lc.label_len),
                "left_child_label_val" => node.latest_node.left_child.map(|lc| lc.label_val),
                "right_child_len" => node.latest_node.right_child.map(|rc| rc.label_len),
                "right_child_label_val" => node.latest_node.right_child.map(|rc| rc.label_val),
                "hash" => node.latest_node.hash.0,
                // "Previous" node values
                "p_last_epoch" => node.previous_node.clone().map(|a| a.last_epoch),
                "p_least_descendant_ep" => node.previous_node.clone().map(|a| a.min_descendant_epoch),
                "p_parent_label_len" => node.previous_node.clone().map(|a| a.parent.label_len),
                "p_parent_label_val" => node.previous_node.clone().map(|a| a.parent.label_val),
                "p_node_type" => node.previous_node.clone().map(|a| a.node_type as u8),
                "p_left_child_len" => node.previous_node.clone().and_then(|a| a.left_child.map(|lc| lc.label_len)),
                "p_left_child_label_val" => node.previous_node.clone().and_then(|a| a.left_child.map(|lc| lc.label_val)),
                "p_right_child_len" => node.previous_node.clone().and_then(|a| a.right_child.map(|rc| rc.label_len)),
                "p_right_child_label_val" => node.previous_node.clone().and_then(|a| a.right_child.map(|rc| rc.label_val)),
                "p_hash" => node.previous_node.clone().map(|a| a.hash.0),
            }),
            DbRecord::ValueState(state) => Some(
                params! { "username" => state.get_id().0, "epoch" => state.epoch, "version" => state.version, "node_label_len" => state.label.label_len, "node_label_val" => state.label.label_val, "data" => state.value.0.clone() },
            ),
        }
    }

    fn set_batch_statement<St: Storable>(items: usize) -> String {
        let mut parts = "".to_string();
        for i in 0..items {
            match St::data_type() {
                StorageType::TreeNode => {
                    parts = format!(
                        "{parts}(:label_len{i}
                            , :label_val{i}
                            , :last_epoch{i}
                            , :least_descendant_ep{i}
                            , :parent_label_len{i}
                            , :parent_label_val{i}
                            , :node_type{i}
                            , :left_child_len{i}
                            , :left_child_label_val{i}
                            , :right_child_len{i}
                            , :right_child_label_val{i}
                            , :hash{i}
                            , :p_last_epoch{i}
                            , :p_least_descendant_ep{i}
                            , :p_parent_label_len{i}
                            , :p_parent_label_val{i}
                            , :p_node_type{i}
                            , :p_left_child_len{i}
                            , :p_left_child_label_val{i}
                            , :p_right_child_len{i}
                            , :p_right_child_label_val{i}
                            , :p_hash{i})"
                    );
                }
                StorageType::ValueState => {
                    parts = format!(
                        "{parts}(:username{i}, :epoch{i}, :version{i}, :node_label_val{i}, :node_label_len{i}, :data{i})"
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
            StorageType::Azks => format!(
                "INSERT INTO `{TABLE_AZKS}` (`key`, {SELECT_AZKS_DATA})
            VALUES (:key, :epoch, :num_nodes) as new
            ON DUPLICATE KEY UPDATE `epoch` = new.epoch, `num_nodes` = new.num_nodes"
            ),
            StorageType::TreeNode => format!(
                "INSERT INTO `{TABLE_HISTORY_TREE_NODES}` ({SELECT_HISTORY_TREE_NODE_DATA})
            VALUES {parts} as new
            ON DUPLICATE KEY UPDATE
                `label_len` = new.label_len
                , `label_val` = new.label_val
                , `least_descendant_ep` = new.least_descendant_ep
                , `last_epoch` = new.last_epoch
                , `parent_label_len` = new.parent_label_len
                , `parent_label_val` = new.parent_label_val
                , `node_type` = new.node_type
                , `left_child_len` = new.left_child_len
                , `left_child_label_val` = new.left_child_label_val
                , `right_child_len` = new.right_child_len
                , `right_child_label_val` = new.right_child_label_val
                , `hash` = new.hash
                , `p_last_epoch` = new.p_last_epoch
                , `p_least_descendant_ep` = new.p_least_descendant_ep
                , `p_parent_label_len` = new.p_parent_label_len
                , `p_parent_label_val` = new.p_parent_label_val
                , `p_node_type` = new.p_node_type
                , `p_left_child_len` = new.p_left_child_len
                , `p_left_child_label_val` = new.p_left_child_label_val
                , `p_right_child_len` = new.p_right_child_len
                , `p_right_child_label_val` = new.p_right_child_label_val
                , `p_hash` = new.p_hash"
            ),
            StorageType::ValueState => format!(
                "INSERT INTO `{TABLE_USER}` ({SELECT_USER_DATA})
            VALUES {parts} as new
            ON DUPLICATE KEY UPDATE
                `data` = new.data
                , `node_label_val` = new.node_label_val
                , `node_label_len` = new.node_label_len
                , `version` = new.version"
            ),
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
                DbRecord::TreeNode(node) => {
                    let pnode = &node.previous_node;
                    Ok(vec![
                        (format!("label_len{idx}"), Value::from(node.label.label_len)),
                        (format!("label_val{idx}"), Value::from(node.label.label_val)),
                        (
                            format!("last_epoch{idx}"),
                            Value::from(node.latest_node.last_epoch),
                        ),
                        (
                            format!("least_descendant_ep{idx}"),
                            Value::from(node.latest_node.min_descendant_epoch),
                        ),
                        (
                            format!("parent_label_len{idx}"),
                            Value::from(node.latest_node.parent.label_len),
                        ),
                        (
                            format!("parent_label_val{idx}"),
                            Value::from(node.latest_node.parent.label_val),
                        ),
                        (
                            format!("node_type{idx}"),
                            Value::from(node.latest_node.node_type as u8),
                        ),
                        (
                            format!("left_child_len{idx}"),
                            Value::from(node.latest_node.left_child.map(|lc| lc.label_len)),
                        ),
                        (
                            format!("left_child_label_val{idx}"),
                            Value::from(node.latest_node.left_child.map(|lc| lc.label_val)),
                        ),
                        (
                            format!("right_child_len{idx}"),
                            Value::from(node.latest_node.right_child.map(|rc| rc.label_len)),
                        ),
                        (
                            format!("right_child_label_val{idx}"),
                            Value::from(node.latest_node.right_child.map(|rc| rc.label_val)),
                        ),
                        (format!("hash{idx}"), Value::from(node.latest_node.hash.0)),
                        (
                            format!("p_last_epoch{idx}"),
                            Value::from(pnode.clone().map(|a| a.last_epoch)),
                        ),
                        (
                            format!("p_least_descendant_ep{idx}"),
                            Value::from(pnode.clone().map(|a| a.min_descendant_epoch)),
                        ),
                        (
                            format!("p_parent_label_len{idx}"),
                            Value::from(pnode.clone().map(|a| a.parent.label_len)),
                        ),
                        (
                            format!("p_parent_label_val{idx}"),
                            Value::from(pnode.clone().map(|a| a.parent.label_val)),
                        ),
                        (
                            format!("p_node_type{idx}"),
                            Value::from(pnode.clone().map(|a| a.node_type as u8)),
                        ),
                        (
                            format!("p_left_child_len{idx}"),
                            Value::from(
                                pnode
                                    .clone()
                                    .and_then(|a| a.left_child.map(|lc| lc.label_len)),
                            ),
                        ),
                        (
                            format!("p_left_child_label_val{idx}"),
                            Value::from(
                                pnode
                                    .clone()
                                    .and_then(|a| a.left_child.map(|lc| lc.label_val)),
                            ),
                        ),
                        (
                            format!("p_right_child_len{idx}"),
                            Value::from(
                                pnode
                                    .clone()
                                    .and_then(|a| a.right_child.map(|rc| rc.label_len)),
                            ),
                        ),
                        (
                            format!("p_right_child_label_val{idx}"),
                            Value::from(
                                pnode
                                    .clone()
                                    .and_then(|a| a.right_child.map(|rc| rc.label_val)),
                            ),
                        ),
                        (
                            format!("p_hash{idx}"),
                            Value::from(pnode.clone().map(|a| a.hash.0)),
                        ),
                    ])
                }
                DbRecord::ValueState(state) => Ok(vec![
                    (format!("username{idx}"), Value::from(state.get_id().0)),
                    (format!("epoch{idx}"), Value::from(state.epoch)),
                    (format!("version{idx}"), Value::from(state.version)),
                    (
                        format!("node_label_len{idx}"),
                        Value::from(state.label.label_len),
                    ),
                    (
                        format!("node_label_val{idx}"),
                        Value::from(state.label.label_val),
                    ),
                    (format!("data{idx}"), Value::from(state.value.0.clone())),
                ]),
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        Ok(mysql_async::Params::from(param_batch))
    }

    fn get_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => format!("SELECT {SELECT_AZKS_DATA} FROM `{TABLE_AZKS}`"),
            StorageType::TreeNode => {
                format!("SELECT {SELECT_HISTORY_TREE_NODE_DATA} FROM `{TABLE_HISTORY_TREE_NODES}`")
            }
            StorageType::ValueState => format!("SELECT {SELECT_USER_DATA} FROM `{TABLE_USER}`"),
        }
    }

    fn get_batch_create_temp_table<St: Storable>() -> Option<String> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::TreeNode => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{TEMP_IDS_TABLE}`(`label_len` INT UNSIGNED NOT NULL, `label_val` VARBINARY(32) NOT NULL, PRIMARY KEY(`label_len`, `label_val`))"
                    )
                )
            },
            StorageType::ValueState => {
                Some(
                    format!(
                        "CREATE TEMPORARY TABLE `{TEMP_IDS_TABLE}`(`username` VARCHAR(256) NOT NULL, `epoch` BIGINT UNSIGNED NOT NULL, PRIMARY KEY(`username`, `epoch`))"
                    )
                )
            },
        }
    }

    fn get_batch_fill_temp_table<St: Storable>(num_items: Option<usize>) -> String {
        let mut statement = match St::data_type() {
            StorageType::Azks => "".to_string(),
            StorageType::TreeNode => {
                format!("INSERT INTO `{TEMP_IDS_TABLE}` (`label_len`, `label_val`) VALUES ")
            }
            StorageType::ValueState => {
                format!("INSERT INTO `{TEMP_IDS_TABLE}` (`username`, `epoch`) VALUES ")
            }
        };
        if let Some(item_count) = num_items {
            for i in 0..item_count {
                let append = match St::data_type() {
                    StorageType::Azks => String::from(""),
                    StorageType::TreeNode => {
                        format!("(:label_len{i}, :label_val{i})")
                    }
                    StorageType::ValueState => {
                        format!("(:username{i}, :epoch{i})")
                    }
                };
                statement = format!("{statement}{append}");

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
                format!("SELECT {SELECT_AZKS_DATA} FROM `{TABLE_AZKS}` LIMIT 1")
            }
            StorageType::TreeNode => {
                format!(
                    "SELECT
                        a.`label_len`
                        , a.`label_val`
                        , a.`last_epoch`
                        , a.`least_descendant_ep`
                        , a.`parent_label_len`
                        , a.`parent_label_val`
                        , a.`node_type`
                        , a.`left_child_len`
                        , a.`left_child_label_val`
                        , a.`right_child_len`
                        , a.`right_child_label_val`
                        , a.`hash`, a.`p_last_epoch`
                        , a.`p_least_descendant_ep`
                        , a.`p_parent_label_len`
                        , a.`p_parent_label_val`
                        , a.`p_node_type`
                        , a.`p_left_child_len`
                        , a.`p_left_child_label_val`
                        , a.`p_right_child_len`
                        , a.`p_right_child_label_val`
                        , a.`p_hash`
                    FROM `{TABLE_HISTORY_TREE_NODES}` a
                    INNER JOIN {TEMP_IDS_TABLE} ids
                        ON ids.`label_len` = a.`label_len`
                        AND ids.`label_val` = a.`label_val`"
                )
            }
            StorageType::ValueState => {
                format!(
                    "SELECT
                        a.`username`
                        , a.`epoch`
                        , a.`version`
                        , a.`node_label_val`
                        , a.`node_label_len`
                        , a.`data`
                    FROM `{TABLE_USER}` a
                    INNER JOIN {TEMP_IDS_TABLE} ids
                        ON ids.`username` = a.`username`
                        AND ids.`epoch` = a.`epoch`"
                )
            }
        }
    }

    fn get_specific_statement<St: Storable>() -> String {
        match St::data_type() {
            StorageType::Azks => {
                format!("SELECT {SELECT_AZKS_DATA} FROM `{TABLE_AZKS}` LIMIT 1")
            }
            StorageType::TreeNode => format!(
                "SELECT {SELECT_HISTORY_TREE_NODE_DATA} FROM `{TABLE_HISTORY_TREE_NODES}` WHERE `label_len` = :label_len AND `label_val` = :label_val"
            ),
            StorageType::ValueState => format!(
                "SELECT {SELECT_USER_DATA} FROM `{TABLE_USER}` WHERE `username` = :username AND `epoch` = :epoch"
            ),
        }
    }

    fn get_specific_params<St: Storable>(key: &St::StorageKey) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::TreeNode => {
                let bin = St::get_full_binary_key_id(key);
                if let Ok(back) = TreeNodeWithPreviousValue::key_from_full_binary(&bin) {
                    Some(params! {
                        "label_len" => back.0.label_len,
                        "label_val" => back.0.label_val,
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
        keys: &[St::StorageKey],
    ) -> Option<mysql_async::Params> {
        match St::data_type() {
            StorageType::Azks => None,
            StorageType::TreeNode => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .flat_map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        // Since these are constructed from a safe key, they should never fail
                        // so we'll leave the unwrap to simplify
                        let back: NodeKey =
                            TreeNodeWithPreviousValue::key_from_full_binary(&bin).unwrap();
                        vec![
                            (format!("label_len{idx}"), Value::from(back.0.label_len)),
                            (format!("label_val{idx}"), Value::from(back.0.label_val)),
                        ]
                    })
                    .collect::<Vec<_>>();
                Some(mysql_async::Params::from(pvec))
            }
            StorageType::ValueState => {
                let pvec = keys
                    .iter()
                    .enumerate()
                    .flat_map(|(idx, key)| {
                        let bin = St::get_full_binary_key_id(key);
                        // Since these are constructed from a safe key, they should never fail
                        // so we'll leave the unwrap to simplify
                        let back: akd::storage::types::ValueStateKey =
                            akd::storage::types::ValueState::key_from_full_binary(&bin).unwrap();
                        vec![
                            (format!("username{idx}"), Value::from(back.0.clone())),
                            (format!("epoch{idx}"), Value::from(back.1)),
                        ]
                    })
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
            MySqlError::from(mysql_async::ServerError {
                state: "".to_string(),
                code: 0,
                message: "Failed to cast label:val into [u8; 32]".to_string(),
            })
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
                        (Err(_len_err), _) => Err(Error::from(mysql_async::ServerError {
                            state: "".to_string(),
                            code: 0,
                            message: "Error decoding length".to_string(),
                        })),
                        (_, Err(_val_err)) => Err(Error::from(mysql_async::ServerError {
                            state: "".to_string(),
                            code: 0,
                            message: "Error decoding value".to_string(),
                        })),
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
                // A NOTE ABOUT THE SYNTAX HERE: The outer-most Some(**) of the row.take(..) indicates the COLUMN EXISTS, not that it actually has a value.
                // Therefore the signature of these fields you want is Some(Option<value>) for a nullable column. The inner option type is not necessary
                // for types which have NOT NULL in the SQL definition
                if let (
                    Some(Ok(label_len)),
                    Some(Ok(label_val)),
                    Some(Ok(last_epoch)),
                    Some(Ok(least_descendant_ep)),
                    Some(Ok(parent_label_len)),
                    Some(Ok(parent_label_val)),
                    Some(Ok(node_type)),
                    left_child_len_res,
                    left_child_val_res,
                    right_child_len_res,
                    right_child_val_res,
                    Some(Ok(hash)),
                    Some(p_last_epoch),
                    Some(p_least_descendant_ep),
                    Some(p_parent_label_len),
                    Some(p_parent_label_val),
                    Some(p_node_type),
                    p_left_child_len,
                    p_left_child_label_val,
                    p_right_child_len,
                    p_right_child_label_val,
                    Some(p_hash),
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
                    row.take(12),
                    row.take(13),
                    row.take(14),
                    row.take(15),
                    row.take(16),
                    row.take(17),
                    row.take(18),
                    row.take(19),
                    row.take(20),
                    row.take(21),
                ) {
                    let left_child = optional_child_label(left_child_val_res, left_child_len_res)?;
                    let right_child =
                        optional_child_label(right_child_val_res, right_child_len_res)?;
                    let p_left_child =
                        optional_child_label(p_left_child_label_val, p_left_child_len)?;
                    let p_right_child =
                        optional_child_label(p_right_child_label_val, p_right_child_len)?;

                    let label_val_vec: Vec<u8> = label_val;

                    let parent_label_val_vec: Vec<u8> = parent_label_val;
                    let prev_parent_label_val_vec: Option<Vec<u8>> = p_parent_label_val;
                    let hash_vec: Vec<u8> = hash;
                    let prev_hash_vec: Option<Vec<u8>> = p_hash;

                    let massaged_prev_parent_label_val: Option<[u8; 32]> =
                        match prev_parent_label_val_vec {
                            Some(v) => Some(v.try_into().map_err(|_| cast_err())?),
                            None => None,
                        };
                    let massaged_hash_vec: akd::Digest =
                        akd::hash::try_parse_digest(&hash_vec).map_err(|_| cast_err())?;
                    let massaged_prev_hash_vec: Option<akd::Digest> = match prev_hash_vec {
                        Some(v) => match akd::hash::try_parse_digest(&v).map_err(|_| cast_err()) {
                            Ok(r) => Some(r),
                            Err(err) => return Err(err),
                        },
                        None => None,
                    };

                    let node = DbRecord::build_tree_node_with_previous_value(
                        label_val_vec.try_into().map_err(|_| cast_err())?,
                        label_len,
                        last_epoch,
                        least_descendant_ep,
                        parent_label_val_vec.try_into().map_err(|_| cast_err())?,
                        parent_label_len,
                        node_type,
                        left_child,
                        right_child,
                        massaged_hash_vec,
                        p_last_epoch,
                        p_least_descendant_ep,
                        massaged_prev_parent_label_val,
                        p_parent_label_len,
                        p_node_type,
                        p_left_child,
                        p_right_child,
                        massaged_prev_hash_vec,
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
