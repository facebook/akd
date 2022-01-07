// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the type conversions between internal AKD types and the serializable protobuf types

use std::convert::{TryFrom, TryInto};

pub mod inter_node;

// Protobuf best practice says everything should be `optional` to ensure
// maximum back-compatibility. This helper function ensures an optional
// field is present in a particular interface version.
macro_rules! require {
    ($obj:ident, $has_field:ident) => {
        if !$obj.$has_field() {
            return Err(crate::comms::CommunicationError::Serialization(format!(
                "Condition {}.{}() failed.",
                stringify!($obj),
                stringify!($has_field)
            )));
        }
    };
}

// ==============================================================
// NodeLabel
// ==============================================================

impl TryFrom<akd::node_state::NodeLabel> for inter_node::NodeLabel {
    type Error = crate::comms::CommunicationError;

    fn try_from(input: akd::node_state::NodeLabel) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_len(input.len);
        result.set_val(input.val);
        Ok(result)
    }
}

impl TryFrom<inter_node::NodeLabel> for akd::node_state::NodeLabel {
    type Error = crate::comms::CommunicationError;

    fn try_from(input: inter_node::NodeLabel) -> Result<Self, Self::Error> {
        require!(input, has_len);
        require!(input, has_val);
        Ok(akd::node_state::NodeLabel {
            len: input.get_len(),
            val: input.get_val(),
        })
    }
}

// ==============================================================
// Node
// ==============================================================

impl<H> TryFrom<akd::node_state::Node<H>> for inter_node::Node
where
    H: winter_crypto::Hasher,
{
    type Error = crate::comms::CommunicationError;

    fn try_from(input: akd::node_state::Node<H>) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_label(input.label.try_into()?);
        match akd::serialization::from_digest::<H>(input.hash) {
            Ok(hash) => {
                result.set_hash(hash);
            }
            Err(_) => {
                return Err(crate::comms::CommunicationError::Serialization(format!(
                    "Failed to serialize hash to bytes"
                )));
            }
        }
        Ok(result)
    }
}

impl<H> TryFrom<inter_node::Node> for akd::node_state::Node<H>
where
    H: winter_crypto::Hasher,
{
    type Error = crate::comms::CommunicationError;

    fn try_from(input: inter_node::Node) -> Result<Self, Self::Error> {
        require!(input, has_label);
        require!(input, has_hash);
        let label: akd::node_state::NodeLabel = input.get_label().clone().try_into()?;
        match akd::serialization::to_digest::<H>(input.get_hash()) {
            Err(_) => Err(crate::comms::CommunicationError::Serialization(format!(
                "Failed to de-serialize hash from bytes"
            ))),
            Ok(hash) => Ok(akd::node_state::Node::<H> { label, hash }),
        }
    }
}

// ==============================================================
// Append-only proof
// ==============================================================

// impl<H> TryFrom<akd::proof_structs::AppendOnlyProof<H>> for inter_node::AppendOnlyProof
// where
//     H: winter_crypto::Hasher,
// {
//     type Error = crate::comms::CommunicationError;

//     fn try_from(input: akd::proof_structs::AppendOnlyProof<H>) -> Result<Self, Self::Error> {
//         let mut result = Self::new();
//         result.set_label(input.label.try_into()?);
//         match akd::serialization::from_digest::<H>(input.hash) {
//             Ok(hash) => {
//                 result.set_hash(hash);
//             }
//             Err(_) => {
//                 return Err(crate::comms::CommunicationError::Serialization(format!(
//                     "Failed to serialize hash to bytes"
//                 )));
//             }
//         }
//         Ok(result)
//     }
// }

// impl<H> TryFrom<inter_node::AppendOnlyProof> for akd::proof_structs::AppendOnlyProof<H>
// where
//     H: winter_crypto::Hasher,
// {
//     type Error = crate::comms::CommunicationError;

//     fn try_from(input: inter_node::AppendOnlyProof) -> Result<Self, Self::Error> {
//         require!(input, has_label);
//         require!(input, has_hash);
//         let label: akd::node_state::NodeLabel = input.get_label().clone().try_into()?;
//         match akd::serialization::to_digest::<H>(input.get_hash()) {
//             Err(_) => Err(crate::comms::CommunicationError::Serialization(format!(
//                 "Failed to de-serialize hash from bytes"
//             ))),
//             Ok(hash) => Ok(akd::node_state::Node::<H> { label, hash }),
//         }
//     }
// }
