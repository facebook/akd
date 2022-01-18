// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the type conversions between internal AKD & message types
//! with the protobuf types

use protobuf::RepeatedField;
use std::convert::{TryFrom, TryInto};

type ConversionError = crate::comms::CommunicationError;

pub mod inter_node;

// Protobuf best practice says everything should be `optional` to ensure
// maximum back-compatibility. This helper function ensures an optional
// field is present in a particular interface version.
macro_rules! require {
    ($obj:ident, $has_field:ident) => {
        if !$obj.$has_field() {
            return Err(ConversionError::Serialization(format!(
                "Condition {}.{}() failed.",
                stringify!($obj),
                stringify!($has_field)
            )));
        }
    };
}

macro_rules! hash_to_bytes {
    ($obj:expr) => {
        akd::serialization::from_digest::<H>($obj).map_err(|_| {
            ConversionError::Serialization("Failed to convert digest to bytes".to_string())
        })?
    };
}

macro_rules! hash_from_bytes {
    ($obj:expr) => {
        akd::serialization::to_digest::<H>($obj).map_err(|_| {
            ConversionError::Serialization("Failed to convert bytes to digest".to_string())
        })?
    };
}

// ==============================================================
// InterNodeAck
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::InterNodeAck> for inter_node::InterNodeAck {
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::InterNodeAck,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_ok(input.ok);
        if let Some(err_msg) = input.err {
            result.set_err(err_msg);
        }
        match input.ackd_msg {
            crate::node::messages::inter_node::AckableMessage::AddNodeResult(add) => {
                result.set_add_result(add.try_into()?);
            }
            crate::node::messages::inter_node::AckableMessage::RemoveNodeResult(remove) => {
                result.set_remove_result(remove.try_into()?);
            }
        }
        Ok(result)
    }
}

impl TryFrom<&inter_node::InterNodeAck> for crate::node::messages::inter_node::InterNodeAck {
    type Error = ConversionError;

    fn try_from(input: &inter_node::InterNodeAck) -> Result<Self, Self::Error> {
        require!(input, has_ok);
        let err = match input.has_err() {
            true => Some(input.get_err().to_string()),
            false => None,
        };
        let ackable = match (input.has_add_result(), input.has_remove_result()) {
            (true, _) => Ok(
                crate::node::messages::inter_node::AckableMessage::AddNodeResult(
                    input.get_add_result().try_into()?,
                ),
            ),
            (_, true) => Ok(
                crate::node::messages::inter_node::AckableMessage::RemoveNodeResult(
                    input.get_remove_result().try_into()?,
                ),
            ),
            _ => Err(Self::Error::Serialization(
                "A inter-node ack requires the ack'd message as an argument to be populated"
                    .to_string(),
            )),
        }?;
        Ok(crate::node::messages::inter_node::InterNodeAck {
            ok: input.get_ok(),
            err,
            ackd_msg: ackable,
        })
    }
}

// ==============================================================
// NodeLabel
// ==============================================================

impl TryFrom<akd::node_state::NodeLabel> for inter_node::NodeLabel {
    type Error = ConversionError;

    fn try_from(input: akd::node_state::NodeLabel) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_len(input.len);
        result.set_val(input.val);
        Ok(result)
    }
}

impl TryFrom<&inter_node::NodeLabel> for akd::node_state::NodeLabel {
    type Error = ConversionError;

    fn try_from(input: &inter_node::NodeLabel) -> Result<Self, Self::Error> {
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
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(input: akd::node_state::Node<H>) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_label(input.label.try_into()?);
        result.set_hash(hash_to_bytes!(input.hash));
        Ok(result)
    }
}

impl<H> TryFrom<&inter_node::Node> for akd::node_state::Node<H>
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::Node) -> Result<Self, Self::Error> {
        require!(input, has_label);
        require!(input, has_hash);
        let label: akd::node_state::NodeLabel = input.get_label().try_into()?;
        Ok(akd::node_state::Node::<H> {
            label,
            hash: hash_from_bytes!(input.get_hash()),
        })
    }
}

// ==============================================================
// Append-only proof
// ==============================================================

impl<H> TryFrom<akd::proof_structs::AppendOnlyProof<H>> for inter_node::AppendOnlyProof
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(input: akd::proof_structs::AppendOnlyProof<H>) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        let mut inserted = vec![];
        let mut unchanged = vec![];

        for item in input.inserted.into_iter() {
            inserted.push(item.try_into()?);
        }
        for item in input.unchanged_nodes.into_iter() {
            unchanged.push(item.try_into()?);
        }

        result.set_inserted(RepeatedField::from_vec(inserted));
        result.set_unchanged(RepeatedField::from_vec(unchanged));
        Ok(result)
    }
}

impl<H> TryFrom<&inter_node::AppendOnlyProof> for akd::proof_structs::AppendOnlyProof<H>
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::AppendOnlyProof) -> Result<Self, Self::Error> {
        let mut inserted = vec![];
        let mut unchanged = vec![];
        for item in input.get_inserted() {
            inserted.push(item.try_into()?);
        }
        for item in input.get_unchanged() {
            unchanged.push(item.try_into()?);
        }
        Ok(akd::proof_structs::AppendOnlyProof {
            inserted,
            unchanged_nodes: unchanged,
        })
    }
}

// ==============================================================
// Verify Request
// ==============================================================

impl<H> TryFrom<crate::node::messages::inter_node::VerifyRequest<H>> for inter_node::VerifyRequest
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::VerifyRequest<H>,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_epoch(input.epoch);
        result.set_new_hash(hash_to_bytes!(input.new_hash));
        result.set_proof(input.append_only_proof.try_into()?);
        result.set_previous_hash(hash_to_bytes!(input.previous_hash));
        Ok(result)
    }
}

impl<H> TryFrom<&inter_node::VerifyRequest> for crate::node::messages::inter_node::VerifyRequest<H>
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::VerifyRequest) -> Result<Self, Self::Error> {
        require!(input, has_epoch);
        require!(input, has_new_hash);
        require!(input, has_previous_hash);

        let proof: akd::proof_structs::AppendOnlyProof<H> = input.get_proof().try_into()?;

        Ok(crate::node::messages::inter_node::VerifyRequest::<H> {
            epoch: input.get_epoch(),
            new_hash: hash_from_bytes!(input.get_new_hash()),
            append_only_proof: proof,
            previous_hash: hash_from_bytes!(input.get_previous_hash()),
        })
    }
}

// ==============================================================
// Verify Response
// ==============================================================

impl<H> TryFrom<crate::node::messages::inter_node::VerifyResponse<H>> for inter_node::VerifyResponse
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::VerifyResponse<H>,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        if let (Some(shard), hash) = (input.encrypted_quorum_key_shard, input.verified_hash) {
            result.set_verified_hash(hash_to_bytes!(hash));
            result.set_encrypted_quorum_key_shard(shard);
        }
        // Else: >= 1 of the components is missing, this is assumed a "validation failure" scenario
        // i.e. the proof failed to verify
        Ok(result)
    }
}

impl<H> TryFrom<&inter_node::VerifyResponse>
    for crate::node::messages::inter_node::VerifyResponse<H>
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::VerifyResponse) -> Result<Self, Self::Error> {
        require!(input, has_verified_hash);
        if input.has_encrypted_quorum_key_shard() {
            // verification succeeded on the worker node, proceed with reconstructing the result
            Ok(Self {
                verified_hash: hash_from_bytes!(input.get_verified_hash()),
                encrypted_quorum_key_shard: Some(input.get_encrypted_quorum_key_shard().to_vec()),
            })
        } else {
            // Verification failed or a partial result came back. Both are mapped to verification failed
            Ok(Self {
                verified_hash: hash_from_bytes!(input.get_verified_hash()),
                encrypted_quorum_key_shard: None,
            })
        }
    }
}

// ==============================================================
// Verify Response
// ==============================================================

impl TryFrom<crate::comms::ContactInformation> for inter_node::NodeContact {
    type Error = ConversionError;
    fn try_from(input: crate::comms::ContactInformation) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_ip_address(input.ip_address);
        result.set_port(input.port.into());
        Ok(result)
    }
}

impl TryFrom<&inter_node::NodeContact> for crate::comms::ContactInformation {
    type Error = ConversionError;
    fn try_from(input: &inter_node::NodeContact) -> Result<Self, Self::Error> {
        Ok(Self {
            ip_address: input.get_ip_address().to_string(),
            port: input.get_port() as u16,
        })
    }
}

// ==============================================================
// Add Node Init
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::AddNodeInit> for inter_node::AddNodeInit {
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::AddNodeInit,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_contact_information(input.contact_info.try_into()?);
        result.set_public_key(input.public_key);
        Ok(result)
    }
}

impl TryFrom<&inter_node::AddNodeInit> for crate::node::messages::inter_node::AddNodeInit {
    type Error = ConversionError;

    fn try_from(input: &inter_node::AddNodeInit) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: input.get_public_key().to_vec(),
            contact_info: input.get_contact_information().try_into()?,
        })
    }
}

// ==============================================================
// Add Node Test Result
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::AddNodeTestResult>
    for inter_node::AddNodeTestResult
{
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::AddNodeTestResult,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        if let Some(key) = input.encrypted_quorum_key_shard {
            result.set_encrypted_quorum_key_shard(key);
        }
        result.set_contact_information(input.contact_info.try_into()?);
        Ok(result)
    }
}

impl TryFrom<&inter_node::AddNodeTestResult>
    for crate::node::messages::inter_node::AddNodeTestResult
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::AddNodeTestResult) -> Result<Self, Self::Error> {
        require!(input, has_contact_information);
        let key = match input.has_encrypted_quorum_key_shard() {
            true => Some(input.get_encrypted_quorum_key_shard().to_vec()),
            false => None,
        };
        Ok(Self {
            encrypted_quorum_key_shard: key,
            contact_info: input.get_contact_information().try_into()?,
        })
    }
}

// ==============================================================
// Add Node Result
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::AddNodeResult> for inter_node::AddNodeResult {
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::AddNodeResult,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        if let Some(key) = input.encrypted_quorum_key_shard {
            result.set_encrypted_quorum_key_shard(key);
        }
        result.set_node_id(input.new_member.node_id);
        result.set_public_key(input.new_member.public_key);
        result.set_contact_information(input.new_member.contact_information.try_into()?);
        Ok(result)
    }
}

impl TryFrom<&inter_node::AddNodeResult> for crate::node::messages::inter_node::AddNodeResult {
    type Error = ConversionError;

    fn try_from(input: &inter_node::AddNodeResult) -> Result<Self, Self::Error> {
        require!(input, has_node_id);
        require!(input, has_public_key);
        require!(input, has_contact_information);
        let key = match input.has_encrypted_quorum_key_shard() {
            true => Some(input.get_encrypted_quorum_key_shard().to_vec()),
            false => None,
        };
        Ok(Self {
            encrypted_quorum_key_shard: key,
            new_member: crate::storage::MemberInformation {
                node_id: input.get_node_id(),
                public_key: input.get_public_key().to_vec(),
                contact_information: input.get_contact_information().try_into()?,
            },
        })
    }
}

// ==============================================================
// New Node Test
// ==============================================================

impl<H> TryFrom<crate::node::messages::inter_node::NewNodeTest<H>> for inter_node::NewNodeTest
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::NewNodeTest<H>,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_new_hash(hash_to_bytes!(input.new_hash));
        result.set_previous_hash(hash_to_bytes!(input.previous_hash));
        result.set_requesters_public_key(input.requesters_public_key);
        result.set_test_proof(input.test_proof.try_into()?);
        Ok(result)
    }
}

impl<H> TryFrom<&inter_node::NewNodeTest> for crate::node::messages::inter_node::NewNodeTest<H>
where
    H: winter_crypto::Hasher + Clone,
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::NewNodeTest) -> Result<Self, Self::Error> {
        require!(input, has_new_hash);
        require!(input, has_previous_hash);
        require!(input, has_requesters_public_key);
        require!(input, has_test_proof);
        Ok(Self {
            new_hash: hash_from_bytes!(input.get_new_hash()),
            previous_hash: hash_from_bytes!(input.get_previous_hash()),
            requesters_public_key: input.get_requesters_public_key().to_vec(),
            test_proof: input.get_test_proof().try_into()?,
        })
    }
}

// ==============================================================
// New Node Test Result
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::NewNodeTestResult>
    for inter_node::NewNodeTestResult
{
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::NewNodeTestResult,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_test_pass(input.test_pass);
        Ok(result)
    }
}

impl TryFrom<&inter_node::NewNodeTestResult>
    for crate::node::messages::inter_node::NewNodeTestResult
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::NewNodeTestResult) -> Result<Self, Self::Error> {
        require!(input, has_test_pass);
        Ok(Self {
            test_pass: input.get_test_pass(),
        })
    }
}

// ==============================================================
// Remove Node Init
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::RemoveNodeInit> for inter_node::RemoveNodeInit {
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::RemoveNodeInit,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_node_id(input.node_id);
        Ok(result)
    }
}

impl TryFrom<&inter_node::RemoveNodeInit> for crate::node::messages::inter_node::RemoveNodeInit {
    type Error = ConversionError;

    fn try_from(input: &inter_node::RemoveNodeInit) -> Result<Self, Self::Error> {
        require!(input, has_node_id);
        Ok(Self {
            node_id: input.get_node_id(),
        })
    }
}

// ==============================================================
// Remove Node Test Result
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::RemoveNodeTestResult>
    for inter_node::RemoveNodeTestResult
{
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::RemoveNodeTestResult,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_node_id(input.offending_member);
        if let Some(shard) = input.encrypted_quorum_key_shard {
            result.set_encrypted_quorum_key_shard(shard);
        }
        Ok(result)
    }
}

impl TryFrom<&inter_node::RemoveNodeTestResult>
    for crate::node::messages::inter_node::RemoveNodeTestResult
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::RemoveNodeTestResult) -> Result<Self, Self::Error> {
        let shard = match input.has_encrypted_quorum_key_shard() {
            true => Some(input.get_encrypted_quorum_key_shard().to_vec()),
            false => None,
        };
        Ok(Self {
            encrypted_quorum_key_shard: shard,
            offending_member: input.get_node_id(),
        })
    }
}

// ==============================================================
// Remove Node Result
// ==============================================================

impl TryFrom<crate::node::messages::inter_node::RemoveNodeResult> for inter_node::RemoveNodeResult {
    type Error = ConversionError;

    fn try_from(
        input: crate::node::messages::inter_node::RemoveNodeResult,
    ) -> Result<Self, Self::Error> {
        let mut result = Self::new();
        result.set_node_id(input.offending_member);
        if let Some(shard) = input.encrypted_quorum_key_shard {
            result.set_encrypted_quorum_key_shard(shard);
        }
        Ok(result)
    }
}

impl TryFrom<&inter_node::RemoveNodeResult>
    for crate::node::messages::inter_node::RemoveNodeResult
{
    type Error = ConversionError;

    fn try_from(input: &inter_node::RemoveNodeResult) -> Result<Self, Self::Error> {
        require!(input, has_node_id);
        let shard = match input.has_encrypted_quorum_key_shard() {
            true => Some(input.get_encrypted_quorum_key_shard().to_vec()),
            false => None,
        };
        Ok(Self {
            encrypted_quorum_key_shard: shard,
            offending_member: input.get_node_id(),
        })
    }
}
