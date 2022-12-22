// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the protobuf types for type conversion between internal and external
//! types. NOTE: Protobuf encoding is NOT supported in nostd environments. The generated code is using vector
//! too heavily to be nostd compliant

// Setup the protobuf specs
pub mod specs;

#[cfg(test)]
mod tests;

use crate::hash::Digest;

use core::convert::{TryFrom, TryInto};
use protobuf::MessageField;

const DIRECTION_BLINDING_FACTOR: u32 = 0x000Fu32;

/// An error converting a protobuf proof
#[derive(Debug, Eq, PartialEq)]
pub enum ConversionError {
    /// Error deserializing from a protobuf structure/proof
    Deserialization(String),
    /// A core protobuf error occurred
    Protobuf(String),
}

impl From<protobuf::Error> for ConversionError {
    fn from(err: protobuf::Error) -> Self {
        Self::Protobuf(format!(
            "An error occurred in protobuf serialization/deserialization {}",
            err
        ))
    }
}

impl core::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            ConversionError::Deserialization(msg) => format!("(Deserialization) - {}", msg),
            ConversionError::Protobuf(msg) => format!("(Protobuf) - {}", msg),
        };
        write!(f, "Type conversion error {}", code)
    }
}

// ************************ Converter macros ************************ //

// Protobuf best practice says everything should be `optional` to ensure
// maximum backwards compatibility. This helper function ensures an optional
// field is present in a particular interface version.
macro_rules! require {
    ($obj:ident, $has_field:ident) => {
        if !$obj.$has_field() {
            return Err(ConversionError::Deserialization(format!(
                "Required field {} missing. '{}'",
                stringify!($obj).to_string(),
                stringify!($has_field).to_string(),
            )));
        }
    };
}

macro_rules! require_messagefield {
    ($obj:ident, $field:ident) => {
        if $obj.$field.is_none() {
            return Err(ConversionError::Deserialization(format!(
                "Required field {} missing. '{}'",
                stringify!($obj).to_string(),
                stringify!($field).to_string(),
            )));
        }
    };
}

macro_rules! hash_from_bytes {
    ($obj:expr) => {{
        crate::hash::try_parse_digest($obj).map_err(Self::Error::Deserialization)?
    }};
}

macro_rules! convert_from_vector {
    ($obj:expr, $expected_type:ty) => {{
        let mut data: Vec<$expected_type> = vec![];
        for item in $obj.iter() {
            data.push(item.try_into()?);
        }
        data
    }};
}

// ==============================================================
// NodeLabel
// ==============================================================

fn encode_minimum_label(v: &[u8; 32]) -> Vec<u8> {
    if let Some(last_non_zero) = v.iter().rposition(|b| *b != 0) {
        v[..=last_non_zero].to_vec()
    } else {
        Vec::new()
    }
}

fn decode_minimized_label(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..v.len()].copy_from_slice(v);
    out
}

impl From<&crate::NodeLabel> for specs::types::NodeLabel {
    fn from(input: &crate::NodeLabel) -> Self {
        Self {
            label_len: Some(input.label_len),
            label_val: Some(encode_minimum_label(&input.label_val)),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::NodeLabel> for crate::NodeLabel {
    type Error = ConversionError;

    fn try_from(input: &specs::types::NodeLabel) -> Result<Self, Self::Error> {
        require!(input, has_label_len);
        require!(input, has_label_val);
        let label_val = decode_minimized_label(input.label_val());

        Ok(Self {
            label_len: input.label_len(),
            label_val,
        })
    }
}

// ==============================================================
// Node
// ==============================================================

impl From<&crate::Node> for specs::types::Node {
    fn from(input: &crate::Node) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            hash: Some(input.hash.to_vec()),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::Node> for crate::Node {
    type Error = ConversionError;

    fn try_from(input: &specs::types::Node) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        require!(input, has_hash);
        let label: crate::NodeLabel = input.label.as_ref().unwrap().try_into()?;

        // get the raw data & it's length, but at most crate::hash::DIGEST_BYTES bytes
        let out_val = hash_from_bytes!(input.hash());

        Ok(Self {
            label,
            hash: out_val,
        })
    }
}

// ==============================================================
// LayerProof
// ==============================================================

impl From<&crate::LayerProof> for specs::types::LayerProof {
    fn from(input: &crate::LayerProof) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            siblings: input.siblings.iter().map(|s| s.into()).collect::<Vec<_>>(),
            direction: Some(input.direction as u32),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::LayerProof> for crate::LayerProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::LayerProof) -> Result<Self, Self::Error> {
        require!(input, has_direction);
        require_messagefield!(input, label);
        let label: crate::NodeLabel = input.label.as_ref().unwrap().try_into()?;

        // get the raw data & it's length, but at most crate::hash::DIGEST_BYTES bytes
        let sibling = input.siblings.get(0);
        if sibling.is_none() {
            return Err(ConversionError::Deserialization(
                "Required field siblings missing".to_string(),
            ));
        }

        // blind out the highest bits to all 0's, since we're pulling it down to a u8
        let direction = (input.direction() & DIRECTION_BLINDING_FACTOR) as u8;

        Ok(Self {
            label,
            siblings: [sibling.unwrap().try_into()?],
            direction: crate::types::Direction::try_from(direction)
                .map_err(ConversionError::Deserialization)?,
        })
    }
}

// ==============================================================
// MembershipProof
// ==============================================================

impl From<&crate::MembershipProof> for specs::types::MembershipProof {
    fn from(input: &crate::MembershipProof) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            hash_val: Some(input.hash_val.to_vec()),
            layer_proofs: input
                .layer_proofs
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::MembershipProof> for crate::MembershipProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::MembershipProof) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        require!(input, has_hash_val);

        let label: crate::NodeLabel = input.label.as_ref().unwrap().try_into()?;
        let hash_val: Digest = hash_from_bytes!(input.hash_val());

        let mut layer_proofs = vec![];
        for proof in input.layer_proofs.iter() {
            layer_proofs.push(proof.try_into()?);
        }

        Ok(Self {
            label,
            hash_val,
            layer_proofs,
        })
    }
}

// ==============================================================
// NonMembershipProof
// ==============================================================

impl From<&crate::NonMembershipProof> for specs::types::NonMembershipProof {
    fn from(input: &crate::NonMembershipProof) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            longest_prefix: MessageField::some((&input.longest_prefix).into()),
            longest_prefix_children: input
                .longest_prefix_children
                .iter()
                .map(|child| child.into())
                .collect::<Vec<_>>(),
            longest_prefix_membership_proof: MessageField::some(
                (&input.longest_prefix_membership_proof).into(),
            ),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::NonMembershipProof> for crate::NonMembershipProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::NonMembershipProof) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        require_messagefield!(input, longest_prefix);
        require_messagefield!(input, longest_prefix_membership_proof);

        let label: crate::NodeLabel = input.label.as_ref().unwrap().try_into()?;
        let longest_prefix: crate::NodeLabel = input.longest_prefix.as_ref().unwrap().try_into()?;
        let longest_prefix_membership_proof: crate::MembershipProof = input
            .longest_prefix_membership_proof
            .as_ref()
            .unwrap()
            .try_into()?;

        let mut longest_prefix_children = vec![];
        for child in input.longest_prefix_children.iter() {
            longest_prefix_children.push(child.try_into()?);
        }

        Ok(Self {
            label,
            longest_prefix,
            longest_prefix_children: longest_prefix_children.try_into().map_err(|_| {
                ConversionError::Deserialization(
                    "Required field longest_prefix_children must be 2 elements long".to_string(),
                )
            })?,
            longest_prefix_membership_proof,
        })
    }
}

// ==============================================================
// LookupProof
// ==============================================================

impl From<&crate::LookupProof> for specs::types::LookupProof {
    fn from(input: &crate::LookupProof) -> Self {
        Self {
            epoch: Some(input.epoch),
            plaintext_value: Some(input.plaintext_value.0.clone()),
            version: Some(input.version),
            existence_vrf_proof: Some(input.existence_vrf_proof.clone()),
            existence_proof: MessageField::some((&input.existence_proof).into()),
            marker_vrf_proof: Some(input.marker_vrf_proof.clone()),
            marker_proof: MessageField::some((&input.marker_proof).into()),
            freshness_vrf_proof: Some(input.freshness_vrf_proof.clone()),
            freshness_proof: MessageField::some((&input.freshness_proof).into()),
            commitment_proof: Some(input.commitment_proof.clone()),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::LookupProof> for crate::LookupProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::LookupProof) -> Result<Self, Self::Error> {
        require!(input, has_epoch);
        require!(input, has_plaintext_value);
        require!(input, has_version);
        require!(input, has_existence_vrf_proof);
        require_messagefield!(input, existence_proof);
        require!(input, has_marker_vrf_proof);
        require_messagefield!(input, marker_proof);
        require!(input, has_freshness_vrf_proof);
        require_messagefield!(input, freshness_proof);
        require!(input, has_commitment_proof);

        Ok(Self {
            epoch: input.epoch(),
            plaintext_value: crate::AkdValue(input.plaintext_value().to_vec()),
            version: input.version(),
            existence_vrf_proof: input.existence_vrf_proof().to_vec(),
            existence_proof: input.existence_proof.as_ref().unwrap().try_into()?,
            marker_vrf_proof: input.marker_vrf_proof().to_vec(),
            marker_proof: input.marker_proof.as_ref().unwrap().try_into()?,
            freshness_vrf_proof: input.freshness_vrf_proof().to_vec(),
            freshness_proof: input.freshness_proof.as_ref().unwrap().try_into()?,
            commitment_proof: input.commitment_proof().to_vec(),
        })
    }
}

// ==============================================================
// UpdateProof
// ==============================================================

impl From<&crate::UpdateProof> for specs::types::UpdateProof {
    fn from(input: &crate::UpdateProof) -> Self {
        Self {
            epoch: Some(input.epoch),
            plaintext_value: Some(input.plaintext_value.0.clone()),
            version: Some(input.version),
            existence_vrf_proof: Some(input.existence_vrf_proof.clone()),
            existence_at_ep: MessageField::some((&input.existence_at_ep).into()),
            previous_version_vrf_proof: input.previous_version_vrf_proof.as_ref().cloned(),
            previous_version_stale_at_ep: MessageField::from_option(
                input
                    .previous_version_stale_at_ep
                    .as_ref()
                    .map(|p| p.into()),
            ),
            commitment_proof: Some(input.commitment_proof.clone()),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::UpdateProof> for crate::UpdateProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::UpdateProof) -> Result<Self, Self::Error> {
        require!(input, has_epoch);
        require!(input, has_plaintext_value);
        require!(input, has_version);
        require!(input, has_existence_vrf_proof);
        require_messagefield!(input, existence_at_ep);
        require!(input, has_commitment_proof);
        let previous_version_vrf_proof = input
            .previous_version_vrf_proof
            .as_ref()
            .map(|item| item.to_vec());
        let previous_version_stale_at_ep: Option<crate::MembershipProof> = input
            .previous_version_stale_at_ep
            .as_ref()
            .map(|item| item.try_into())
            .transpose()?;

        Ok(Self {
            epoch: input.epoch(),
            plaintext_value: crate::AkdValue(input.plaintext_value().to_vec()),
            version: input.version(),
            existence_vrf_proof: input.existence_vrf_proof().to_vec(),
            existence_at_ep: input.existence_at_ep.as_ref().unwrap().try_into()?,
            previous_version_vrf_proof,
            previous_version_stale_at_ep,
            commitment_proof: input.commitment_proof().to_vec(),
        })
    }
}

// ==============================================================
// HistoryProof
// ==============================================================

impl From<&crate::HistoryProof> for specs::types::HistoryProof {
    fn from(input: &crate::HistoryProof) -> Self {
        Self {
            update_proofs: input
                .update_proofs
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            next_few_vrf_proofs: input.next_few_vrf_proofs.to_vec(),
            non_existence_of_next_few: input
                .non_existence_of_next_few
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            future_marker_vrf_proofs: input.future_marker_vrf_proofs.to_vec(),
            non_existence_of_future_markers: input
                .non_existence_of_future_markers
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::HistoryProof> for crate::HistoryProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::HistoryProof) -> Result<Self, Self::Error> {
        let update_proofs = convert_from_vector!(input.update_proofs, crate::UpdateProof);

        let next_few_vrf_proofs = input
            .next_few_vrf_proofs
            .iter()
            .map(|item| item.to_vec())
            .collect::<Vec<_>>();
        let non_existence_of_next_few =
            convert_from_vector!(input.non_existence_of_next_few, crate::NonMembershipProof);

        let future_marker_vrf_proofs = input
            .future_marker_vrf_proofs
            .iter()
            .map(|item| item.to_vec())
            .collect::<Vec<_>>();
        let non_existence_of_future_markers = convert_from_vector!(
            input.non_existence_of_future_markers,
            crate::NonMembershipProof
        );

        Ok(Self {
            update_proofs,
            next_few_vrf_proofs,
            non_existence_of_next_few,
            future_marker_vrf_proofs,
            non_existence_of_future_markers,
        })
    }
}

// ==============================================================
// SingleAppendOnlyProof
// ==============================================================

impl From<&crate::SingleAppendOnlyProof> for specs::types::SingleAppendOnlyProof {
    fn from(input: &crate::SingleAppendOnlyProof) -> Self {
        Self {
            inserted: input
                .inserted
                .iter()
                .map(|node| node.into())
                .collect::<Vec<_>>(),
            unchanged_nodes: input
                .unchanged_nodes
                .iter()
                .map(|node| node.into())
                .collect::<Vec<_>>(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::SingleAppendOnlyProof> for crate::SingleAppendOnlyProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::SingleAppendOnlyProof) -> Result<Self, Self::Error> {
        let inserted = convert_from_vector!(input.inserted, crate::Node);
        let unchanged_nodes = convert_from_vector!(input.unchanged_nodes, crate::Node);
        Ok(Self {
            inserted,
            unchanged_nodes,
        })
    }
}

// ==============================================================
// SingleAppendOnlyProof
// ==============================================================

impl From<&crate::AppendOnlyProof> for specs::types::AppendOnlyProof {
    fn from(input: &crate::AppendOnlyProof) -> Self {
        Self {
            proofs: input
                .proofs
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            epochs: input.epochs.clone(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::AppendOnlyProof> for crate::AppendOnlyProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::AppendOnlyProof) -> Result<Self, Self::Error> {
        let proofs = input
            .proofs
            .iter()
            .map(|proof| proof.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let epochs = input.epochs.clone();
        Ok(Self { proofs, epochs })
    }
}
