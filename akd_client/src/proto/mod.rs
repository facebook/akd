// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the type conversions between internal AKD & message types
//! with the protobuf types

use protobuf::MessageField;
use std::convert::{TryFrom, TryInto};

pub mod types;

#[cfg(test)]
mod tests;

// ************************ Converter macros ************************ //

// Protobuf best practice says everything should be `optional` to ensure
// maximum backwards compatibility. This helper function ensures an optional
// field is present in a particular interface version.
macro_rules! require {
    ($obj:ident, $has_field:ident) => {
        if !$obj.$has_field() {
            return Err(crate::VerificationError::build(
                Some(crate::VerificationErrorType::ProofDeserializationFailed),
                Some(format!(
                    "Required field {} missing. '{}'",
                    stringify!($obj).to_string(),
                    stringify!($has_field).to_string(),
                )),
            ));
        }
    };
}

macro_rules! require_messagefield {
    ($obj:ident, $field:ident) => {
        if !$obj.$field.is_some() {
            return Err(crate::VerificationError::build(
                Some(crate::VerificationErrorType::ProofDeserializationFailed),
                Some(format!(
                    "Required field {} missing. '{}'",
                    stringify!($obj).to_string(),
                    stringify!($field).to_string(),
                )),
            ));
        }
    };
}

macro_rules! hash_from_bytes {
    ($obj:expr) => {{
        // get the raw data & it's length, but at most crate::hash::DIGEST_BYTES bytes
        let len = std::cmp::min($obj.len(), crate::hash::DIGEST_BYTES);
        // construct the output buffer
        let mut out_val = [0u8; crate::hash::DIGEST_BYTES];
        // copy into the output buffer the raw data up to the computed length
        out_val[..len].clone_from_slice(&$obj[..len]);
        out_val
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

impl From<&crate::NodeLabel> for types::NodeLabel {
    fn from(input: &crate::NodeLabel) -> Self {
        Self {
            label_len: Some(input.label_len),
            label_val: Some(input.label_val.to_vec()),
            ..Default::default()
        }
    }
}

impl TryFrom<&types::NodeLabel> for crate::NodeLabel {
    type Error = crate::VerificationError;

    fn try_from(input: &types::NodeLabel) -> Result<Self, Self::Error> {
        require!(input, has_label_len);
        require!(input, has_label_val);
        // get the raw data & it's length, but at most 32 bytes
        let raw = input.label_val();
        let len = std::cmp::min(raw.len(), 32);
        // construct the output buffer
        let mut out_val = [0u8; 32];
        // copy into the output buffer the raw data up to the computed length
        out_val[..len].clone_from_slice(&raw[..len]);

        Ok(Self {
            label_len: input.label_len(),
            label_val: out_val,
        })
    }
}

// ==============================================================
// Node
// ==============================================================

impl From<&crate::Node> for types::Node {
    fn from(input: &crate::Node) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            hash: Some(input.hash.to_vec()),
            ..Default::default()
        }
    }
}

impl TryFrom<&types::Node> for crate::Node {
    type Error = crate::VerificationError;

    fn try_from(input: &types::Node) -> Result<Self, Self::Error> {
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

impl From<&crate::LayerProof> for types::LayerProof {
    fn from(input: &crate::LayerProof) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            siblings: input.siblings.iter().map(|s| s.into()).collect::<Vec<_>>(),
            direction: input.direction.map(|i| i as u32),
            ..Default::default()
        }
    }
}

impl TryFrom<&types::LayerProof> for crate::LayerProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::LayerProof) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        let label: crate::NodeLabel = input.label.as_ref().unwrap().try_into()?;

        // get the raw data & it's length, but at most crate::hash::DIGEST_BYTES bytes
        let sibling = input.siblings.get(0);
        if sibling.is_none() {
            return Err(crate::VerificationError::build(
                Some(crate::VerificationErrorType::ProofDeserializationFailed),
                Some("Required field siblings missing".to_string()),
            ));
        }

        let direction = input.direction.map(|i| i as usize);

        Ok(Self {
            label,
            siblings: [sibling.unwrap().try_into()?],
            direction,
        })
    }
}

// ==============================================================
// MembershipProof
// ==============================================================

impl From<&crate::MembershipProof> for types::MembershipProof {
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

impl TryFrom<&types::MembershipProof> for crate::MembershipProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::MembershipProof) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        require!(input, has_hash_val);

        let label: crate::NodeLabel = input.label.as_ref().unwrap().try_into()?;
        let hash_val: crate::Digest = hash_from_bytes!(input.hash_val());

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

impl From<&crate::NonMembershipProof> for types::NonMembershipProof {
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

impl TryFrom<&types::NonMembershipProof> for crate::NonMembershipProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::NonMembershipProof) -> Result<Self, Self::Error> {
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
                crate::VerificationError::build(
                    Some(crate::VerificationErrorType::ProofDeserializationFailed),
                    Some(
                        "Required field longest_prefix_children must be 2 elements long"
                            .to_string(),
                    ),
                )
            })?,
            longest_prefix_membership_proof,
        })
    }
}

// ==============================================================
// LookupProof
// ==============================================================

impl From<&crate::LookupProof> for types::LookupProof {
    fn from(input: &crate::LookupProof) -> Self {
        Self {
            epoch: Some(input.epoch),
            plaintext_value: Some(input.plaintext_value.clone()),
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

impl TryFrom<&types::LookupProof> for crate::LookupProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::LookupProof) -> Result<Self, Self::Error> {
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
            plaintext_value: input.plaintext_value().to_vec(),
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

impl From<&crate::UpdateProof> for types::UpdateProof {
    fn from(input: &crate::UpdateProof) -> Self {
        Self {
            epoch: Some(input.epoch),
            plaintext_value: Some(input.plaintext_value.clone()),
            version: Some(input.version),
            existence_vrf_proof: Some(input.existence_vrf_proof.clone()),
            existence_at_ep: MessageField::some((&input.existence_at_ep).into()),
            previous_version_vrf_proof: input
                .previous_version_vrf_proof
                .as_ref()
                .map(|p| p.clone()),
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

impl TryFrom<&types::UpdateProof> for crate::UpdateProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::UpdateProof) -> Result<Self, Self::Error> {
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
        let previous_version_stale_at_ep: Option<crate::MembershipProof> =
            if let Some(item) = input.previous_version_stale_at_ep.as_ref() {
                Some(item.try_into()?)
            } else {
                None
            };

        Ok(Self {
            epoch: input.epoch(),
            plaintext_value: input.plaintext_value().to_vec(),
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

impl From<&crate::HistoryProof> for types::HistoryProof {
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

impl TryFrom<&types::HistoryProof> for crate::HistoryProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::HistoryProof) -> Result<Self, Self::Error> {
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
