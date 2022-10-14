// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the type conversions between internal AKD & message types
//! with the protobuf types

use protobuf::RepeatedField;
use std::convert::{TryFrom, TryInto};

pub mod types;

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
        for item in $obj {
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
        let mut result = Self::new();
        result.set_label_len(input.label_len);
        result.set_label_val(input.label_val.to_vec());
        result
    }
}

impl TryFrom<&types::NodeLabel> for crate::NodeLabel {
    type Error = crate::VerificationError;

    fn try_from(input: &types::NodeLabel) -> Result<Self, Self::Error> {
        require!(input, has_label_len);
        require!(input, has_label_val);
        // get the raw data & it's length, but at most 32 bytes
        let raw = input.get_label_val();
        let len = std::cmp::min(raw.len(), 32);
        // construct the output buffer
        let mut out_val = [0u8; 32];
        // copy into the output buffer the raw data up to the computed length
        out_val[..len].clone_from_slice(&raw[..len]);

        Ok(Self {
            label_len: input.get_label_len(),
            label_val: out_val,
        })
    }
}

// ==============================================================
// Node
// ==============================================================

impl From<&crate::Node> for types::Node {
    fn from(input: &crate::Node) -> Self {
        let mut result = Self::new();
        result.set_label((&input.label).into());
        result.set_hash(input.hash.to_vec());
        result
    }
}

impl TryFrom<&types::Node> for crate::Node {
    type Error = crate::VerificationError;

    fn try_from(input: &types::Node) -> Result<Self, Self::Error> {
        require!(input, has_label);
        require!(input, has_hash);
        let label: crate::NodeLabel = input.get_label().try_into()?;

        // get the raw data & it's length, but at most crate::hash::DIGEST_BYTES bytes
        let out_val = hash_from_bytes!(input.get_hash());

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
        let mut result = Self::new();
        result.set_label((&input.label).into());
        let siblings = input.siblings.iter().map(|s| s.into()).collect::<Vec<_>>();
        result.set_siblings(RepeatedField::from_vec(siblings));
        if let Some(direction) = input.direction {
            result.set_direction(direction as u32);
        } else {
            result.clear_direction();
        }
        result
    }
}

impl TryFrom<&types::LayerProof> for crate::LayerProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::LayerProof) -> Result<Self, Self::Error> {
        require!(input, has_label);
        let label: crate::NodeLabel = input.get_label().try_into()?;

        // get the raw data & it's length, but at most crate::hash::DIGEST_BYTES bytes
        let raw = input.get_siblings();
        let sibling = raw.get(0);
        if sibling.is_none() {
            return Err(crate::VerificationError::build(
                Some(crate::VerificationErrorType::ProofDeserializationFailed),
                Some("Required field siblings missing".to_string()),
            ));
        }

        let direction = if input.has_direction() {
            Some(input.get_direction() as usize)
        } else {
            None
        };

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
        let mut result = Self::new();
        result.set_label((&input.label).into());
        result.set_hash_val(input.hash_val.to_vec());
        let proofs = input
            .layer_proofs
            .iter()
            .map(|proof| proof.into())
            .collect::<Vec<_>>();
        result.set_layer_proofs(RepeatedField::from_vec(proofs));

        result
    }
}

impl TryFrom<&types::MembershipProof> for crate::MembershipProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::MembershipProof) -> Result<Self, Self::Error> {
        require!(input, has_label);
        require!(input, has_hash_val);

        let label: crate::NodeLabel = input.get_label().try_into()?;
        let hash_val: crate::Digest = hash_from_bytes!(input.get_hash_val());

        let mut layer_proofs = vec![];
        for proof in input.get_layer_proofs() {
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
        let mut result = Self::new();
        result.set_label((&input.label).into());
        result.set_longest_prefix((&input.longest_prefix).into());
        let longest_prefix_children = input
            .longest_prefix_children
            .iter()
            .map(|child| child.into())
            .collect::<Vec<_>>();
        result.set_longest_prefix_children(RepeatedField::from_vec(longest_prefix_children));
        result.set_longest_prefix_membership_proof((&input.longest_prefix_membership_proof).into());
        result
    }
}

impl TryFrom<&types::NonMembershipProof> for crate::NonMembershipProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::NonMembershipProof) -> Result<Self, Self::Error> {
        require!(input, has_label);
        require!(input, has_longest_prefix);
        require!(input, has_longest_prefix_membership_proof);

        let label: crate::NodeLabel = input.get_label().try_into()?;
        let longest_prefix: crate::NodeLabel = input.get_longest_prefix().try_into()?;
        let longest_prefix_membership_proof: crate::MembershipProof =
            input.get_longest_prefix_membership_proof().try_into()?;

        let mut longest_prefix_children = vec![];
        for child in input.get_longest_prefix_children() {
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
        let mut result = Self::new();
        result.set_epoch(input.epoch);
        result.set_plaintext_value(input.plaintext_value.clone());
        result.set_version(input.version);
        result.set_existence_vrf_proof(input.existence_vrf_proof.clone());
        result.set_existence_proof((&input.existence_proof).into());
        result.set_marker_vrf_proof(input.marker_vrf_proof.clone());
        result.set_marker_proof((&input.marker_proof).into());
        result.set_freshness_vrf_proof(input.freshness_vrf_proof.clone());
        result.set_freshness_proof((&input.freshness_proof).into());
        result.set_commitment_proof(input.commitment_proof.clone());
        result
    }
}

impl TryFrom<&types::LookupProof> for crate::LookupProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::LookupProof) -> Result<Self, Self::Error> {
        require!(input, has_epoch);
        require!(input, has_plaintext_value);
        require!(input, has_version);
        require!(input, has_existence_vrf_proof);
        require!(input, has_existence_proof);
        require!(input, has_marker_vrf_proof);
        require!(input, has_marker_proof);
        require!(input, has_freshness_vrf_proof);
        require!(input, has_freshness_proof);
        require!(input, has_commitment_proof);

        Ok(Self {
            epoch: input.get_epoch(),
            plaintext_value: input.get_plaintext_value().to_vec(),
            version: input.get_version(),
            existence_vrf_proof: input.get_existence_vrf_proof().to_vec(),
            existence_proof: input.get_existence_proof().try_into()?,
            marker_vrf_proof: input.get_marker_vrf_proof().to_vec(),
            marker_proof: input.get_marker_proof().try_into()?,
            freshness_vrf_proof: input.get_freshness_vrf_proof().to_vec(),
            freshness_proof: input.get_freshness_proof().try_into()?,
            commitment_proof: input.get_commitment_proof().to_vec(),
        })
    }
}

// ==============================================================
// UpdateProof
// ==============================================================

impl From<&crate::UpdateProof> for types::UpdateProof {
    fn from(input: &crate::UpdateProof) -> Self {
        let mut result = Self::new();
        result.set_epoch(input.epoch);
        result.set_plaintext_value(input.plaintext_value.clone());
        result.set_version(input.version);
        result.set_existence_vrf_proof(input.existence_vrf_proof.clone());
        result.set_existence_at_ep((&input.existence_at_ep).into());
        if let Some(value) = &input.previous_version_vrf_proof {
            result.set_previous_version_vrf_proof(value.clone());
        } else {
            result.clear_previous_version_vrf_proof();
        }
        if let Some(value) = &input.previous_version_stale_at_ep {
            result.set_previous_version_stale_at_ep(value.into());
        } else {
            result.clear_previous_version_stale_at_ep();
        }
        result.set_commitment_proof(input.commitment_proof.clone());
        result
    }
}

impl TryFrom<&types::UpdateProof> for crate::UpdateProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::UpdateProof) -> Result<Self, Self::Error> {
        require!(input, has_epoch);
        require!(input, has_plaintext_value);
        require!(input, has_version);
        require!(input, has_existence_vrf_proof);
        require!(input, has_existence_at_ep);
        require!(input, has_commitment_proof);

        let previous_version_vrf_proof: Option<Vec<u8>> = if input.has_previous_version_vrf_proof()
        {
            Some(input.get_previous_version_vrf_proof().to_vec())
        } else {
            None
        };
        let previous_version_stale_at_ep: Option<crate::MembershipProof> =
            if input.has_previous_version_stale_at_ep() {
                Some(input.get_previous_version_stale_at_ep().try_into()?)
            } else {
                None
            };

        Ok(Self {
            epoch: input.get_epoch(),
            plaintext_value: input.get_plaintext_value().to_vec(),
            version: input.get_version(),
            existence_vrf_proof: input.get_existence_vrf_proof().to_vec(),
            existence_at_ep: input.get_existence_at_ep().try_into()?,
            previous_version_vrf_proof,
            previous_version_stale_at_ep,
            commitment_proof: input.get_commitment_proof().to_vec(),
        })
    }
}

// ==============================================================
// HistoryProof
// ==============================================================

impl From<&crate::HistoryProof> for types::HistoryProof {
    fn from(input: &crate::HistoryProof) -> Self {
        let mut result = Self::new();

        let update_proofs = input
            .update_proofs
            .iter()
            .map(|proof| proof.into())
            .collect::<Vec<_>>();
        result.set_update_proofs(RepeatedField::from_vec(update_proofs));

        let next_few_vrf_proofs = input.next_few_vrf_proofs.to_vec();
        result.set_next_few_vrf_proofs(RepeatedField::from_vec(next_few_vrf_proofs));

        let non_existence_of_next_few = input
            .non_existence_of_next_few
            .iter()
            .map(|proof| proof.into())
            .collect::<Vec<_>>();
        result.set_non_existence_of_next_few(RepeatedField::from_vec(non_existence_of_next_few));

        let future_marker_vrf_proofs = input.future_marker_vrf_proofs.to_vec();
        result.set_future_marker_vrf_proofs(RepeatedField::from_vec(future_marker_vrf_proofs));

        let non_existence_of_future_markers = input
            .non_existence_of_future_markers
            .iter()
            .map(|proof| proof.into())
            .collect::<Vec<_>>();
        result.set_non_existence_of_future_markers(RepeatedField::from_vec(
            non_existence_of_future_markers,
        ));

        result
    }
}

impl TryFrom<&types::HistoryProof> for crate::HistoryProof {
    type Error = crate::VerificationError;

    fn try_from(input: &types::HistoryProof) -> Result<Self, Self::Error> {
        let update_proofs = convert_from_vector!(input.get_update_proofs(), crate::UpdateProof);

        let next_few_vrf_proofs = input
            .get_next_few_vrf_proofs()
            .iter()
            .map(|item| item.to_vec())
            .collect::<Vec<_>>();
        let non_existence_of_next_few = convert_from_vector!(
            input.get_non_existence_of_next_few(),
            crate::NonMembershipProof
        );

        let future_marker_vrf_proofs = input
            .get_future_marker_vrf_proofs()
            .iter()
            .map(|item| item.to_vec())
            .collect::<Vec<_>>();
        let non_existence_of_future_markers = convert_from_vector!(
            input.get_non_existence_of_future_markers(),
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
