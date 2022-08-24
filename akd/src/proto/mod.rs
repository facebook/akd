// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains all the type conversions between internal AKD & message types
//! with the protobuf types
//!
//! Additionally it supports the conversion between the output from the `Directory` to
//! public-storage safe blob types encoded with Protobuf. Download and upload
//! to the blob storage medium is left to the new application crate akd_local_auditor

use crate::errors::AkdError;
use protobuf::Message;
use protobuf::ProtobufError;
use protobuf::RepeatedField;
use std::convert::{TryFrom, TryInto};

pub mod audit;
// Forget the generics, we're hardcoding to blake3
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
type Hasher = Blake3_256<BaseElement>;
type Digest = <Blake3_256<BaseElement> as winter_crypto::Hasher>::Digest;

// ************************ Converters ************************ //

// Protobuf best practice says everything should be `optional` to ensure
// maximum back-compatibility. This helper function ensures an optional
// field is present in a particular interface version.
macro_rules! require {
    ($obj:ident, $has_field:ident) => {
        if !$obj.$has_field() {
            return Err(format!(
                "Condition {}.{}() failed.",
                stringify!($obj),
                stringify!($has_field)
            ));
        }
    };
}

macro_rules! hash_to_bytes {
    ($obj:expr) => {
        crate::serialization::from_digest::<Hasher>($obj).to_vec()
    };
}

macro_rules! hash_from_bytes {
    ($obj:expr) => {
        crate::serialization::to_digest::<Hasher>($obj)
            .map_err(|_| "Failed to convert bytes to digest".to_string())?
    };
}

// ==============================================================
// NodeLabel
// ==============================================================

impl From<&crate::NodeLabel> for audit::NodeLabel {
    fn from(input: &crate::NodeLabel) -> Self {
        let mut result = Self::new();
        result.set_label_len(input.label_len);
        result.set_label_val(input.label_val.to_vec());
        result
    }
}

impl TryFrom<&audit::NodeLabel> for crate::NodeLabel {
    type Error = String;

    fn try_from(input: &audit::NodeLabel) -> Result<Self, Self::Error> {
        require!(input, has_label_len);
        require!(input, has_label_val);
        // get the raw data & it's length, but at most 32 bytes
        let raw = input.get_label_val();
        let len = std::cmp::min(raw.len(), 32);
        // construct the output buffer
        let mut out_val = [0u8; 32];
        // copy into the output buffer the raw data up to the computed length
        out_val[..len].clone_from_slice(&raw[..len]);

        Ok(crate::NodeLabel {
            label_len: input.get_label_len(),
            label_val: out_val,
        })
    }
}

// ==============================================================
// Node
// ==============================================================

impl From<&crate::helper_structs::Node<Hasher>> for audit::Node {
    fn from(input: &crate::helper_structs::Node<Hasher>) -> Self {
        let mut result = Self::new();
        result.set_label((&input.label).into());
        result.set_hash(hash_to_bytes!(input.hash));
        result
    }
}

impl TryFrom<&audit::Node> for crate::helper_structs::Node<Hasher> {
    type Error = String;

    fn try_from(input: &audit::Node) -> Result<Self, Self::Error> {
        require!(input, has_label);
        require!(input, has_hash);
        let label: crate::NodeLabel = input.get_label().try_into()?;
        Ok(crate::helper_structs::Node::<Hasher> {
            label,
            hash: hash_from_bytes!(input.get_hash()),
        })
    }
}

impl From<&crate::proof_structs::SingleAppendOnlyProof<Hasher>> for audit::SingleEncodedProof {
    fn from(input: &crate::proof_structs::SingleAppendOnlyProof<Hasher>) -> Self {
        let mut result = Self::new();
        let inserted = input
            .inserted
            .iter()
            .map(|item| item.into())
            .collect::<Vec<_>>();
        let unchanged = input
            .unchanged_nodes
            .iter()
            .map(|item| item.into())
            .collect::<Vec<_>>();

        result.set_inserted(RepeatedField::from_vec(inserted));
        result.set_unchanged(RepeatedField::from_vec(unchanged));
        result
    }
}

impl TryFrom<audit::SingleEncodedProof> for crate::proof_structs::SingleAppendOnlyProof<Hasher> {
    type Error = String;

    fn try_from(input: audit::SingleEncodedProof) -> Result<Self, Self::Error> {
        let mut inserted = vec![];
        let mut unchanged = vec![];
        for item in input.get_inserted() {
            inserted.push(item.try_into()?);
        }
        for item in input.get_unchanged() {
            unchanged.push(item.try_into()?);
        }
        Ok(crate::proof_structs::SingleAppendOnlyProof {
            inserted,
            unchanged_nodes: unchanged,
        })
    }
}

// ************************ Helper Functions ************************ //

const NAME_SEPARATOR: char = '/';

/// The constructed blobs with naming encoding the
/// blob name = "EPOCH/PREVIOUS_ROOT_HASH/CURRENT_ROOT_HASH"
pub struct AuditBlob {
    /// The name of the blob, which can be decomposed into logical components (phash, chash, epoch)
    pub name: String,
    /// The binary data comprising the blob contents
    pub data: Vec<u8>,
}

impl AuditBlob {
    fn convert_akd_err(err: AkdError) -> String {
        err.to_string()
    }

    /// Decompose the blob's name into the (previous_hash, current_hash, epoch) tuple
    pub fn decompose_name(name: &str) -> Result<(Digest, Digest, u64), String> {
        let parts = name.split(NAME_SEPARATOR).collect::<Vec<_>>();
        if parts.len() < 3 {
            return Err(String::from(
                "Name is malformed, there are not enough components to reconstruct!",
            ));
        }
        let epoch: u64 = parts[0]
            .parse()
            .map_err(|_| format!("Failed to parse {} into an unsigned integer", parts[0]))?;
        let previous_epoch = crate::serialization::to_digest::<Hasher>(
            &hex::decode(parts[1])
                .map_err(|_| format!("Failed to parse {} as a hex string into bytes", parts[1]))?,
        )
        .map_err(Self::convert_akd_err)?;
        let current_epoch = crate::serialization::to_digest::<Hasher>(
            &hex::decode(parts[2])
                .map_err(|_| format!("Failed to parse {} as a hex string into bytes", parts[2]))?,
        )
        .map_err(Self::convert_akd_err)?;

        Ok((previous_epoch, current_epoch, epoch))
    }

    /// Construct a new AuditBlob from the internal structures, which is ready to be written to persistent storage
    pub fn build(
        previous_hash: Digest,
        current_hash: Digest,
        epoch: u64,
        proof: &crate::proof_structs::SingleAppendOnlyProof<Hasher>,
    ) -> Result<AuditBlob, ProtobufError> {
        let phash_bytes = crate::serialization::from_digest::<Hasher>(previous_hash);
        let chash_bytes = crate::serialization::from_digest::<Hasher>(current_hash);
        let name = format!(
            "{}{}{}{}{}",
            epoch,
            NAME_SEPARATOR,
            hex::encode(phash_bytes),
            NAME_SEPARATOR,
            hex::encode(chash_bytes)
        );
        let proto: audit::SingleEncodedProof = proof.into();

        Ok(AuditBlob {
            name,
            data: proto.write_to_bytes()?,
        })
    }

    /// Decode a protobuf encoded AuditBlob into it's components (phash, chash, epoch, proof)
    pub fn decode(
        &self,
    ) -> Result<
        (
            Digest,
            Digest,
            u64,
            crate::proof_structs::SingleAppendOnlyProof<Hasher>,
        ),
        String,
    > {
        let proof: audit::SingleEncodedProof =
            protobuf::parse_from_bytes(&self.data).map_err(|pbuf| {
                format!(
                    "Error deserializating protobuf encoded SingleAppendOnlyProof: {}",
                    pbuf
                )
            })?;
        let (phash, chash, epoch) = Self::decompose_name(&self.name)?;
        let local_proof: Result<crate::proof_structs::SingleAppendOnlyProof<Hasher>, String> =
            proof.try_into();

        Ok((phash, chash, epoch, local_proof?))
    }
}

/// Convert an append-only proof to "Audit Blobs" which are to be stored in a publically readable storage medium
/// suitable for public auditing
pub fn generate_audit_blobs(
    hashes: Vec<Digest>,
    proof: crate::proof_structs::AppendOnlyProof<Hasher>,
) -> Result<Vec<AuditBlob>, String> {
    if proof.epochs.len() + 1 != hashes.len() {
        return Err(format!(
            "The proof has a different number of epochs than needed for hashes.
            The number of hashes you provide should be one more than the number of epochs!
            Number of epochs = {}, number of hashes = {}",
            proof.epochs.len(),
            hashes.len()
        ));
    }

    if proof.epochs.len() != proof.proofs.len() {
        return Err(format!(
            "The proof has {} epochs and {} proofs. These should be equal!",
            proof.epochs.len(),
            proof.proofs.len()
        ));
    }

    let mut results = Vec::with_capacity(proof.proofs.len());

    for i in 0..hashes.len() - 1 {
        let previous_hash = hashes[i];
        let current_hash = hashes[i + 1];
        // use the destination epoch, so each proof validates the period (T-1, T)
        let epoch = proof.epochs[i] + 1;

        let blob = AuditBlob::build(previous_hash, current_hash, epoch, &proof.proofs[i])
            .map_err(|pbuf| format!("Protobuf error serializing AuditBlob {}", pbuf))?;
        results.push(blob);
    }

    Ok(results)
}