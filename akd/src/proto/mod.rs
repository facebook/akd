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
use thiserror::Error;

pub mod audit;
// Forget the generics, we're hardcoding to blake3
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
type Hasher = Blake3_256<BaseElement>;
type Digest = <Blake3_256<BaseElement> as winter_crypto::Hasher>::Digest;

/// Local audit processing errors
#[derive(Error, Debug)]
pub enum LocalAuditorError {
    /// An error parsing the blob name to/from a string
    #[error("Audit blob name parse error {0}")]
    NameParseError(String),
    /// An AKD error occurred converting bytes to digest's
    #[error("Serialization error {0:?}")]
    Serialization(#[from] AkdError),
    /// A protobuf error decoding the audit proof
    #[error("Protobuf conversion error {0:?}")]
    Protobuf(#[from] ProtobufError),
    /// A required protobuf field was missing
    #[error("Condition {0}.{0}() failed.")]
    RequiredFieldMissing(String, String),
}

// ************************ Converters ************************ //

// Protobuf best practice says everything should be `optional` to ensure
// maximum backwards compatibility. This helper function ensures an optional
// field is present in a particular interface version.
macro_rules! require {
    ($obj:ident, $has_field:ident) => {
        if !$obj.$has_field() {
            return Err(LocalAuditorError::RequiredFieldMissing(
                stringify!($obj).to_string(),
                stringify!($has_field).to_string(),
            ));
        }
    };
}

macro_rules! hash_to_bytes {
    ($obj:expr) => {
        crate::serialization::from_digest::<Hasher>($obj)
    };
}

macro_rules! hash_from_bytes {
    ($obj:expr) => {
        crate::serialization::to_digest::<Hasher>($obj).map_err(LocalAuditorError::Serialization)?
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
    type Error = LocalAuditorError;

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
        result.set_hash(hash_to_bytes!(input.hash).to_vec());
        result
    }
}

impl TryFrom<&audit::Node> for crate::helper_structs::Node<Hasher> {
    type Error = LocalAuditorError;

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
    type Error = LocalAuditorError;

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

/// Represents the NAME of an audit blob and can be
/// flatted to/from a string
#[derive(Clone, Debug)]
pub struct AuditBlobName {
    /// The epoch this audit proof is related to
    pub epoch: u64,
    /// The previous root hash from `&self.epoch - 1`
    pub previous_hash: [u8; 32],
    /// The current updated root hash
    pub current_hash: [u8; 32],
}

impl std::string::ToString for AuditBlobName {
    fn to_string(&self) -> String {
        let previous_hash = hex::encode(self.previous_hash);
        let current_hash = hex::encode(self.current_hash);
        format!(
            "{}{}{}{}{}",
            self.epoch, NAME_SEPARATOR, previous_hash, NAME_SEPARATOR, current_hash
        )
    }
}

impl TryFrom<String> for AuditBlobName {
    type Error = LocalAuditorError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        let parts = name.split(NAME_SEPARATOR).collect::<Vec<_>>();
        if parts.len() < 3 {
            return Err(LocalAuditorError::NameParseError(
                "Name is malformed, there are not enough components to reconstruct!".to_string(),
            ));
        }
        // PART[0] = EPOCH
        let epoch: u64 = parts[0].parse().map_err(|_| {
            LocalAuditorError::NameParseError(format!("Failed to parse '{}' into an u64", parts[0]))
        })?;

        // PART[1] = PREVIOUS_HASH
        let previous_hash_bytes = hex::decode(parts[1]).map_err(|hex_err| {
            LocalAuditorError::NameParseError(format!(
                "Failed to decode previous hash from hex string: {}",
                hex_err
            ))
        })?;
        let previous_hash = hash_from_bytes!(&previous_hash_bytes);

        // PART[2] = CURRENT_HASH
        let current_hash_bytes = hex::decode(parts[2]).map_err(|hex_err| {
            LocalAuditorError::NameParseError(format!(
                "Failed to decode current hash from hex string: {}",
                hex_err
            ))
        })?;
        let current_hash = hash_from_bytes!(&current_hash_bytes);

        Ok(AuditBlobName {
            epoch,
            current_hash: hash_to_bytes!(current_hash),
            previous_hash: hash_to_bytes!(previous_hash),
        })
    }
}

/// The constructed blobs with naming encoding the
/// blob name = "EPOCH/PREVIOUS_ROOT_HASH/CURRENT_ROOT_HASH"
pub struct AuditBlob {
    /// The name of the blob, which can be decomposed into logical components (phash, chash, epoch)
    pub name: AuditBlobName,
    /// The binary data comprising the blob contents
    pub data: Vec<u8>,
}

impl AuditBlob {
    /// Construct a new AuditBlob from the internal structures, which is ready to be written to persistent storage
    pub fn new(
        previous_hash: Digest,
        current_hash: Digest,
        epoch: u64,
        proof: &crate::proof_structs::SingleAppendOnlyProof<Hasher>,
    ) -> Result<AuditBlob, ProtobufError> {
        let name = AuditBlobName {
            epoch,
            previous_hash: hash_to_bytes!(previous_hash),
            current_hash: hash_to_bytes!(current_hash),
        };
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
            u64,
            Digest,
            Digest,
            crate::proof_structs::SingleAppendOnlyProof<Hasher>,
        ),
        LocalAuditorError,
    > {
        let proof: audit::SingleEncodedProof = protobuf::parse_from_bytes(&self.data)?;

        let local_proof: Result<
            crate::proof_structs::SingleAppendOnlyProof<Hasher>,
            LocalAuditorError,
        > = proof.try_into();

        Ok((
            self.name.epoch,
            hash_from_bytes!(&self.name.previous_hash),
            hash_from_bytes!(&self.name.current_hash),
            local_proof?,
        ))
    }
}

/// Convert an append-only proof to "Audit Blobs" which are to be stored in a publicly readable storage medium
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

        let blob = AuditBlob::new(previous_hash, current_hash, epoch, &proof.proofs[i])
            .map_err(|pbuf| format!("Protobuf error serializing AuditBlob {}", pbuf))?;
        results.push(blob);
    }

    Ok(results)
}
