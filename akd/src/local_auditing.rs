// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains all the type conversions between internal AKD & message types
//! with the protobuf types
//!
//! Additionally it supports the conversion between the output from the `Directory` to
//! public-storage safe blob types encoded with Protobuf. Download and upload
//! to the blob storage medium is left to the new application crate akd_local_auditor

use crate::Digest;
use protobuf::Message;
use std::convert::{TryFrom, TryInto};

/// Local audit processing errors
#[derive(Debug)]
pub enum LocalAuditorError {
    /// An error parsing the blob name to/from a string
    NameParseError(String),
    /// An error between the lengths of hashes + proofs
    MisMatchedLengths(String),
    /// A conversion error occurred
    ConversionError(akd_core::proto::ConversionError),
}

impl From<akd_core::proto::ConversionError> for LocalAuditorError {
    fn from(err: akd_core::proto::ConversionError) -> Self {
        Self::ConversionError(err)
    }
}

impl From<protobuf::Error> for LocalAuditorError {
    fn from(err: protobuf::Error) -> Self {
        Self::ConversionError(err.into())
    }
}

// ************************ Converters ************************ //

macro_rules! hash_from_ref {
    ($obj:expr) => {
        crate::hash::try_parse_digest($obj)
            .map_err(akd_core::proto::ConversionError::Deserialization)
    };
}

// ************************ Helper Functions ************************ //

const NAME_SEPARATOR: char = '/';

/// Represents the NAME of an audit blob and can be
/// flatted to/from a string
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default, Copy)]
pub struct AuditBlobName {
    /// The epoch this audit proof is related to
    pub epoch: u64,
    /// The previous root hash from `&self.epoch - 1`
    pub previous_hash: Digest,
    /// The current updated root hash
    pub current_hash: Digest,
}

impl std::fmt::Display for AuditBlobName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let previous_hash = hex::encode(self.previous_hash);
        let current_hash = hex::encode(self.current_hash);
        write!(
            f,
            "{}{}{}{}{}",
            self.epoch, NAME_SEPARATOR, previous_hash, NAME_SEPARATOR, current_hash
        )
    }
}

impl TryFrom<&str> for AuditBlobName {
    type Error = LocalAuditorError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
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
                "Failed to decode previous hash from hex string: {hex_err}"
            ))
        })?;
        let previous_hash = hash_from_ref!(&previous_hash_bytes)?;

        // PART[2] = CURRENT_HASH
        let current_hash_bytes = hex::decode(parts[2]).map_err(|hex_err| {
            LocalAuditorError::NameParseError(format!(
                "Failed to decode current hash from hex string: {hex_err}"
            ))
        })?;
        let current_hash = hash_from_ref!(&current_hash_bytes)?;

        Ok(AuditBlobName {
            epoch,
            current_hash,
            previous_hash,
        })
    }
}

/// The constructed blobs with naming encoding the
/// blob name = "EPOCH/PREVIOUS_ROOT_HASH/CURRENT_ROOT_HASH"
#[derive(Clone)]
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
        proof: &crate::SingleAppendOnlyProof,
    ) -> Result<AuditBlob, LocalAuditorError> {
        let name = AuditBlobName {
            epoch,
            previous_hash,
            current_hash,
        };
        let proto: akd_core::proto::specs::types::SingleAppendOnlyProof = proof.into();

        Ok(AuditBlob {
            name,
            data: proto.write_to_bytes()?,
        })
    }

    /// Decode a protobuf encoded AuditBlob into it's components (phash, chash, epoch, proof)
    pub fn decode(
        &self,
    ) -> Result<(u64, Digest, Digest, crate::SingleAppendOnlyProof), LocalAuditorError> {
        let proof =
            akd_core::proto::specs::types::SingleAppendOnlyProof::parse_from_bytes(&self.data)?;
        let local_proof: crate::SingleAppendOnlyProof = (&proof).try_into()?;

        Ok((
            self.name.epoch,
            hash_from_ref!(&self.name.previous_hash)?,
            hash_from_ref!(&self.name.current_hash)?,
            local_proof,
        ))
    }
}

/// Convert an append-only proof to "Audit Blobs" which are to be stored in a publicly readable storage medium
/// suitable for public auditing
pub fn generate_audit_blobs(
    hashes: Vec<Digest>,
    proof: crate::AppendOnlyProof,
) -> Result<Vec<AuditBlob>, LocalAuditorError> {
    if proof.epochs.len() + 1 != hashes.len() {
        return Err(LocalAuditorError::MisMatchedLengths(format!(
            "The proof has a different number of epochs than needed for hashes.
            The number of hashes you provide should be one more than the number of epochs!
            Number of epochs = {}, number of hashes = {}",
            proof.epochs.len(),
            hashes.len()
        )));
    }

    if proof.epochs.len() != proof.proofs.len() {
        return Err(LocalAuditorError::MisMatchedLengths(format!(
            "The proof has {} epochs and {} proofs. These should be equal!",
            proof.epochs.len(),
            proof.proofs.len()
        )));
    }

    let mut results = Vec::with_capacity(proof.proofs.len());

    for i in 0..hashes.len() - 1 {
        let previous_hash = hashes[i];
        let current_hash = hashes[i + 1];
        // The epoch provided is the source epoch, i.e. the proof is validating from (T, T+1)
        let epoch = proof.epochs[i];

        let blob = AuditBlob::new(previous_hash, current_hash, epoch, &proof.proofs[i])?;
        results.push(blob);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::{AuditBlobName, LocalAuditorError};
    use std::convert::TryInto;

    #[test]
    fn test_audit_proof_naming_conventions() -> Result<(), LocalAuditorError> {
        let expected_name = "54/0101010101010101010101010101010101010101010101010101010101010101/0000000000000000000000000000000000000000000000000000000000000000";

        let blob_name = AuditBlobName {
            current_hash: crate::hash::EMPTY_DIGEST,
            previous_hash: [1u8; crate::hash::DIGEST_BYTES],
            epoch: 54,
        };

        let name = blob_name.to_string();
        assert_ne!(String::new(), name);

        assert_eq!(expected_name.to_string(), blob_name.to_string());

        let blob_name_ref: &str = name.as_ref();
        let decomposed: AuditBlobName = blob_name_ref.try_into()?;
        assert_eq!(blob_name, decomposed);
        Ok(())
    }
}
