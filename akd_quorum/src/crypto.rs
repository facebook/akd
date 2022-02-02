// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains the cryptographic operations which need to be
//! performed, including storage & retrieval of private cryptographic operations
//!
//! NOTE: Instead of Shamir secret sharing, we may want to look into
//! threshold signatures (e.g. https://github.com/poanetwork/threshold_crypto)
//! which will avoid the need to ever reconstruct the private key while maintaining
//! a public key which can be used to verify the signatures from a consensus of the network
//! HOWEVER if we remain within a secure context when reconstructing the shards and generating
//! the signed commitment, then we should be safe from exploit. Moving to a public
//! participation might require an adjustment to this.
//!
//! Additionally it is unclear if threshold signatures can be adjusted after they are
//! initially created. Which is a requirement for mutation of the quorum set.

use crate::comms::{NodeId, Nonce};
use crate::storage::QuorumCommitment;
use crate::QuorumOperationError;

use async_trait::async_trait;
use shamirsecretsharing::{combine_shares, create_shares, DATA_SIZE, SHARE_SIZE};
use std::convert::TryInto;
use winter_crypto::Hasher;

// =====================================================
// Consts and Typedefs
// =====================================================

/// The multiplicitave factor of DATA_SIZE which denotes the size of the
/// quorum key. Probably should be a factor of 2
pub(crate) const QUORUM_KEY_NUM_PARTS: usize = 8;

/// The size of the quorum key private key in bytes.
/// NOTE: SSS's DATA_SIZE = 64 bytes, which the quorum key private key
/// need to be a multiple of
pub const QUORUM_KEY_SIZE: usize = QUORUM_KEY_NUM_PARTS * DATA_SIZE;

// =====================================================
// Structs
// =====================================================

/// Represents the node's "shard" of the secret quorum's private
/// signing key. A single shard cannot be utilized to reconstruct the
/// full quorum key.
///
/// Due to limitations of the Shamir's Secret Sharing lib, we are constrained
/// to break the secret information into batches of DATA_SIZE _exactly_ to generate
/// the shards. This means that to support a key bigger than DATA_SIZE, we need to
/// have multiple shards for each slice of the secret information.
#[derive(PartialEq, Debug)]
pub struct QuorumKeyShard {
    pub(crate) components: [[u8; SHARE_SIZE]; QUORUM_KEY_NUM_PARTS],
}

impl Clone for QuorumKeyShard {
    fn clone(&self) -> Self {
        Self {
            components: self.components,
        }
    }
}

impl QuorumKeyShard {
    pub(crate) fn build_from_vec_vec_vec(
        data: Vec<Vec<Vec<u8>>>,
    ) -> Result<Vec<Self>, QuorumOperationError> {
        let mut results = vec![];

        for shards in data.into_iter() {
            let mut formatted_shards: Vec<[u8; SHARE_SIZE]> = vec![];
            for shard in shards.into_iter() {
                formatted_shards.push(shard.try_into().map_err(|_| {
                    QuorumOperationError::Sharding(format!(
                        "Unable to convert shard vec into array of len {}",
                        DATA_SIZE
                    ))
                })?)
            }
            let formatted_shard = Self {
                components: formatted_shards.try_into().map_err(|_| QuorumOperationError::Sharding(format!("Unable to format vector of shards into quorum key shard struct with {} components", QUORUM_KEY_NUM_PARTS)))?
            };
            results.push(formatted_shard);
        }

        Ok(results)
    }

    /// Flatten the crypto shard into a single array of the components in-order
    pub fn flatten(&self) -> [u8; SHARE_SIZE * QUORUM_KEY_NUM_PARTS] {
        let mut data = [0u8; SHARE_SIZE * QUORUM_KEY_NUM_PARTS];
        for part_i in 0..QUORUM_KEY_NUM_PARTS {
            data[part_i * SHARE_SIZE..(part_i + 1) * SHARE_SIZE]
                .clone_from_slice(&self.components[part_i]);
        }
        data
    }

    /// Inflate a decrypted crypto shard from the flattened components
    pub fn inflate(
        raw: [u8; SHARE_SIZE * QUORUM_KEY_NUM_PARTS],
    ) -> Result<Self, QuorumOperationError> {
        let mut components = [[0u8; SHARE_SIZE]; QUORUM_KEY_NUM_PARTS];

        for part_i in 0..QUORUM_KEY_NUM_PARTS {
            let slice = raw[part_i * SHARE_SIZE..(part_i + 1) * SHARE_SIZE].to_vec();
            components[part_i] = slice.try_into().map_err(|_| {
                QuorumOperationError::Sharding(
                    "Unable to deserialize raw binary vec to QuorumKeyShard".to_string(),
                )
            })?;
        }

        Ok(Self { components })
    }
}

/// Represents an encrypted quorum key shard which is encrypted with
/// the public key of the reliant party. These shards cannot be decoded in
/// user-space, and must be handled WITHIN the crypto layer such that they
/// public key cannot be reconstructed by "non secure" memory. The private key
/// which can decrpyt the shards is the node's "transient" key used for communication
/// channels, and never is exposed outside of the cryptographer service
#[derive(Clone)]
pub struct EncryptedQuorumKeyShard {
    /// The flattened QuorumKeyShard components are encrypted
    /// using the leader's public key and can only be
    /// reconstructed within the secure layer such that the
    /// encrypted shard components must be passed within
    /// the secure crypto layer to be reconstructed and generate a
    /// commitment
    pub payload: Vec<u8>,
}

// =====================================================
// Trait definitions
// =====================================================

/// Represents the cryptographic operations which the node needs to execute
/// within a secure context (e.g. HSM)
#[async_trait]
pub trait QuorumCryptographer: Send + Sync + Clone {
    // ==================================================================
    // To be implemented
    // ==================================================================

    /// Retrieve the public key of this quorum node
    async fn retrieve_public_key(&self) -> Result<Vec<u8>, QuorumOperationError>;

    /// Retrieve the public key of the Quorum Key
    async fn retrieve_qk_public_key(&self) -> Result<Vec<u8>, QuorumOperationError>;

    /// Retrieve this node's shard of the quorum key from persistent secure storage
    async fn retrieve_qk_shard(
        &self,
        node_id: NodeId,
    ) -> Result<EncryptedQuorumKeyShard, QuorumOperationError>;

    /// Save this node's shard of the quorum key to persistent secure storage
    async fn update_qk_shard(
        &self,
        shard: EncryptedQuorumKeyShard,
    ) -> Result<(), QuorumOperationError>;

    /// Generate the encrypted shards for nodes [0, node_public_keys.len()) encrypted with the public keys of the nodes.
    /// The provided shards are the quorum key shards, encrypted with THIS node's public key as the leader.
    async fn generate_encrypted_shards(
        &self,
        shards: Vec<EncryptedQuorumKeyShard>,
        node_public_keys: Vec<Vec<u8>>,
    ) -> Result<Vec<EncryptedQuorumKeyShard>, QuorumOperationError>;

    /// Encrypt the given material using the provided public key, optionally with the provided nonce
    async fn encrypt_message(
        &self,
        public_key: Vec<u8>,
        material: Vec<u8>,
        nonce: Nonce,
    ) -> Result<Vec<u8>, QuorumOperationError>;

    /// Decrypt the specified message utilizing this node's
    /// private key. This will require that the message contain
    /// a nonce. I.e. this cannot be used to decrypt the encrypted
    /// shard partials
    async fn decrypt_message(
        &self,
        material: Vec<u8>,
    ) -> Result<(Vec<u8>, Nonce), QuorumOperationError>;

    /// Generate a commitment on the epoch changes using the quorum key
    async fn generate_commitment<H: Hasher>(
        &self,
        quorum_key_shards: Vec<EncryptedQuorumKeyShard>,
        epoch: u64,
        previous_hash: H::Digest,
        current_hash: H::Digest,
    ) -> Result<QuorumCommitment<H>, QuorumOperationError>;

    /// Validate the commitment applied on the specified epoch settings
    async fn validate_commitment<H: Hasher>(
        public_key: Vec<u8>,
        commitment: QuorumCommitment<H>,
    ) -> Result<bool, QuorumOperationError>;

    // ==================================================================
    // Common trait logic
    // ==================================================================

    /// Get the number of shards required to reconstruct the quorum key
    fn shards_required(n: u8) -> u8 {
        let f = if (n - 1) % 3 == 0 {
            (n - 1) / 3
        } else {
            // there's remainders
            1 + (n - 1) / 3
        };
        2 * f + 1
    }

    /// Generate num_shards shards of the quorum key, and return the shard pieces.
    /// We take ownership of the quorum key here to help prevent leakage of the key.
    /// By taking ownership, someone needs to explicitely clone it to use it elsewhere
    fn generate_shards(
        quorum_key: [u8; QUORUM_KEY_SIZE],
        num_shards: u8,
    ) -> Result<Vec<QuorumKeyShard>, QuorumOperationError> {
        let num_approvals = Self::shards_required(num_shards);

        let mut parts = vec![vec![]; num_shards.into()];

        for i in 0..QUORUM_KEY_NUM_PARTS {
            let part: [u8; DATA_SIZE] = quorum_key[i * DATA_SIZE..(i + 1) * DATA_SIZE]
                .try_into()
                .map_err(|_| {
                QuorumOperationError::Sharding(format!(
                    "Unable to convert quorum key slice into SSS shardable component of len {}",
                    DATA_SIZE
                ))
            })?;
            let results = create_shares(&part, num_shards, num_approvals)?;
            for node_i in 0..num_shards {
                let idx: usize = node_i.into();
                match results.get(idx) {
                    None => {
                        return Err(QuorumOperationError::Sharding(format!(
                            "Resulting shards did not have an shard at entry {}",
                            node_i
                        )));
                    }
                    Some(part) => {
                        parts[idx].push(part.clone());
                    }
                }
            }
        }

        let formatted_shards = QuorumKeyShard::build_from_vec_vec_vec(parts)?;
        Ok(formatted_shards)
    }

    /// Reconstruct the quorum key from a specific collection of shards
    fn reconstruct_shards(
        shards: Vec<QuorumKeyShard>,
    ) -> Result<[u8; QUORUM_KEY_SIZE], QuorumOperationError> {
        let mut potential_result = [0u8; QUORUM_KEY_SIZE];
        // there should be QUORUM_KEY_NUM_PARTS in each shard
        for i in 0..QUORUM_KEY_NUM_PARTS {
            let part_i = shards
                .iter()
                .map(|shard| shard.components[i].to_vec())
                .collect::<Vec<_>>();
            let some_key = combine_shares(&part_i)?;
            if let Some(key) = some_key {
                let deconstructed_partial: [u8; DATA_SIZE] = key.try_into().map_err(|_| QuorumOperationError::Sharding(format!("Reconstructing the quorum key resulted in an invalid key length. It _MUST_ be of length {} bytes", DATA_SIZE)))?;
                potential_result[i * DATA_SIZE..(i + 1) * DATA_SIZE]
                    .clone_from_slice(&deconstructed_partial);
            } else {
                return Err(QuorumOperationError::Sharding(
                    "Sharding request to recombine shares resulted in no constructed quorum key"
                        .to_string(),
                ));
            }
        }
        Ok(potential_result)
    }
}

#[cfg(test)]
mod crypto_tests {
    use super::{
        EncryptedQuorumKeyShard, QuorumCryptographer, QuorumKeyShard, QUORUM_KEY_NUM_PARTS,
        QUORUM_KEY_SIZE,
    };
    use crate::comms::{NodeId, Nonce};
    use crate::storage::QuorumCommitment;
    use crate::QuorumOperationError;

    use async_trait::async_trait;
    use rand::{seq::IteratorRandom, thread_rng, Rng};
    use shamirsecretsharing::SHARE_SIZE;
    use std::convert::TryInto;
    use winter_crypto::Hasher;

    #[derive(Clone)]
    struct TestCryptographer;

    #[async_trait]
    impl QuorumCryptographer for TestCryptographer {
        async fn retrieve_public_key(&self) -> Result<Vec<u8>, QuorumOperationError> {
            unimplemented!();
        }

        async fn retrieve_qk_public_key(&self) -> Result<Vec<u8>, QuorumOperationError> {
            unimplemented!();
        }

        async fn retrieve_qk_shard(
            &self,
            _node_id: NodeId,
        ) -> Result<EncryptedQuorumKeyShard, QuorumOperationError> {
            unimplemented!();
        }

        async fn update_qk_shard(
            &self,
            _shard: EncryptedQuorumKeyShard,
        ) -> Result<(), QuorumOperationError> {
            unimplemented!();
        }

        async fn generate_encrypted_shards(
            &self,
            _shards: Vec<EncryptedQuorumKeyShard>,
            _node_public_keys: Vec<Vec<u8>>,
        ) -> Result<Vec<EncryptedQuorumKeyShard>, QuorumOperationError> {
            unimplemented!();
        }

        async fn encrypt_message(
            &self,
            _public_key: Vec<u8>,
            _material: Vec<u8>,
            _nonce: Nonce,
        ) -> Result<Vec<u8>, QuorumOperationError> {
            unimplemented!();
        }

        async fn decrypt_message(
            &self,
            _material: Vec<u8>,
        ) -> Result<(Vec<u8>, Nonce), QuorumOperationError> {
            unimplemented!();
        }

        async fn generate_commitment<H: Hasher>(
            &self,
            _quorum_key_shards: Vec<EncryptedQuorumKeyShard>,
            _epoch: u64,
            _previous_hash: H::Digest,
            _current_hash: H::Digest,
        ) -> Result<QuorumCommitment<H>, QuorumOperationError> {
            unimplemented!();
        }

        async fn validate_commitment<H: Hasher>(
            _public_key: Vec<u8>,
            _commitment: QuorumCommitment<H>,
        ) -> Result<bool, QuorumOperationError> {
            unimplemented!();
        }
    }

    #[test]
    fn test_shard_generation_and_reconstruction() {
        let data: [u8; QUORUM_KEY_SIZE] = [42; QUORUM_KEY_SIZE];
        let shards = TestCryptographer::generate_shards(data, 7).unwrap();
        assert_eq!(7, shards.len());

        // all shards should be fine
        let construction_ok = TestCryptographer::reconstruct_shards(shards.to_vec());
        assert_eq!(Ok(data), construction_ok);

        // using 5 shards should be fine, given a factor of 2 in f
        let construction_ok = TestCryptographer::reconstruct_shards(shards[0..5].to_vec());
        assert_eq!(Ok(data), construction_ok);

        // using a random subset of shards of size <= 4 should fail
        let mut rng = thread_rng();
        for _ in 1..5 {
            let sample = shards.clone().into_iter().choose_multiple(&mut rng, 4);
            let construction_fail = TestCryptographer::reconstruct_shards(sample);
            assert!(construction_fail.is_err());
        }
    }

    #[test]
    fn test_quorum_shard_serialize_deserialize() {
        let mut rng = rand::thread_rng();
        let mut components = [[0u8; SHARE_SIZE]; QUORUM_KEY_NUM_PARTS];
        for i in 0..QUORUM_KEY_NUM_PARTS {
            let bytes: [u8; SHARE_SIZE] = (0..SHARE_SIZE)
                .map(|_| rng.gen::<u8>())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            components[i] = bytes;
        }
        let shard = QuorumKeyShard { components };

        let flat = shard.flatten();
        assert_eq!(SHARE_SIZE * QUORUM_KEY_NUM_PARTS, flat.len());

        let inflated = QuorumKeyShard::inflate(flat).unwrap();
        assert_eq!(shard, inflated);
    }
}
