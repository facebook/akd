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
