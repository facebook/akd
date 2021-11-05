// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of an append-only zero knowledge set
use crate::{
    errors::HistoryTreeNodeError,
    history_tree_node::*,
    proof_structs::{AppendOnlyProof, MembershipProof, NonMembershipProof},
    storage::{Storable, V2Storage},
};

use crate::serialization::to_digest;

use crate::storage::types::StorageType;
use crate::{errors::*, history_tree_node::HistoryTreeNode, node_state::*, ARITY, *};
use async_recursion::async_recursion;
use std::marker::{PhantomData, Send, Sync};
use winter_crypto::Hasher;

use serde::{Deserialize, Serialize};

use keyed_priority_queue::{Entry, KeyedPriorityQueue};

/// The default azks key
pub const DEFAULT_AZKS_KEY: u8 = 1u8;
/// An append-only zero knowledge set, the data structure used to efficiently implement
/// a auditable key directory.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Azks<H> {
    /// The location of the root
    pub root: usize,
    /// The latest complete epoch
    pub latest_epoch: u64,
    /// The number of nodes ie the size of this tree
    pub num_nodes: usize, // The size of the tree
    /// Placeholder
    pub _h: PhantomData<H>,
}

impl<H: Hasher> Storable for Azks<H> {
    type Key = u8;

    fn data_type() -> StorageType {
        StorageType::Azks
    }

    fn get_id(&self) -> u8 {
        1u8
    }
}

unsafe impl<H: Hasher> Sync for Azks<H> {}

impl<H: Hasher> Clone for Azks<H> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            latest_epoch: self.latest_epoch,
            num_nodes: self.num_nodes,
            _h: PhantomData,
        }
    }
}

impl<H: Hasher + Send + Sync> Azks<H> {
    /// Creates a new azks
    pub async fn new<S: V2Storage + Sync + Send>(storage: &S) -> Result<Self, AkdError> {
        let root = get_empty_root::<H, S>(storage, Option::Some(0)).await?;
        let azks = Azks {
            root: 0,
            latest_epoch: 0,
            num_nodes: 1,
            _h: PhantomData,
        };

        root.write_to_storage(storage).await?;

        Ok(azks)
    }

    /// Inserts a single leaf and is only used for testing, since batching is more efficient.
    /// We just want to make sure batch insertions work correctly and this function is useful for that.
    pub async fn insert_leaf<S: V2Storage + Sync + Send>(
        &mut self,
        storage: &S,
        label: NodeLabel,
        value: H::Digest,
    ) -> Result<(), AkdError> {
        // Calls insert_single_leaf on the root node and updates the root and tree_nodes
        self.increment_epoch();

        let new_leaf =
            get_leaf_node::<H, S>(storage, label, 0, value.as_ref(), 0, self.latest_epoch).await?;

        let mut root_node = HistoryTreeNode::get_from_storage(storage, NodeKey(self.root)).await?;
        root_node
            .insert_single_leaf(storage, new_leaf, self.latest_epoch, &mut self.num_nodes)
            .await?;

        Ok(())
    }

    /// Insert a batch of new leaves
    pub async fn batch_insert_leaves<S: V2Storage + Sync + Send>(
        &mut self,
        storage: &S,
        insertion_set: Vec<(NodeLabel, H::Digest)>,
    ) -> Result<(), AkdError> {
        self.batch_insert_leaves_helper(storage, insertion_set, false)
            .await
    }

    /// An azks is built both by the [crate::directory::Directory] and the auditor.
    /// However, both constructions have very minor differences, and the append_only_usage
    /// bool keeps track of this.
    pub async fn batch_insert_leaves_helper<S: V2Storage + Sync + Send>(
        &mut self,
        storage: &S,
        insertion_set: Vec<(NodeLabel, H::Digest)>,
        append_only_usage: bool,
    ) -> Result<(), AkdError> {
        self.increment_epoch();

        let mut hash_q = KeyedPriorityQueue::<usize, i32>::new();
        let mut priorities: i32 = 0;
        let mut root_node = HistoryTreeNode::get_from_storage(storage, NodeKey(self.root)).await?;
        for (label, value) in insertion_set {
            let new_leaf_loc = self.num_nodes;

            let mut new_leaf =
                get_leaf_node::<H, S>(storage, label, 0, value.as_ref(), 0, self.latest_epoch)
                    .await?;
            if append_only_usage {
                new_leaf = get_leaf_node_without_hashing::<H, S>(
                    storage,
                    label,
                    0,
                    value,
                    0,
                    self.latest_epoch,
                )
                .await?;
            }

            root_node
                .insert_leaf(storage, new_leaf, self.latest_epoch, &mut self.num_nodes)
                .await?;

            hash_q.push(new_leaf_loc, priorities);
            priorities -= 1;
        }

        while !hash_q.is_empty() {
            let (next_node_loc, _) = hash_q
                .pop()
                .ok_or(AzksError::PopFromEmptyPriorityQueue(self.latest_epoch))?;

            let mut next_node: HistoryTreeNode<H> =
                HistoryTreeNode::get_from_storage(storage, NodeKey(next_node_loc)).await?;

            next_node.update_hash(storage, self.latest_epoch).await?;

            if !next_node.is_root() {
                match hash_q.entry(next_node.parent) {
                    Entry::Vacant(entry) => {
                        entry.set_priority(priorities);
                    }
                    Entry::Occupied(entry) => {
                        entry.set_priority(priorities);
                    }
                };

                priorities -= 1;
            }
        }
        Ok(())
    }

    /// Returns the Merkle membership proof for the trie as it stood at epoch
    // Assumes the verifier has access to the root at epoch
    pub async fn get_membership_proof<S: V2Storage + Sync + Send>(
        &self,
        storage: &S,
        label: NodeLabel,
        epoch: u64,
    ) -> Result<MembershipProof<H>, AkdError> {
        let (pf, _) = self
            .get_membership_proof_and_node(storage, label, epoch)
            .await?;
        Ok(pf)
    }

    /// In a compressed trie, the proof consists of the longest prefix
    /// of the label that is included in the trie, as well as its children, to show that
    /// none of the children is equal to the given label.
    pub async fn get_non_membership_proof<S: V2Storage + Sync + Send>(
        &self,
        storage: &S,
        label: NodeLabel,
        epoch: u64,
    ) -> Result<NonMembershipProof<H>, AkdError> {
        let (longest_prefix_membership_proof, lcp_node_id) = self
            .get_membership_proof_and_node(storage, label, epoch)
            .await?;
        let lcp_node: HistoryTreeNode<H> =
            HistoryTreeNode::get_from_storage(storage, NodeKey(lcp_node_id)).await?;
        let longest_prefix = lcp_node.label;
        let mut longest_prefix_children_labels = [NodeLabel::new(0, 0); ARITY];
        let mut longest_prefix_children_values = [H::hash(&[]); ARITY];
        let state = lcp_node.get_state_at_epoch(storage, epoch).await?;

        for (i, child) in state.child_states.iter().enumerate() {
            let unwrapped_child: HistoryTreeNode<H> =
                HistoryTreeNode::get_from_storage(storage, NodeKey(child.location)).await?;
            longest_prefix_children_labels[i] = unwrapped_child.label;
            longest_prefix_children_values[i] = unwrapped_child
                .get_value_without_label_at_epoch(storage, epoch)
                .await?;
        }
        Ok(NonMembershipProof {
            label,
            longest_prefix,
            longest_prefix_children_labels,
            longest_prefix_children_values,
            longest_prefix_membership_proof,
        })
    }

    /// An append-only proof for going from `start_epoch` to `end_epoch` consists of roots of subtrees
    /// the azks tree that remain unchanged from `start_epoch` to `end_epoch` and the leaves inserted into the
    /// tree after `start_epoch` and  up until `end_epoch`.
    /// If there is no errors, this function returns an `Ok` result, containing the
    ///  append-only proof and otherwise, it returns a [errors::AkdError].
    ///
    /// **RESTRICTIONS**: Note that `start_epoch` and `end_epoch` are valid only when the following are true
    /// * `start_epoch` <= `end_epoch`
    /// * `start_epoch` and `end_epoch` are both existing epochs of this AZKS
    pub async fn get_append_only_proof<S: V2Storage + Sync + Send>(
        &self,
        storage: &S,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyProof<H>, AkdError> {
        // Suppose the epochs start_epoch and end_epoch exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.
        let node = HistoryTreeNode::get_from_storage(storage, NodeKey(self.root)).await?;
        let (unchanged, leaves) = self
            .get_append_only_proof_helper(storage, node, start_epoch, end_epoch)
            .await?;
        Ok(AppendOnlyProof {
            inserted: leaves,
            unchanged_nodes: unchanged,
        })
    }

    #[async_recursion]
    async fn get_append_only_proof_helper<S: V2Storage + Sync + Send>(
        &self,
        storage: &S,
        node: HistoryTreeNode<H>,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyHelper<H::Digest>, AkdError> {
        let mut unchanged = Vec::<(NodeLabel, H::Digest)>::new();
        let mut leaves = Vec::<(NodeLabel, H::Digest)>::new();
        if node.get_latest_epoch()? <= start_epoch {
            if node.is_root() {
                // this is the case where the root is unchanged since the last epoch
                return Ok((unchanged, leaves));
            }

            unchanged.push((
                node.label,
                node.get_value_without_label_at_epoch(storage, node.get_latest_epoch()?)
                    .await?,
            ));
            return Ok((unchanged, leaves));
        }
        if node.get_birth_epoch() > end_epoch {
            // really you shouldn't even be here. Later do error checking
            return Ok((unchanged, leaves));
        }
        if node.is_leaf() {
            leaves.push((
                node.label,
                node.get_value_without_label_at_epoch(storage, node.get_latest_epoch()?)
                    .await?,
            ));
        } else {
            for child_node_state in node
                .get_state_at_epoch(storage, end_epoch)
                .await?
                .child_states
                .iter()
                .map(|x| x.clone())
            {
                if child_node_state.dummy_marker == DummyChildState::Dummy {
                    continue;
                } else {
                    let child_node = HistoryTreeNode::get_from_storage(
                        storage,
                        NodeKey(child_node_state.location),
                    )
                    .await?;
                    let mut rec_output = self
                        .get_append_only_proof_helper(storage, child_node, start_epoch, end_epoch)
                        .await?;
                    unchanged.append(&mut rec_output.0);
                    leaves.append(&mut rec_output.1);
                }
            }
        }
        Ok((unchanged, leaves))
    }

    // FIXME: these functions below should be moved into higher-level API
    /// Gets the root hash for this azks
    pub async fn get_root_hash<S: V2Storage + Sync + Send>(
        &self,
        storage: &S,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        self.get_root_hash_at_epoch(storage, self.get_latest_epoch())
            .await
    }

    /// Gets the root hash of the tree at a epoch.
    /// Since this is accessing the root node and the root node exists at all epochs that
    /// the azks does, this would never be called at an epoch before the birth of the root node.
    pub async fn get_root_hash_at_epoch<S: V2Storage + Sync + Send>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<H::Digest, HistoryTreeNodeError> {
        let root_node: HistoryTreeNode<H> =
            HistoryTreeNode::get_from_storage(storage, NodeKey(self.root)).await?;
        root_node.get_value_at_epoch(storage, epoch).await
    }

    /// Gets the latest epoch of this azks. If an update aka epoch transition
    /// is in progress, this should return the most recent completed epoch.
    pub fn get_latest_epoch(&self) -> u64 {
        self.latest_epoch
    }

    fn increment_epoch(&mut self) {
        let epoch = self.latest_epoch + 1;
        self.latest_epoch = epoch;
    }

    /// This function returns the node location for the node whose label is the longest common
    /// prefix for the queried label. It also returns a membership proof for said label.
    /// This is meant to be used in both, getting membership proofs and getting non-membership proofs.
    pub async fn get_membership_proof_and_node<S: V2Storage + Sync + Send>(
        &self,
        storage: &S,
        label: NodeLabel,
        epoch: u64,
    ) -> Result<(MembershipProof<H>, usize), AkdError> {
        let mut parent_labels = Vec::<NodeLabel>::new();
        let mut sibling_labels = Vec::<[NodeLabel; ARITY - 1]>::new();
        let mut sibling_hashes = Vec::<[H::Digest; ARITY - 1]>::new();
        let mut dirs = Vec::<Direction>::new();
        let mut curr_node: HistoryTreeNode<H> =
            HistoryTreeNode::get_from_storage(storage, NodeKey(self.root)).await?;
        let mut dir = curr_node.label.get_dir(label);
        let mut equal = label == curr_node.label;
        let mut prev_node = 0;
        while !equal && dir.is_some() {
            dirs.push(dir);
            parent_labels.push(curr_node.label);
            prev_node = curr_node.location;
            let curr_state = curr_node.get_state_at_epoch(storage, epoch).await?;
            let mut labels = [NodeLabel::new(0, 0); ARITY - 1];
            let mut hashes = [H::hash(&[0u8]); ARITY - 1];
            let mut count = 0;
            let direction = dir.ok_or(AkdError::NoDirectionError)?;
            let next_state = curr_state.get_child_state_in_dir(direction);
            if next_state.dummy_marker == DummyChildState::Dummy {
                break;
            }
            for i in 0..ARITY {
                if i != dir.ok_or(AkdError::NoDirectionError)? {
                    labels[count] = curr_state.child_states[i].label;
                    hashes[count] = to_digest::<H>(&curr_state.child_states[i].hash_val).unwrap();
                    count += 1;
                }
            }
            sibling_labels.push(labels);
            sibling_hashes.push(hashes);
            let new_curr_node: HistoryTreeNode<H> = HistoryTreeNode::get_from_storage(
                storage,
                NodeKey(
                    curr_node
                        .get_child_location_at_epoch(storage, epoch, dir)
                        .await?,
                ),
            )
            .await?;
            curr_node = new_curr_node;
            dir = curr_node.label.get_dir(label);
            equal = label == curr_node.label;
        }
        if !equal {
            let new_curr_node: HistoryTreeNode<H> =
                HistoryTreeNode::get_from_storage(storage, NodeKey(prev_node)).await?;
            curr_node = new_curr_node;

            parent_labels.pop();
            sibling_labels.pop();
            sibling_hashes.pop();
            dirs.pop();
        }

        let hash_val = curr_node
            .get_value_without_label_at_epoch(storage, epoch)
            .await?;

        Ok((
            MembershipProof::<H> {
                label: curr_node.label,
                hash_val,
                parent_labels,
                sibling_labels,
                sibling_hashes,
                dirs,
            },
            prev_node,
        ))
    }
}

type AppendOnlyHelper<D> = (Vec<(NodeLabel, D)>, Vec<(NodeLabel, D)>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auditor::verify_append_only,
        client::{verify_membership, verify_nonmembership},
        storage::memory::AsyncInMemoryDatabase,
    };
    use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;

    #[actix_rt::test]
    async fn test_batch_insert_basic() -> Result<(), AkdError> {
        let mut rng = OsRng;
        let num_nodes = 10;
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks1 = Azks::<Blake3>::new(&db).await?;

        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let val = Blake3::hash(&input);
            insertion_set.push((node, val));
            azks1.insert_leaf(&db, node, val).await?;
        }

        let db2 = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks2 = Azks::<Blake3>::new(&db2).await?;

        azks2.batch_insert_leaves(&db2, insertion_set).await?;

        assert_eq!(
            azks1.get_root_hash(&db).await?,
            azks2.get_root_hash(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[actix_rt::test]
    async fn test_insert_permuted() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks1 = Azks::<Blake3>::new(&db).await?;
        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set.push((node, input));
            azks1.insert_leaf(&db, node, input).await?;
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);

        let db2 = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks2 = Azks::<Blake3>::new(&db2).await?;

        azks2.batch_insert_leaves(&db2, insertion_set).await?;

        assert_eq!(
            azks1.get_root_hash(&db).await?,
            azks2.get_root_hash(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[actix_rt::test]
    async fn test_membership_proof_permuted() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set.push((node, input));
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks = Azks::<Blake3>::new(&db).await?;
        azks.batch_insert_leaves(&db, insertion_set.clone()).await?;

        let proof = azks
            .get_membership_proof(&db, insertion_set[0].0, 1)
            .await?;

        verify_membership::<Blake3>(azks.get_root_hash(&db).await?, &proof)?;

        Ok(())
    }

    #[actix_rt::test]
    async fn test_membership_proof_failing() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set.push((node, input));
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks = Azks::<Blake3>::new(&db).await?;
        azks.batch_insert_leaves(&db, insertion_set.clone()).await?;

        let mut proof = azks
            .get_membership_proof(&db, insertion_set[0].0, 1)
            .await?;
        let hash_val = Blake3::hash(&[0u8]);
        proof = MembershipProof::<Blake3> {
            label: proof.label,
            hash_val,
            sibling_hashes: proof.sibling_hashes,
            sibling_labels: proof.sibling_labels,
            parent_labels: proof.parent_labels,
            dirs: proof.dirs,
        };
        assert!(
            !verify_membership::<Blake3>(azks.get_root_hash(&db).await?, &proof).is_ok(),
            "Membership proof does verifies, despite being wrong"
        );

        Ok(())
    }

    #[actix_rt::test]
    async fn test_membership_proof_intermediate() -> Result<(), AkdError> {
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set.push((NodeLabel::new(0b0, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b1 << 63, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b11 << 62, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b01 << 62, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b111 << 61, 64), Blake3::hash(&[])));
        let mut azks = Azks::<Blake3>::new(&db).await?;
        azks.batch_insert_leaves(&db, insertion_set).await?;
        let search_label = NodeLabel::new(0b1111 << 60, 64);
        let proof = azks.get_non_membership_proof(&db, search_label, 1).await?;
        assert!(
            verify_nonmembership::<Blake3>(azks.get_root_hash(&db).await?, &proof)?,
            "Nonmembership proof does not verify"
        );
        Ok(())
    }

    #[actix_rt::test]
    async fn test_nonmembership_proof() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set.push((node, input));
        }
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks = Azks::<Blake3>::new(&db).await?;
        let search_label = insertion_set[num_nodes - 1].0;
        azks.batch_insert_leaves(&db, insertion_set.clone()[0..num_nodes - 1].to_vec())
            .await?;
        let proof = azks.get_non_membership_proof(&db, search_label, 1).await?;

        assert!(
            verify_nonmembership::<Blake3>(azks.get_root_hash(&db).await?, &proof)?,
            "Nonmembership proof does not verify"
        );

        Ok(())
    }

    #[actix_rt::test]
    async fn test_append_only_proof_very_tiny() -> Result<(), AkdError> {
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks = Azks::<Blake3>::new(&db).await?;

        let mut insertion_set_1: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_1.push((NodeLabel::new(0b0, 64), Blake3::hash(&[])));
        azks.batch_insert_leaves(&db, insertion_set_1).await?;
        let start_hash = azks.get_root_hash(&db).await?;

        let mut insertion_set_2: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_2.push((NodeLabel::new(0b01 << 62, 64), Blake3::hash(&[])));

        azks.batch_insert_leaves(&db, insertion_set_2).await?;
        let end_hash = azks.get_root_hash(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 2).await?;

        verify_append_only::<Blake3>(proof, start_hash, end_hash).await?;
        Ok(())
    }

    #[actix_rt::test]
    async fn test_append_only_proof_tiny() -> Result<(), AkdError> {
        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks = Azks::<Blake3>::new(&db).await?;

        let mut insertion_set_1: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_1.push((NodeLabel::new(0b0, 64), Blake3::hash(&[])));
        insertion_set_1.push((NodeLabel::new(0b1 << 63, 64), Blake3::hash(&[])));
        azks.batch_insert_leaves(&db, insertion_set_1).await?;
        let start_hash = azks.get_root_hash(&db).await?;

        let mut insertion_set_2: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_2.push((NodeLabel::new(0b01 << 62, 64), Blake3::hash(&[])));
        insertion_set_2.push((NodeLabel::new(0b111 << 61, 64), Blake3::hash(&[])));

        azks.batch_insert_leaves(&db, insertion_set_2).await?;
        let end_hash = azks.get_root_hash(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 2).await?;

        verify_append_only::<Blake3>(proof, start_hash, end_hash).await?;
        Ok(())
    }

    #[actix_rt::test]
    async fn test_append_only_proof() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set_1: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set_1.push((node, input));
        }

        let db = storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
        let mut azks = Azks::<Blake3>::new(&db).await?;
        azks.batch_insert_leaves(&db, insertion_set_1.clone())
            .await?;

        let start_hash = azks.get_root_hash(&db).await?;

        let mut insertion_set_2: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set_2.push((node, input));
        }

        azks.batch_insert_leaves(&db, insertion_set_2.clone())
            .await?;

        let mut insertion_set_3: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set_3.push((node, input));
        }

        azks.batch_insert_leaves(&db, insertion_set_3.clone())
            .await?;

        let end_hash = azks.get_root_hash(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 3).await?;

        verify_append_only::<Blake3>(proof, start_hash, end_hash).await?;
        Ok(())
    }
}
