// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::HistoryTreeNodeError,
    history_tree_node::*,
    storage::{Storable, Storage},
};

use crate::serialization::to_digest;
use crate::{history_tree_node::HistoryTreeNode, node_state::*, ARITY, *};
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;
use winter_crypto::Hasher;

use serde::{Deserialize, Serialize};

use keyed_priority_queue::{Entry, KeyedPriorityQueue};

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Azks<H, S> {
    /// Random identifier for the AZKS instance
    azks_id: Vec<u8>,
    root: usize,
    latest_epoch: u64,
    num_nodes: usize, // The size of the tree
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}

// parameter is azks_id
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AzksKey(pub(crate) Vec<u8>);

impl<H: Hasher, S: Storage> Storable<S> for Azks<H, S> {
    type Key = AzksKey;

    fn identifier() -> String {
        String::from("Azks")
    }
}

impl<H: Hasher, S: Storage> Clone for Azks<H, S> {
    fn clone(&self) -> Self {
        Self {
            azks_id: self.azks_id.clone(),
            root: self.root,
            latest_epoch: self.latest_epoch,
            num_nodes: self.num_nodes,
            _s: PhantomData,
            _h: PhantomData,
        }
    }
}

impl<H: Hasher, S: Storage> Azks<H, S> {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, SeemlessError> {
        let mut azks_id = vec![0u8; 32];
        rng.fill_bytes(&mut azks_id);

        let root = get_empty_root::<H, S>(&azks_id, Option::Some(0))?;

        let azks = Azks {
            azks_id,
            root: 0,
            latest_epoch: 0,
            num_nodes: 1,
            _s: PhantomData,
            _h: PhantomData,
        };

        root.write_to_storage()?;

        Ok(azks)
    }

    pub fn insert_leaf(&mut self, label: NodeLabel, value: H::Digest) -> Result<(), SeemlessError> {
        // Calls insert_single_leaf on the root node and updates the root and tree_nodes
        self.increment_epoch();

        let new_leaf = get_leaf_node::<H, S>(
            &self.azks_id,
            label,
            0,
            value.as_ref(),
            0,
            self.latest_epoch,
        )?;

        let mut root_node = HistoryTreeNode::retrieve(NodeKey(self.azks_id.clone(), self.root))?;
        root_node.insert_single_leaf(
            new_leaf,
            &self.azks_id,
            self.latest_epoch,
            &mut self.num_nodes,
        )?;

        Ok(())
    }

    pub fn batch_insert_leaves(
        &mut self,
        insertion_set: Vec<(NodeLabel, H::Digest)>,
    ) -> Result<(), SeemlessError> {
        self.batch_insert_leaves_helper(insertion_set, false)
    }

    pub fn batch_insert_leaves_helper(
        &mut self,
        insertion_set: Vec<(NodeLabel, H::Digest)>,
        append_only_usage: bool,
    ) -> Result<(), SeemlessError> {
        self.increment_epoch();

        let mut hash_q = KeyedPriorityQueue::<usize, i32>::new();
        let mut priorities: i32 = 0;
        let mut root_node = HistoryTreeNode::retrieve(NodeKey(self.azks_id.clone(), self.root))?;
        for insertion_elt in insertion_set {
            let new_leaf_loc = self.num_nodes;

            let mut new_leaf = get_leaf_node::<H, S>(
                &self.azks_id,
                insertion_elt.0,
                0,
                insertion_elt.1.as_ref(),
                0,
                self.latest_epoch,
            )?;
            if append_only_usage {
                new_leaf = get_leaf_node_without_hashing::<H, S>(
                    &self.azks_id,
                    insertion_elt.0,
                    0,
                    insertion_elt.1,
                    0,
                    self.latest_epoch,
                )?;
            }

            root_node.insert_single_leaf_without_hash(
                new_leaf,
                &self.azks_id,
                self.latest_epoch,
                &mut self.num_nodes,
            )?;

            hash_q.push(new_leaf_loc, priorities);
            priorities -= 1;
        }

        while !hash_q.is_empty() {
            let (next_node_loc, _) = hash_q
                .pop()
                .ok_or(AzksError::PopFromEmptyPriorityQueue(self.latest_epoch))?;

            let mut next_node =
                HistoryTreeNode::<H, S>::retrieve(NodeKey(self.azks_id.clone(), next_node_loc))?;

            next_node.update_hash(self.latest_epoch)?;

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

    pub fn get_membership_proof(
        &self,
        label: NodeLabel,
        epoch: u64,
    ) -> Result<MembershipProof<H>, SeemlessError> {
        // Regular Merkle membership proof for the trie as it stood at epoch
        // Assumes the verifier as access to the root at epoch
        let (pf, _) = self.get_membership_proof_and_node(label, epoch)?;
        Ok(pf)
    }

    pub fn get_non_membership_proof(
        &self,
        label: NodeLabel,
        epoch: u64,
    ) -> Result<NonMembershipProof<H>, SeemlessError> {
        // In a compressed trie, the proof consists of the longest prefix
        // of the label that is included in the trie, as well as its children, to show that
        // none of the children is equal to the given label.

        let (longest_prefix_membership_proof, lcp_node_id) =
            self.get_membership_proof_and_node(label, epoch)?;
        let lcp_node =
            HistoryTreeNode::<H, S>::retrieve(NodeKey(self.azks_id.clone(), lcp_node_id))?;
        let longest_prefix = lcp_node.label;
        let mut longest_prefix_children_labels = [NodeLabel::new(0, 0); ARITY];
        let mut longest_prefix_children_values = [H::hash(&[]); ARITY];
        let state = lcp_node.get_state_at_epoch(epoch)?;

        let children = state
            .child_states
            .iter()
            .map(|x: &node_state::HistoryChildState<H, S>| -> Result<HistoryTreeNode<H, S>, HistoryTreeNodeError> {
                let node = HistoryTreeNode::retrieve(NodeKey(self.azks_id.clone(), x.location))?;
                Ok(node)
            });

        for (i, child) in children.enumerate() {
            let unwrapped_child = child?;
            longest_prefix_children_labels[i] = unwrapped_child.label;
            longest_prefix_children_values[i] =
                unwrapped_child.get_value_without_label_at_epoch(epoch)?;
        }
        Ok(NonMembershipProof {
            label,
            longest_prefix,
            longest_prefix_children_labels,
            longest_prefix_children_values,
            longest_prefix_membership_proof,
        })
    }

    pub fn get_append_only_proof(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyProof<H>, SeemlessError> {
        // Suppose the epochs start_epoch and end_epoch exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.
        let node = HistoryTreeNode::retrieve(NodeKey(self.azks_id.clone(), self.root))?;
        let (unchanged, leaves) =
            self.get_append_only_proof_helper(node, start_epoch, end_epoch)?;
        Ok(AppendOnlyProof {
            inserted: leaves,
            unchanged_nodes: unchanged,
        })
    }

    fn get_append_only_proof_helper(
        &self,
        node: HistoryTreeNode<H, S>,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyHelper<H::Digest>, SeemlessError> {
        let mut unchanged = Vec::<(NodeLabel, H::Digest)>::new();
        let mut leaves = Vec::<(NodeLabel, H::Digest)>::new();
        if node.get_latest_epoch()? <= start_epoch {
            if node.is_root() {
                // this is the case where the root is unchanged since the last epoch
                return Ok((unchanged, leaves));
            }

            unchanged.push((
                node.label,
                node.get_value_without_label_at_epoch(node.get_latest_epoch()?)?,
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
                node.get_value_without_label_at_epoch(node.get_latest_epoch()?)?,
            ));
        } else {
            for child_node_state in node
                .get_state_at_epoch(end_epoch)?
                .child_states
                .iter()
                .map(|x| x.clone())
            {
                if child_node_state.dummy_marker == DummyChildState::Dummy {
                    continue;
                } else {
                    let child_node = HistoryTreeNode::retrieve(NodeKey(
                        self.azks_id.clone(),
                        child_node_state.location,
                    ))?;
                    let mut rec_output =
                        self.get_append_only_proof_helper(child_node, start_epoch, end_epoch)?;
                    unchanged.append(&mut rec_output.0);
                    leaves.append(&mut rec_output.1);
                }
            }
        }
        Ok((unchanged, leaves))
    }

    pub fn get_consecutive_append_only_proof(
        &self,
        start_epoch: u64,
    ) -> Result<AppendOnlyProof<H>, SeemlessError> {
        // Suppose the epochs start_epoch and start_epoch+1 exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.
        self.get_append_only_proof(start_epoch, start_epoch + 1)
    }

    // FIXME: these functions below should be moved into higher-level API

    pub fn get_root_hash(&self) -> Result<H::Digest, HistoryTreeNodeError> {
        self.get_root_hash_at_epoch(self.get_latest_epoch())
    }

    pub fn get_root_hash_at_epoch(&self, epoch: u64) -> Result<H::Digest, HistoryTreeNodeError> {
        let root_node =
            HistoryTreeNode::<H, S>::retrieve(NodeKey(self.azks_id.clone(), self.root))?;
        root_node.get_value_at_epoch(epoch)
    }

    pub fn get_latest_epoch(&self) -> u64 {
        self.latest_epoch
    }

    fn increment_epoch(&mut self) {
        let epoch = self.latest_epoch + 1;
        self.latest_epoch = epoch;
    }

    pub fn get_membership_proof_and_node(
        &self,
        label: NodeLabel,
        epoch: u64,
    ) -> Result<(MembershipProof<H>, usize), SeemlessError> {
        let mut parent_labels = Vec::<NodeLabel>::new();
        let mut sibling_labels = Vec::<[NodeLabel; ARITY - 1]>::new();
        let mut sibling_hashes = Vec::<[H::Digest; ARITY - 1]>::new();
        let mut dirs = Vec::<Direction>::new();
        let mut curr_node =
            HistoryTreeNode::<H, S>::retrieve(NodeKey(self.azks_id.clone(), self.root))?;
        let mut dir = curr_node.label.get_dir(label);
        let mut equal = label == curr_node.label;
        let mut prev_node = 0;
        while !equal && dir.is_some() {
            dirs.push(dir);
            parent_labels.push(curr_node.label);
            prev_node = curr_node.location;
            let curr_state = curr_node.get_state_at_epoch(epoch)?;
            let mut labels = [NodeLabel::new(0, 0); ARITY - 1];
            let mut hashes = [H::hash(&[0u8]); ARITY - 1];
            let mut count = 0;
            let direction = dir.ok_or(SeemlessError::NoDirectionError)?;
            let next_state = curr_node.get_state_at_epoch(epoch);
            let next_state = next_state.map(|curr| curr.get_child_state_in_dir(direction))?;
            if next_state.dummy_marker == DummyChildState::Dummy {
                break;
            }
            for i in 0..ARITY {
                if i != dir.ok_or(SeemlessError::NoDirectionError)? {
                    labels[count] = curr_state.child_states[i].label;
                    hashes[count] = to_digest::<H>(&curr_state.child_states[i].hash_val).unwrap();
                    count += 1;
                }
            }
            sibling_labels.push(labels);
            sibling_hashes.push(hashes);
            let new_curr_node = HistoryTreeNode::retrieve(NodeKey(
                self.azks_id.clone(),
                curr_node.get_child_location_at_epoch(epoch, dir)?,
            ))?;
            curr_node = new_curr_node;
            dir = curr_node.label.get_dir(label);
            equal = label == curr_node.label;
        }
        if !equal {
            let new_curr_node =
                HistoryTreeNode::retrieve(NodeKey(self.azks_id.clone(), prev_node))?;
            curr_node = new_curr_node;

            parent_labels.pop();
            sibling_labels.pop();
            sibling_hashes.pop();
            dirs.pop();
        }

        let hash_val = curr_node.get_value_without_label_at_epoch(epoch)?;

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

    pub fn get_azks_id(&self) -> &[u8] {
        &self.azks_id
    }
}

type AppendOnlyHelper<D> = (Vec<(NodeLabel, D)>, Vec<(NodeLabel, D)>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        seemless_auditor::verify_append_only,
        seemless_client::{verify_membership, verify_nonmembership},
        tests::InMemoryDb,
    };
    use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;

    #[test]
    fn test_batch_insert_basic() -> Result<(), SeemlessError> {
        let num_nodes = 10;
        let mut rng = OsRng;
        let mut azks1 = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;

        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let val = Blake3::hash(&input);
            insertion_set.push((node, val));
            azks1.insert_leaf(node, val)?;
        }

        let mut azks2 = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;

        azks2.batch_insert_leaves(insertion_set)?;

        assert_eq!(
            azks1.get_root_hash()?,
            azks2.get_root_hash()?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }
    #[test]
    fn test_insert_permuted() -> Result<(), SeemlessError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut azks1 = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;
        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set.push((node, input));
            azks1.insert_leaf(node, input)?;
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);

        let mut azks2 = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;

        azks2.batch_insert_leaves(insertion_set)?;

        assert_eq!(
            azks1.get_root_hash()?,
            azks2.get_root_hash()?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[test]
    fn test_membership_proof_permuted() -> Result<(), SeemlessError> {
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

        let mut azks = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;
        azks.batch_insert_leaves(insertion_set.clone())?;

        let proof = azks.get_membership_proof(insertion_set[0].0, 1)?;

        verify_membership::<Blake3>(azks.get_root_hash()?, &proof)?;

        Ok(())
    }

    #[test]
    fn test_membership_proof_failing() -> Result<(), SeemlessError> {
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

        let mut azks = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;
        azks.batch_insert_leaves(insertion_set.clone())?;

        let mut proof = azks.get_membership_proof(insertion_set[0].0, 1)?;
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
            !verify_membership::<Blake3>(azks.get_root_hash()?, &proof).is_ok(),
            "Membership proof does verifies, despite being wrong"
        );

        Ok(())
    }

    #[test]
    fn test_membership_proof_intermediate() -> Result<(), SeemlessError> {
        let mut rng = OsRng;
        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set.push((NodeLabel::new(0b0, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b1 << 63, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b11 << 62, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b01 << 62, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b111 << 61, 64), Blake3::hash(&[])));
        let mut azks = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;
        azks.batch_insert_leaves(insertion_set)?;
        let search_label = NodeLabel::new(0b1111 << 60, 64);
        let proof = azks.get_non_membership_proof(search_label, 1)?;
        assert!(
            verify_nonmembership::<Blake3>(azks.get_root_hash()?, &proof)?,
            "Nonmembership proof does not verify"
        );
        Ok(())
    }

    #[test]
    fn test_nonmembership_proof() -> Result<(), SeemlessError> {
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

        let mut azks = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;
        let search_label = insertion_set[num_nodes - 1].0;
        azks.batch_insert_leaves(insertion_set.clone()[0..num_nodes - 1].to_vec())?;
        let proof = azks.get_non_membership_proof(search_label, 1)?;

        assert!(
            verify_nonmembership::<Blake3>(azks.get_root_hash()?, &proof)?,
            "Nonmembership proof does not verify"
        );

        Ok(())
    }

    #[test]
    fn test_append_only_proof_very_tiny() -> Result<(), SeemlessError> {
        let mut rng = OsRng;
        let mut azks = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;

        let mut insertion_set_1: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_1.push((NodeLabel::new(0b0, 64), Blake3::hash(&[])));
        azks.batch_insert_leaves(insertion_set_1)?;
        let start_hash = azks.get_root_hash()?;

        let mut insertion_set_2: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_2.push((NodeLabel::new(0b01 << 62, 64), Blake3::hash(&[])));

        azks.batch_insert_leaves(insertion_set_2)?;
        let end_hash = azks.get_root_hash()?;

        let proof = azks.get_append_only_proof(1, 2)?;

        verify_append_only::<Blake3>(proof, start_hash, end_hash)?;
        Ok(())
    }

    #[test]
    fn test_append_only_proof_tiny() -> Result<(), SeemlessError> {
        let mut rng = OsRng;
        let mut azks = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;

        let mut insertion_set_1: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_1.push((NodeLabel::new(0b0, 64), Blake3::hash(&[])));
        insertion_set_1.push((NodeLabel::new(0b1 << 63, 64), Blake3::hash(&[])));
        azks.batch_insert_leaves(insertion_set_1)?;
        let start_hash = azks.get_root_hash()?;

        let mut insertion_set_2: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set_2.push((NodeLabel::new(0b01 << 62, 64), Blake3::hash(&[])));
        insertion_set_2.push((NodeLabel::new(0b111 << 61, 64), Blake3::hash(&[])));

        azks.batch_insert_leaves(insertion_set_2)?;
        let end_hash = azks.get_root_hash()?;

        let proof = azks.get_append_only_proof(1, 2)?;

        verify_append_only::<Blake3>(proof, start_hash, end_hash)?;
        Ok(())
    }

    #[test]
    fn test_append_only_proof() -> Result<(), SeemlessError> {
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

        let mut azks = Azks::<Blake3, InMemoryDb>::new(&mut rng)?;
        azks.batch_insert_leaves(insertion_set_1.clone())?;

        let start_hash = azks.get_root_hash()?;

        let mut insertion_set_2: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set_2.push((node, input));
        }

        azks.batch_insert_leaves(insertion_set_2.clone())?;

        let mut insertion_set_3: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set_3.push((node, input));
        }

        azks.batch_insert_leaves(insertion_set_3.clone())?;

        let end_hash = azks.get_root_hash()?;

        let proof = azks.get_append_only_proof(1, 3)?;

        verify_append_only::<Blake3>(proof, start_hash, end_hash)?;
        Ok(())
    }
}
