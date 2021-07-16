// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::fmt::Error;

use crate::{
    errors::HistoryTreeNodeError,
    history_tree_node::{NodeType, *},
};
use crate::{history_tree_node::HistoryTreeNode, node_state::*, ARITY, *};
use crypto::Hasher;

use keyed_priority_queue::{Entry, KeyedPriorityQueue};
use queues::*;

pub struct Azks<H: Hasher> {
    root: usize,
    latest_epoch: u64,
    epochs: Vec<u64>,
    tree_nodes: Vec<HistoryTreeNode<H>>, // This also needs to include a VRF key to actually compute
                                         // labels but need to figure out how we want to instantiate.
                                         // For now going to assume that the inserted leaves come with unique labels.
}

#[derive(Debug)]
pub struct MembershipProof<H: Hasher> {
    label: NodeLabel,
    hash_val: H::Digest,
    parent_labels: Vec<NodeLabel>,
    sibling_labels: Vec<[NodeLabel; ARITY - 1]>,
    sibling_hashes: Vec<[H::Digest; ARITY - 1]>,
    dirs: Vec<Direction>,
}

#[derive(Debug)]
pub struct NonMembershipProof<H: Hasher> {
    label: NodeLabel,
    longest_prefix: NodeLabel,
    longest_prefix_children_labels: [NodeLabel; ARITY],
    longest_prefix_children_values: [H::Digest; ARITY],
    longest_prefix_membership_proof: MembershipProof<H>,
}

#[derive(Debug)]
pub struct AppendOnlyProof<H: Hasher> {
    inserted: Vec<(NodeLabel, H::Digest)>,
    unchanged_nodes: Vec<(NodeLabel, H::Digest)>,
}

impl<H: Hasher> Azks<H> {
    pub fn new() -> Self {
        let root = get_empty_root::<H>(Option::Some(0u64));
        let latest_epoch = 0;
        let mut epochs = vec![latest_epoch];
        let mut tree_nodes = vec![root];
        Azks {
            root: 0,
            latest_epoch,
            epochs,
            tree_nodes,
        }
    }

    pub fn insert_leaf(&mut self, label: NodeLabel, value: H::Digest) -> Result<(), SeemlessError> {
        // Calls insert_single_leaf on the root node and updates the root and tree_nodes
        if self.latest_epoch != 0 {
            self.increment_epoch();
        }
        let mut new_leaf = get_leaf_node::<H>(label, 0, value.as_ref(), 0, self.latest_epoch);
        let mut tree_repr = self.tree_nodes.clone();
        let (_, tree_repr) = self.tree_nodes[self.root].insert_single_leaf(
            new_leaf,
            self.latest_epoch,
            tree_repr,
        )?;
        self.tree_nodes = tree_repr;
        if self.latest_epoch != 0 {
            self.increment_epoch();
        }
        Ok(())
        // self.batch_insert_leaves(vec![(label, value)])
    }

    pub fn batch_insert_leaves(
        &mut self,
        insertion_set: Vec<(NodeLabel, H::Digest)>,
    ) -> Result<(), SeemlessError> {
        let original_len = self.tree_nodes.len();
        if self.latest_epoch != 0 {
            self.increment_epoch();
        }
        let mut hash_q = KeyedPriorityQueue::<usize, i32>::new();
        let mut priorities: i32 = 0;
        for insertion_elt in insertion_set {
            let mut new_leaf = get_leaf_node::<H>(
                insertion_elt.0,
                0,
                insertion_elt.1.as_ref(),
                0,
                self.latest_epoch,
            );
            let mut tree_repr = self.tree_nodes.clone();
            let (_, tree_repr) = self.tree_nodes[self.root].insert_single_leaf_without_hash(
                new_leaf,
                self.latest_epoch,
                tree_repr,
            )?;
            self.tree_nodes = tree_repr.clone();
            hash_q.push(tree_repr.len() - 1, priorities);
            priorities -= 1;
        }
        while (!hash_q.is_empty()) {
            let (next_node_loc, _) = hash_q
                .pop()
                .ok_or(AzksError::PopFromEmptyPriorityQueue(self.latest_epoch))
                .unwrap();
            let mut next_node = self.tree_nodes[next_node_loc].clone();
            let mut tree_repr = self.tree_nodes.clone();
            let tree_repr = next_node.update_hash(self.latest_epoch, tree_repr)?;
            self.tree_nodes = tree_repr;
            if !next_node.is_root() {
                match hash_q.entry(next_node.parent) {
                    Entry::Vacant(entry) => entry.set_priority(priorities),
                    Entry::Occupied(entry) => {
                        entry.set_priority(priorities);
                    }
                };
                priorities -= 1;
            }
        }
        if self.latest_epoch == 0 {
            self.increment_epoch();
        }
        Ok(())
    }

    pub fn get_membership_proof(&self, label: NodeLabel, epoch: u64) -> MembershipProof<H> {
        // Regular Merkle membership proof for the trie as it stood at epoch
        // Assumes the verifier as access to the root at epoch
        let (pf, _) = self.get_membership_proof_and_node(label, epoch);
        pf
    }

    pub fn get_non_membership_proof(&self, label: NodeLabel, epoch: u64) -> NonMembershipProof<H> {
        // In a compressed trie, the proof consists of the longest prefix
        // of the label that is included in the trie, as well as its children, to show that
        // none of the children is equal to the given label.
        /*
        pub struct NonMembershipProof<H: Hasher> {
            label: NodeLabel,
            longest_prefix: NodeLabel,
            longest_prefix_children_labels: [NodeLabel; ARITY],
            longest_prefix_children_values: [H::Digest; ARITY],
            longest_prefix_membership_proof: MembershipProof<H>,
        }
        */

        let (membership_pf, lcp_node_id) = self.get_membership_proof_and_node(label, epoch);


        let (longest_prefix_membership_proof, lcp_node_id) =
            self.get_membership_proof_and_node(label, epoch);
        let lcp_node = self.tree_nodes[lcp_node_id].clone();
        let longest_prefix = lcp_node.label;
        let mut longest_prefix_children_labels = [NodeLabel::new(0, 0); ARITY];
        let mut longest_prefix_children_values = [H::hash(&[]); ARITY];
        let children = lcp_node
            .get_state_at_epoch(epoch)
            .unwrap()
            .child_states
            .iter()
            .map(|x| self.tree_nodes[x.location].clone());
        for (i, child) in children.enumerate() {
            longest_prefix_children_labels[i] = child.label;
            longest_prefix_children_values[i] =
                child.get_value_without_label_at_epoch(epoch).unwrap();
        }
        NonMembershipProof {
            label,
            longest_prefix,
            longest_prefix_children_labels,
            longest_prefix_children_values,
            longest_prefix_membership_proof,
        }

    }

    pub fn get_consecutive_append_only_proof(&self, start_epoch: u64) -> AppendOnlyProof<H> {
        // Suppose the epochs start_epoch and start_epoch+1 exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.
        unimplemented!()
    }

    // FIXME: these functions below should be moved into higher-level API

    pub fn get_root_hash(&self) -> Result<H::Digest, HistoryTreeNodeError> {
        self.get_root_hash_at_epoch(self.get_latest_epoch())
    }

    pub fn get_root_hash_at_epoch(&self, epoch: u64) -> Result<H::Digest, HistoryTreeNodeError> {
        self.tree_nodes[self.root].get_value_at_epoch(epoch)
    }

    pub fn get_latest_epoch(&self) -> u64 {
        self.latest_epoch
    }

    pub fn verify_membership(
        &self,
        root_hash: H::Digest,
        epoch: u64,
        proof: MembershipProof<H>,
    ) -> bool {
        let hash_val = H::merge(&[proof.hash_val, hash_label::<H>(proof.label)]);
        let mut sibling_hashes = proof.sibling_hashes.clone();
        let mut parent_labels = proof.parent_labels.clone();
        let mut dirs = proof.dirs;
        let mut final_hash = hash_val;
        for i in 0..parent_labels.len() {
            let hashes = sibling_hashes.pop().unwrap();
            let dir = dirs.pop().unwrap();
            let parent_label = parent_labels.pop().unwrap();
            final_hash = build_and_hash_layer::<H>(hashes, dir, final_hash, parent_label);
        }

        final_hash == root_hash
    }

    pub fn verify_nonmembership(
        &self,
        label: NodeLabel,
        root_hash: H::Digest,
        epoch: u64,
        proof: NonMembershipProof<H>,
    ) -> bool {
        /*
        pub struct NonMembershipProof<H: Hasher> {
            label: NodeLabel,
            longest_prefix: NodeLabel,
            longest_prefix_children_labels: [NodeLabel; ARITY],
            longest_prefix_children_values: [H::Digest; ARITY],
            longest_prefix_membership_proof: MembershipProof<H>,
        }
        */
        let mut verified = true;
        let mut lcp_hash = H::hash(&[]);
        let mut lcp_real = label;
        for i in 0..ARITY {
            let child_hash = H::merge(&[
                proof.longest_prefix_children_values[i],
                hash_label::<H>(proof.longest_prefix_children_labels[i]),
            ]);
            lcp_hash = H::merge(&[lcp_hash, child_hash]);
            lcp_real = lcp_real.get_longest_common_prefix(proof.longest_prefix_children_labels[i]);
        }
        // lcp_hash = H::merge(&[lcp_hash, hash_label::<H>(proof.longest_prefix)]);
        verified = verified && (lcp_hash == proof.longest_prefix_membership_proof.hash_val);
        assert!(verified, "lcp_hash != longest_prefix_hash");
        verified = verified
            && self.verify_membership(root_hash, epoch, proof.longest_prefix_membership_proof);
        assert!(verified, "membership_proof did not verify");
        // The audit must have checked that this node is indeed the lcp of its children.
        // So we can just check that one of the children's lcp is = the proof.longest_prefix
        verified = verified && (proof.longest_prefix == lcp_real);
        assert!(verified, "longest_prefix != lcp");
        verified
    }

    fn increment_epoch(&mut self) {
        let epoch = self.latest_epoch + 1;
        self.latest_epoch = epoch;
        self.epochs.push(epoch);
    }

    pub fn get_membership_proof_and_node(
        &self,
        label: NodeLabel,
        epoch: u64,
    ) -> (MembershipProof<H>, usize) {
        // Regular Merkle membership proof for the trie as it stood at epoch
        // Assumes the verifier has access to the root hash at epoch
        /*pub struct MembershipProof<H: Hasher> {
            label: NodeLabel,
            hash_val: H::Digest,
            sibling_labels: Vec<NodeLabel>,
            sibling_hashes: Vec<H::Digest>,
        }*/
        let mut parent_labels = Vec::<NodeLabel>::new();
        let mut sibling_labels = Vec::<[NodeLabel; ARITY - 1]>::new();
        let mut sibling_hashes = Vec::<[H::Digest; ARITY - 1]>::new();
        let mut dirs = Vec::<Direction>::new();
        let mut curr_node = self.tree_nodes[self.root].clone();
        let mut dir = curr_node.label.get_dir(label);
        let mut equal = label == curr_node.label;
        let mut prev_node = 0;
        while !equal && dir.is_some() {
            dirs.push(dir);
            parent_labels.push(curr_node.label);
            prev_node = curr_node.location;
            let curr_state = curr_node.get_state_at_epoch(epoch).unwrap();
            let mut labels = [NodeLabel::new(0, 0); ARITY - 1];
            let mut hashes = [H::hash(&[0u8]); ARITY - 1];
            let mut count = 0;
            for i in 0..ARITY {
                if i != dir.unwrap() {
                    if dir.unwrap() > 1 {
                        println! {"Curr node = {:?}", curr_node.label};
                    }
                    labels[count] = curr_state.child_states[i].label;
                    hashes[count] = curr_state.child_states[i].hash_val;
                    count += 1;
                }
            }
            sibling_labels.push(labels);
            sibling_hashes.push(hashes);
            curr_node = self.tree_nodes[curr_node.get_child_location_at_epoch(epoch, dir)].clone();
            dir = curr_node.label.get_dir(label);
            equal = label == curr_node.label;
        }
        if !equal {
            curr_node = self.tree_nodes[prev_node].clone();
            parent_labels.pop();
            sibling_labels.pop();
            sibling_hashes.pop();
            dirs.pop();
        }

        let hash_val = curr_node.get_value_without_label_at_epoch(epoch).unwrap();

        (
            MembershipProof::<H> {
                label: curr_node.label,
                hash_val,
                parent_labels,
                sibling_labels,
                sibling_hashes,
                dirs,
            },
            prev_node,
        )
    }
}

impl<H: Hasher> Default for Azks<H> {
    fn default() -> Self {
        Self::new()
    }
}

fn build_and_hash_layer<H: Hasher>(
    hashes: [H::Digest; ARITY - 1],
    dir: Direction,
    ancestor_hash: H::Digest,
    parent_label: NodeLabel,
) -> H::Digest {
    let direction = dir.unwrap();
    let mut hashes_as_vec = hashes.to_vec();
    hashes_as_vec.insert(direction, ancestor_hash);
    hash_layer::<H>(hashes_as_vec, parent_label)
}

fn hash_layer<H: Hasher>(hashes: Vec<H::Digest>, parent_label: NodeLabel) -> H::Digest {
    let mut new_hash = H::hash(&[]); //hash_label::<H>(parent_label);
    for child_hash in hashes.iter().take(ARITY) {
        new_hash = H::merge(&[new_hash, *child_hash]);
    }
    new_hash = H::merge(&[new_hash, hash_label::<H>(parent_label)]);
    new_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::hashers::Blake3_256;
    use math::fields::f128::BaseElement;
    use rand::{rngs::OsRng, seq::SliceRandom, RngCore};

    type Blake3 = Blake3_256<BaseElement>;
    type Blake3Digest = <Blake3_256<math::fields::f128::BaseElement> as Hasher>::Digest; //Blake3_256<BaseElement>::Digest;
    #[test]
    fn test_batch_insert_basic() -> Result<(), HistoryTreeNodeError> {
        let num_nodes = 1000;
        let mut rng = OsRng;

        let mut azks1 = Azks::<Blake3>::new();
        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let val = Blake3::hash(&input);
            insertion_set.push((node, val));
            azks1.insert_leaf(node, val).unwrap();
        }

        let mut azks2 = Azks::<Blake3>::new();
        azks2.batch_insert_leaves(insertion_set);
        assert_eq!(
            azks1.get_root_hash()?,
            azks2.get_root_hash()?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }
    #[test]
    fn test_insert_permuted() -> Result<(), HistoryTreeNodeError> {
        let num_nodes = 1000;
        let mut rng = OsRng;

        let mut azks1 = Azks::<Blake3>::new();
        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set.push((node, input));
            azks1.insert_leaf(node, input).unwrap();
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);

        let mut azks2 = Azks::<Blake3>::new();

        azks2.batch_insert_leaves(insertion_set);

        assert_eq!(
            azks1.get_root_hash()?,
            azks2.get_root_hash()?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[test]
    fn test_membership_proof_permuted() -> Result<(), HistoryTreeNodeError> {
        let num_nodes = 1000;
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

        let mut azks = Azks::<Blake3>::new();
        azks.batch_insert_leaves(insertion_set.clone());

        let proof = azks.get_membership_proof(insertion_set[0].0, 0);

        assert!(
            azks.verify_membership(azks.get_root_hash()?, 0, proof),
            "Membership proof does not verify"
        );

        Ok(())
    }

    #[test]
    fn test_membership_proof_failing() -> Result<(), HistoryTreeNodeError> {
        let num_nodes = 1000;
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

        let mut azks = Azks::<Blake3>::new();
        azks.batch_insert_leaves(insertion_set.clone());

        let mut proof = azks.get_membership_proof(insertion_set[0].0, 0);
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
            !azks.verify_membership(azks.get_root_hash()?, 0, proof),
            "Membership proof does verifies, despite being wrong"
        );

        Ok(())
    }

    #[test]
    fn test_membership_proof_intermediate() -> Result<(), HistoryTreeNodeError> {
        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];
        insertion_set.push((NodeLabel::new(0b0, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b1 << 63, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b11 << 62, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b01 << 62, 64), Blake3::hash(&[])));
        insertion_set.push((NodeLabel::new(0b111 << 61, 64), Blake3::hash(&[])));
        let mut azks = Azks::<Blake3>::new();
        azks.batch_insert_leaves(insertion_set);
        let search_label = NodeLabel::new(0b1111 << 60, 64);
        let proof = azks.get_non_membership_proof(search_label, 0);
        println!(
            "proof label = {:?}",
            proof.longest_prefix_membership_proof.label
        );
        println!("proof = {:?}", proof.longest_prefix_membership_proof);
        assert!(
            azks.verify_nonmembership(search_label, azks.get_root_hash()?, 0, proof),
            "Nonmembership proof does not verify"
        );
        Ok(())
    }

    #[test]
    fn test_nonmembership_proof() -> Result<(), HistoryTreeNodeError> {
        let num_nodes = 1000;
        let mut rng = OsRng;

        let mut insertion_set: Vec<(NodeLabel, Blake3Digest)> = vec![];

        for _ in 0..num_nodes {
            let node = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let input = Blake3Digest::new(input);
            insertion_set.push((node, input));
        }

        let mut azks = Azks::<Blake3>::new();
        let search_label = insertion_set[num_nodes - 1].0;
        azks.batch_insert_leaves(insertion_set.clone()[0..num_nodes - 1].to_vec());
        let proof = azks.get_non_membership_proof(search_label, 0);

        assert!(
            azks.verify_nonmembership(search_label, azks.get_root_hash()?, 0, proof),
            "Nonmembership proof does not verify"
        );

        Ok(())
    }
}
