// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of an append-only zero knowledge set
use crate::{
    errors::TreeNodeError,
    proof_structs::{AppendOnlyProof, MembershipProof, NonMembershipProof, SingleAppendOnlyProof},
    storage::{Storable, Storage},
    tree_node::*,
};

use crate::serialization::to_digest;

use crate::storage::types::StorageType;
use crate::{errors::*, node_state::*, tree_node::TreeNode, ARITY, *};
use async_recursion::async_recursion;
use log::{debug, info};
use std::marker::{Send, Sync};
use tokio::time::Instant;
use winter_crypto::Hasher;

use keyed_priority_queue::{Entry, KeyedPriorityQueue};
use std::collections::HashSet;

/// The default azks key
pub const DEFAULT_AZKS_KEY: u8 = 1u8;

/// An append-only zero knowledge set, the data structure used to efficiently implement
/// a auditable key directory.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct Azks {
    /// The latest complete epoch
    pub latest_epoch: u64,
    /// The number of nodes ie the size of this tree
    pub num_nodes: u64, // The size of the tree
}

impl Storable for Azks {
    type Key = u8;

    fn data_type() -> StorageType {
        StorageType::Azks
    }

    fn get_id(&self) -> u8 {
        DEFAULT_AZKS_KEY
    }

    fn get_full_binary_key_id(key: &u8) -> Vec<u8> {
        vec![StorageType::Azks as u8, *key]
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<u8, String> {
        if bin.is_empty() || bin[0] != StorageType::Azks as u8 {
            return Err("Not an AZKS key".to_string());
        }
        Ok(DEFAULT_AZKS_KEY)
    }
}

unsafe impl Sync for Azks {}

impl Clone for Azks {
    fn clone(&self) -> Self {
        Self {
            latest_epoch: self.latest_epoch,
            num_nodes: self.num_nodes,
        }
    }
}

impl Azks {
    /// Creates a new azks
    pub async fn new<S: Storage + Sync + Send, H: Hasher>(storage: &S) -> Result<Self, AkdError> {
        let root = get_empty_root::<H>(Option::Some(0), Option::Some(0));
        let azks = Azks {
            latest_epoch: 0,
            num_nodes: 1,
        };

        root.write_to_storage(storage).await?;

        Ok(azks)
    }

    /// Inserts a single leaf and is only used for testing, since batching is more efficient.
    /// We just want to make sure batch insertions work correctly and this function is useful for that.
    pub async fn insert_leaf<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        node: Node<H>,
        epoch: u64,
    ) -> Result<(), AkdError> {
        // Calls insert_single_leaf on the root node and updates the root and tree_nodes
        // Since this function is only for testing batch_insert_leaves, which is one epoch
        // increment for the entire batch. Hence, we want to take care of epochs outside.
        let new_leaf = get_leaf_node::<H>(node.label, &node.hash, NodeLabel::root(), epoch);

        let mut root_node = TreeNode::get_from_storage(
            storage,
            &NodeKey(NodeLabel::root()),
            self.get_latest_epoch(),
        )
        .await?;
        root_node
            .insert_single_leaf::<_, H>(storage, new_leaf, epoch, &mut self.num_nodes, None)
            .await?;

        Ok(())
    }

    /// Insert a batch of new leaves
    pub async fn batch_insert_leaves<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        insertion_set: Vec<Node<H>>,
    ) -> Result<(), AkdError> {
        self.batch_insert_leaves_helper::<_, H>(storage, insertion_set, false)
            .await
    }

    async fn preload_nodes_for_insertion<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        insertion_set: &[Node<H>],
    ) -> Result<u64, AkdError> {
        let prefixes_set = crate::utils::build_prefixes_set(
            insertion_set
                .iter()
                .map(|n| n.label)
                .collect::<Vec<NodeLabel>>()
                .as_ref(),
        );

        self.bfs_preload_nodes::<S, H>(storage, prefixes_set).await
    }

    /// Preloads given nodes using breadth-first search.
    pub async fn bfs_preload_nodes<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        nodes_to_load: HashSet<NodeLabel>,
    ) -> Result<u64, AkdError> {
        let mut load_count: u64 = 0;
        let mut current_nodes = vec![NodeKey(NodeLabel::root())];

        while !current_nodes.is_empty() {
            let nodes =
                TreeNode::batch_get_from_storage(storage, &current_nodes, self.get_latest_epoch())
                    .await?;
            load_count += nodes.len() as u64;

            current_nodes = Vec::<NodeKey>::new();

            // Now that states are loaded in the cache, you can read and access them.
            // Note, the two for loops are needed because otherwise, you'd be accessing remote storage
            // individually for each node's state.
            for node in &nodes {
                if !nodes_to_load.contains(&node.label) {
                    // Only continue to traverse nodes which are relevant prefixes to insertion_set
                    continue;
                }

                for dir in 0..ARITY {
                    let child = node
                        .get_child_state::<S>(storage, Direction::Some(dir))
                        .await?;

                    if let Some(child) = child {
                        current_nodes.push(NodeKey(child.label));
                    }
                }
            }
        }
        Ok(load_count)
    }

    /// An azks is built both by the [crate::directory::Directory] and the auditor.
    /// However, both constructions have very minor differences, and the append_only_usage
    /// bool keeps track of this.
    pub async fn batch_insert_leaves_helper<S: Storage + Sync + Send, H: Hasher>(
        &mut self,
        storage: &S,
        insertion_set: Vec<Node<H>>,
        append_only_exclude_usage: bool,
    ) -> Result<(), AkdError> {
        let tic = Instant::now();
        let load_count = self
            .preload_nodes_for_insertion::<S, H>(storage, &insertion_set)
            .await?;
        let toc = Instant::now() - tic;
        info!(
            "Preload of tree ({} objects loaded), took {} s",
            load_count,
            toc.as_secs_f64()
        );

        self.increment_epoch();

        let mut hash_q = KeyedPriorityQueue::<NodeLabel, i32>::new();
        let mut priorities: i32 = 0;
        let mut root_node = TreeNode::get_from_storage(
            storage,
            &NodeKey(NodeLabel::root()),
            self.get_latest_epoch(),
        )
        .await?;
        for node in insertion_set {
            let new_leaf =
                get_leaf_node::<H>(node.label, &node.hash, NodeLabel::root(), self.latest_epoch);
            debug!("BEGIN insert leaf");
            root_node
                .insert_leaf::<_, H>(
                    storage,
                    new_leaf,
                    self.latest_epoch,
                    &mut self.num_nodes,
                    Some(append_only_exclude_usage),
                )
                .await?;
            debug!("END insert leaf");

            hash_q.push(node.label, priorities);
            priorities -= 1;
        }
        // Now hash up the tree, the highest priority items will be closer to the leaves.
        while let Some((next_node_label, _)) = hash_q.pop() {
            let mut next_node: TreeNode = TreeNode::get_from_storage(
                storage,
                &NodeKey(next_node_label),
                self.get_latest_epoch(),
            )
            .await?;
            next_node
                .update_node_hash::<_, H>(
                    storage,
                    self.latest_epoch,
                    Some(append_only_exclude_usage),
                )
                .await?;
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
    pub async fn get_membership_proof<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        label: NodeLabel,
        _epoch: u64,
    ) -> Result<MembershipProof<H>, AkdError> {
        let (pf, _) = self.get_membership_proof_and_node(storage, label).await?;
        Ok(pf)
    }

    // EOZ: There is a needless_range_loop warning by Clippy for `for i in 0..ARITY`
    // and the suggestion is to use `for (i, <item>) in longest_prefix_children.iter_mut().enumerate().take(ARITY)`
    // but I think this is inaccurate
    #[allow(clippy::needless_range_loop)]
    /// In a compressed trie, the proof consists of the longest prefix
    /// of the label that is included in the trie, as well as its children, to show that
    /// none of the children is equal to the given label.
    pub async fn get_non_membership_proof<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        label: NodeLabel,
    ) -> Result<NonMembershipProof<H>, AkdError> {
        let (longest_prefix_membership_proof, lcp_node_label) =
            self.get_membership_proof_and_node(storage, label).await?;
        let lcp_node: TreeNode =
            TreeNode::get_from_storage(storage, &NodeKey(lcp_node_label), self.get_latest_epoch())
                .await?;
        let longest_prefix = lcp_node.label;
        // load with placeholder nodes, to be replaced in the loop below
        let mut longest_prefix_children = [Node {
            label: EMPTY_LABEL,
            hash: crate::utils::empty_node_hash::<H>(),
        }; ARITY];
        for i in 0..ARITY {
            let child = lcp_node.get_child_state(storage, Some(i)).await?;
            match child {
                None => {
                    debug!("i = {}, empty", i);
                    continue;
                }
                Some(child) => {
                    let unwrapped_child: TreeNode = TreeNode::get_from_storage(
                        storage,
                        &NodeKey(child.label),
                        self.get_latest_epoch(),
                    )
                    .await?;
                    debug!("Label of child {} is {:?}", i, unwrapped_child.label);
                    longest_prefix_children[i] = Node {
                        label: unwrapped_child.label,
                        hash: optional_child_state_hash::<H>(&Some(unwrapped_child))?,
                    };
                }
            }
        }

        debug!("Lcp label = {:?}", longest_prefix);
        Ok(NonMembershipProof {
            label,
            longest_prefix,
            longest_prefix_children,
            longest_prefix_membership_proof,
        })
    }

    // FIXME add an error if the epochs don't exist or end is less than start ep.
    /// An append-only proof for going from `start_epoch` to `end_epoch` consists of roots of subtrees
    /// the azks tree that remain unchanged from `start_epoch` to `end_epoch` and the leaves inserted into the
    /// tree after `start_epoch` and  up until `end_epoch`.
    /// If there is no errors, this function returns an `Ok` result, containing the
    ///  append-only proof and otherwise, it returns a [errors::AkdError].
    ///
    /// **RESTRICTIONS**: Note that `start_epoch` and `end_epoch` are valid only when the following are true
    /// * `start_epoch` <= `end_epoch`
    /// * `start_epoch` and `end_epoch` are both existing epochs of this AZKS
    pub async fn get_append_only_proof<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyProof<H>, AkdError> {
        let mut proofs = Vec::<SingleAppendOnlyProof<H>>::new();
        let mut epochs = Vec::<u64>::new();
        // Suppose the epochs start_epoch and end_epoch exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.
        for ep in start_epoch..end_epoch {
            let node = TreeNode::get_from_storage(
                storage,
                &NodeKey(NodeLabel::root()),
                self.get_latest_epoch(),
            )
            .await?;
            let (unchanged, leaves) = self
                .get_append_only_proof_helper::<_, H>(storage, node, ep, ep + 1)
                .await?;
            proofs.push(SingleAppendOnlyProof {
                inserted: leaves,
                unchanged_nodes: unchanged,
            });
            epochs.push(ep);
        }

        Ok(AppendOnlyProof { proofs, epochs })
    }

    #[async_recursion]
    async fn get_append_only_proof_helper<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        node: TreeNode,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyHelper<H>, AkdError> {
        let mut unchanged = Vec::<Node<H>>::new();
        let mut leaves = Vec::<Node<H>>::new();

        if node.get_latest_epoch() <= start_epoch {
            if node.is_root() {
                // this is the case where the root is unchanged since the last epoch
                return Ok((unchanged, leaves));
            }
            unchanged.push(Node::<H> {
                label: node.label,
                hash: optional_child_state_hash::<H>(&Some(node))?,
            });

            return Ok((unchanged, leaves));
        }

        if node.least_descendent_ep > end_epoch {
            return Ok((unchanged, leaves));
        }

        if node.is_leaf() {
            leaves.push(Node::<H> {
                label: node.label,
                hash: to_digest::<H>(&node.hash)?,
            });
        } else {
            for child_label in [node.left_child, node.right_child] {
                match child_label {
                    None => {
                        continue;
                    }
                    Some(label) => {
                        let child_node = TreeNode::get_from_storage(
                            storage,
                            &NodeKey(label),
                            self.get_latest_epoch(),
                        )
                        .await?;
                        let mut rec_output = self
                            .get_append_only_proof_helper::<_, H>(
                                storage,
                                child_node,
                                start_epoch,
                                end_epoch,
                            )
                            .await?;
                        unchanged.append(&mut rec_output.0);
                        leaves.append(&mut rec_output.1);
                    }
                }
            }
        }
        Ok((unchanged, leaves))
    }

    // FIXME: these functions below should be moved into higher-level API
    /// Gets the root hash for this azks
    pub async fn get_root_hash<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
    ) -> Result<H::Digest, AkdError> {
        self.get_root_hash_at_epoch::<_, H>(storage, self.get_latest_epoch())
            .await
    }

    /// Gets the root hash of the tree at a epoch.
    /// Since this is accessing the root node and the root node exists at all epochs that
    /// the azks does, this would never be called at an epoch before the birth of the root node.
    pub async fn get_root_hash_at_epoch<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        epoch: u64,
    ) -> Result<H::Digest, AkdError> {
        if self.latest_epoch < epoch {
            // cannot retrieve information for future epoch
            return Err(AkdError::TreeNode(TreeNodeError::NonexistentAtEpoch(
                NodeLabel::root(),
                epoch,
            )));
        }
        let root_node: TreeNode = TreeNode::get_from_storage(
            storage,
            &NodeKey(NodeLabel::root()),
            self.get_latest_epoch(),
        )
        .await?;
        hash_u8_with_label::<H>(&root_node.hash, root_node.label)
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

    /// This function returns the node label for the node whose label is the longest common
    /// prefix for the queried label. It also returns a membership proof for said label.
    /// This is meant to be used in both, getting membership proofs and getting non-membership proofs.
    pub async fn get_membership_proof_and_node<S: Storage + Sync + Send, H: Hasher>(
        &self,
        storage: &S,
        label: NodeLabel,
    ) -> Result<(MembershipProof<H>, NodeLabel), AkdError> {
        let mut layer_proofs = Vec::new();
        let mut curr_node: TreeNode = TreeNode::get_from_storage(
            storage,
            &NodeKey(NodeLabel::root()),
            self.get_latest_epoch(),
        )
        .await?;

        let mut dir = curr_node.label.get_dir(label);
        let mut equal = label == curr_node.label;
        let mut prev_node = NodeLabel::root();
        while !equal && dir.is_some() {
            prev_node = curr_node.label;

            let mut nodes = [Node::<H> {
                label: EMPTY_LABEL,
                hash: crate::utils::empty_node_hash::<H>(),
            }; ARITY - 1];
            let mut count = 0;
            let direction = dir.ok_or(AkdError::TreeNode(TreeNodeError::NoDirection(
                curr_node.label,
                None,
            )))?;
            let next_state = curr_node.get_child_state(storage, Some(direction)).await?;
            if next_state.is_some() {
                for i in 0..ARITY {
                    let no_direction_error =
                        AkdError::TreeNode(TreeNodeError::NoDirection(curr_node.label, None));

                    if i != dir.ok_or(no_direction_error)? {
                        let sibling = curr_node
                            .get_child_state(storage, Direction::Some(i))
                            .await?;
                        nodes[count] = Node::<H> {
                            label: optional_child_state_to_label(&sibling),
                            hash: optional_child_state_hash::<H>(&sibling)?,
                        };
                        count += 1;
                    }
                }
            } else {
                break;
            }
            layer_proofs.push(proof_structs::LayerProof {
                label: curr_node.label,
                siblings: nodes,
                direction: dir,
            });
            let new_curr_node: TreeNode = TreeNode::get_from_storage(
                storage,
                &NodeKey(curr_node.get_child(dir).unwrap().unwrap()),
                self.get_latest_epoch(),
            )
            .await?;
            curr_node = new_curr_node;
            dir = curr_node.label.get_dir(label);
            equal = label == curr_node.label;
        }

        if !equal {
            let new_curr_node: TreeNode =
                TreeNode::get_from_storage(storage, &NodeKey(prev_node), self.get_latest_epoch())
                    .await?;
            curr_node = new_curr_node;

            layer_proofs.pop();
        }
        let hash_val = if curr_node.is_leaf() {
            H::merge_with_int(to_digest::<H>(&curr_node.hash)?, curr_node.last_epoch)
        } else {
            to_digest::<H>(&curr_node.hash)?
        };

        Ok((
            MembershipProof::<H> {
                label: curr_node.label,
                hash_val,
                layer_proofs,
            },
            prev_node,
        ))
    }
}

type AppendOnlyHelper<H> = (Vec<Node<H>>, Vec<Node<H>>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auditor::audit_verify,
        client::{verify_membership, verify_nonmembership},
        storage::memory::AsyncInMemoryDatabase,
    };
    use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type Blake3Digest = <Blake3_256<winter_math::fields::f128::BaseElement> as Hasher>::Digest;

    #[tokio::test]
    async fn test_batch_insert_basic() -> Result<(), AkdError> {
        let mut rng = OsRng;
        let num_nodes = 10;
        let db = AsyncInMemoryDatabase::new();
        let mut azks1 = Azks::new::<_, Blake3>(&db).await?;

        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3::hash(&input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
            azks1.insert_leaf::<_, Blake3>(&db, node, 1).await?;
        }

        let db2 = AsyncInMemoryDatabase::new();
        let mut azks2 = Azks::new::<_, Blake3>(&db2).await?;

        azks2
            .batch_insert_leaves::<_, Blake3>(&db2, insertion_set)
            .await?;

        assert_eq!(
            azks1.get_root_hash::<_, Blake3>(&db).await?,
            azks2.get_root_hash::<_, Blake3>(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_permuted() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;
        let db = AsyncInMemoryDatabase::new();
        let mut azks1 = Azks::new::<_, Blake3>(&db).await?;
        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
            azks1.insert_leaf::<_, Blake3>(&db, node, 1).await?;
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);

        let db2 = AsyncInMemoryDatabase::new();
        let mut azks2 = Azks::new::<_, Blake3>(&db2).await?;

        azks2
            .batch_insert_leaves::<_, Blake3>(&db2, insertion_set)
            .await?;

        assert_eq!(
            azks1.get_root_hash::<_, Blake3>(&db).await?,
            azks2.get_root_hash::<_, Blake3>(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_permuted() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);
        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set.clone())
            .await?;

        let proof = azks
            .get_membership_proof(&db, insertion_set[0].label, 1)
            .await?;

        verify_membership::<Blake3>(azks.get_root_hash::<_, Blake3>(&db).await?, &proof)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_small() -> Result<(), AkdError> {
        let num_nodes = 2;

        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for i in 0..num_nodes {
            let mut label_arr = [0u8; 32];
            label_arr[0] = u8::from(i);
            let label = NodeLabel::new(label_arr, 256u32);
            let input = [0u8; 32];
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
        }

        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set.clone())
            .await?;

        let proof = azks
            .get_membership_proof(&db, insertion_set[0].label, 1)
            .await?;

        verify_membership::<Blake3>(azks.get_root_hash::<_, Blake3>(&db).await?, &proof)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_failing() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);
        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set.clone())
            .await?;

        let mut proof = azks
            .get_membership_proof(&db, insertion_set[0].label, 1)
            .await?;
        let hash_val = Blake3::hash(&EMPTY_VALUE);
        proof = MembershipProof::<Blake3> {
            label: proof.label,
            hash_val,
            layer_proofs: proof.layer_proofs,
        };
        assert!(
            !verify_membership::<Blake3>(azks.get_root_hash::<_, Blake3>(&db).await?, &proof)
                .is_ok(),
            "Membership proof does verify, despite being wrong"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_intermediate() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();

        let mut insertion_set: Vec<Node<Blake3>> = vec![];
        insertion_set.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        insertion_set.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        insertion_set.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b11 << 62), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        insertion_set.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        insertion_set.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set)
            .await?;
        let search_label = NodeLabel::new(byte_arr_from_u64(0b1111 << 60), 64);
        let proof = azks.get_non_membership_proof(&db, search_label).await?;
        assert!(
            verify_nonmembership::<Blake3>(azks.get_root_hash::<_, Blake3>(&db).await?, &proof)?,
            "Nonmembership proof does not verify"
        );
        Ok(())
    }

    // This test checks that a non-membership proof in a tree with 1 leaf verifies.
    #[tokio::test]
    async fn test_nonmembership_proof_very_small() -> Result<(), AkdError> {
        let num_nodes = 2;

        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for i in 0..num_nodes {
            let mut label_arr = [0u8; 32];
            label_arr[31] = u8::from(i);
            let label = NodeLabel::new(label_arr, 256u32);
            let mut input = [0u8; 32];
            input[31] = u8::from(i);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
        }
        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        let search_label = insertion_set[0].label;
        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set.clone()[1..2].to_vec())
            .await?;
        let proof = azks.get_non_membership_proof(&db, search_label).await?;

        verify_nonmembership::<Blake3>(azks.get_root_hash::<_, Blake3>(&db).await?, &proof)?;

        Ok(())
    }

    // This test verifies if a non-membership proof in a small tree of 2 leaves
    // verifies.
    #[tokio::test]
    async fn test_nonmembership_proof_small() -> Result<(), AkdError> {
        let num_nodes = 3;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
        }
        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        let search_label = insertion_set[num_nodes - 1].label;
        azks.batch_insert_leaves::<_, Blake3>(
            &db,
            insertion_set.clone()[0..num_nodes - 1].to_vec(),
        )
        .await?;
        let proof = azks.get_non_membership_proof(&db, search_label).await?;

        verify_nonmembership::<Blake3>(azks.get_root_hash::<_, Blake3>(&db).await?, &proof)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_nonmembership_proof() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set.push(node);
        }
        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        let search_label = insertion_set[num_nodes - 1].label;
        azks.batch_insert_leaves::<_, Blake3>(
            &db,
            insertion_set.clone()[0..num_nodes - 1].to_vec(),
        )
        .await?;
        let proof = azks.get_non_membership_proof(&db, search_label).await?;

        verify_nonmembership::<Blake3>(azks.get_root_hash::<_, Blake3>(&db).await?, &proof)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_append_only_proof_very_tiny() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;

        let mut insertion_set_1: Vec<Node<Blake3>> = vec![];
        insertion_set_1.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set_1)
            .await?;
        let start_hash = azks.get_root_hash::<_, Blake3>(&db).await?;

        let mut insertion_set_2: Vec<Node<Blake3>> = vec![];
        insertion_set_2.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });

        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set_2)
            .await?;
        let end_hash = azks.get_root_hash::<_, Blake3>(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 2).await?;
        audit_verify::<Blake3>(vec![start_hash, end_hash], proof).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_append_only_proof_tiny() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;

        let mut insertion_set_1: Vec<Node<Blake3>> = vec![];
        insertion_set_1.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        insertion_set_1.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });

        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set_1)
            .await?;
        let start_hash = azks.get_root_hash::<_, Blake3>(&db).await?;

        let mut insertion_set_2: Vec<Node<Blake3>> = vec![];
        insertion_set_2.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b1 << 62), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });
        insertion_set_2.push(Node {
            label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
            hash: Blake3::hash(&EMPTY_VALUE),
        });

        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set_2)
            .await?;
        let end_hash = azks.get_root_hash::<_, Blake3>(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 2).await?;
        audit_verify::<Blake3>(vec![start_hash, end_hash], proof).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_append_only_proof() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set_1: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set_1.push(node);
        }

        let db = AsyncInMemoryDatabase::new();
        let mut azks = Azks::new::<_, Blake3>(&db).await?;
        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set_1.clone())
            .await?;

        let start_hash = azks.get_root_hash::<_, Blake3>(&db).await?;

        let mut insertion_set_2: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set_2.push(node);
        }

        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set_2.clone())
            .await?;

        let middle_hash = azks.get_root_hash::<_, Blake3>(&db).await?;

        let mut insertion_set_3: Vec<Node<Blake3>> = vec![];

        for _ in 0..num_nodes {
            let label = NodeLabel::random(&mut rng);
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let hash = Blake3Digest::new(input);
            let node = Node::<Blake3> { label, hash };
            insertion_set_3.push(node);
        }

        azks.batch_insert_leaves::<_, Blake3>(&db, insertion_set_3.clone())
            .await?;

        let end_hash = azks.get_root_hash::<_, Blake3>(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 3).await?;
        let hashes = vec![start_hash, middle_hash, end_hash];
        audit_verify::<Blake3>(hashes, proof).await?;

        Ok(())
    }

    #[tokio::test]
    async fn future_epoch_throws_error() -> Result<(), AkdError> {
        let db = AsyncInMemoryDatabase::new();
        let azks = Azks::new::<_, Blake3>(&db).await?;

        let out = azks.get_root_hash_at_epoch::<_, Blake3>(&db, 123).await;

        let expected = Err::<_, AkdError>(AkdError::TreeNode(TreeNodeError::NonexistentAtEpoch(
            NodeLabel::root(),
            123,
        )));
        assert_eq!(expected, out);
        Ok(())
    }
}
