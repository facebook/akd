// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of an append-only zero knowledge set
use crate::errors::TreeNodeError;
use crate::storage::manager::StorageManager;
use crate::storage::types::StorageType;
use crate::{
    errors::{AkdError, DirectoryError},
    storage::{Database, Storable},
    tree_node::*,
    AppendOnlyProof, Digest, Direction, LayerProof, MembershipProof, Node, NodeLabel,
    NonMembershipProof, SingleAppendOnlyProof, ARITY, DIRECTIONS, EMPTY_LABEL,
};

use akd_core::SizeOf;
use async_recursion::async_recursion;
use log::info;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::marker::{Send, Sync};

/// The default azks key
pub const DEFAULT_AZKS_KEY: u8 = 1u8;

async fn tic_toc<T>(f: impl core::future::Future<Output = T>) -> (T, Option<f64>) {
    #[cfg(feature = "runtime_metrics")]
    {
        let tic = std::time::Instant::now();
        let out = f.await;
        let toc = std::time::Instant::now() - tic;
        (out, Some(toc.as_secs_f64()))
    }
    #[cfg(not(feature = "runtime_metrics"))]
    (f.await, None)
}

/// An azks is built both by the [crate::directory::Directory] and the auditor.
/// However, both constructions have very minor differences, and the insert
/// mode enum is used to differentiate between the two.
#[derive(Debug, Clone, Copy)]
pub(crate) enum InsertMode {
    /// The regular construction of the the tree.
    Directory,
    /// The auditor's mode of constructing the tree - last epochs of leaves are
    /// not included in node hashes.
    Auditor,
}

impl From<InsertMode> for NodeHashingMode {
    fn from(mode: InsertMode) -> Self {
        match mode {
            InsertMode::Directory => NodeHashingMode::WithLeafEpoch,
            InsertMode::Auditor => NodeHashingMode::NoLeafEpoch,
        }
    }
}

/// An append-only zero knowledge set, the data structure used to efficiently implement
/// a auditable key directory.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
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

impl SizeOf for Azks {
    fn size_of(&self) -> usize {
        std::mem::size_of::<u64>() * 2
    }
}

impl Storable for Azks {
    type StorageKey = u8;

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

impl Azks {
    /// Creates a new azks
    pub async fn new<S: Database + Sync + Send>(
        storage: &StorageManager<S>,
    ) -> Result<Self, AkdError> {
        create_empty_root::<S>(storage, Option::Some(0), Option::Some(0)).await?;
        let azks = Azks {
            latest_epoch: 0,
            num_nodes: 1,
        };

        Ok(azks)
    }

    /// Insert a batch of new leaves.
    pub(crate) async fn batch_insert_leaves<S: Database + Sync + Send>(
        &mut self,
        storage: &StorageManager<S>,
        insertion_set: Vec<Node>,
        insert_mode: InsertMode,
    ) -> Result<(), AkdError> {
        // preload the nodes that we will visit during the insertion
        let (fallable_load_count, time_s) =
            tic_toc(self.preload_nodes_for_insertion(storage, &insertion_set)).await;
        let load_count = fallable_load_count?;

        if let Some(time) = time_s {
            info!(
                "Preload of tree ({} objects loaded), took {} s",
                load_count, time,
            );
        } else {
            info!("Preload of tree ({} objects loaded) completed", load_count);
        }

        // increment the current epoch
        self.increment_epoch();

        if !insertion_set.is_empty() {
            // call recursive batch insert on the root
            let (_, num_inserted) = Self::recursive_batch_insert_leaves(
                storage,
                Some(NodeLabel::root()),
                insertion_set,
                self.latest_epoch,
                insert_mode,
            )
            .await?;

            // update the number of nodes
            self.num_nodes += num_inserted;

            info!("Batch insert completed ({} new nodes)", num_inserted);
        }

        Ok(())
    }

    async fn preload_nodes_for_insertion<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        insertion_set: &[Node],
    ) -> Result<u64, AkdError> {
        let insertion_labels = insertion_set
            .iter()
            .map(|n| n.label)
            .collect::<Vec<NodeLabel>>();

        self.bfs_preload_nodes_sorted::<S>(storage, &insertion_labels)
            .await
    }

    /// Given a sorted list of [NodeLabel]s, determine if a given [NodeLabel] is a prefix of any in the list.
    fn insertion_set_contains(insertion_labels: &[NodeLabel], label: &NodeLabel) -> bool {
        insertion_labels
            .binary_search_by(|candidate| {
                match label.label_len == 0 || label.is_prefix_of(candidate) {
                    true => Ordering::Equal,
                    false => candidate.label_val.cmp(&label.label_val),
                }
            })
            .is_ok()
    }

    /// Preloads given nodes using breadth-first search.
    pub async fn bfs_preload_nodes_sorted<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        insertion_labels: &[NodeLabel],
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
                if !Self::insertion_set_contains(insertion_labels, &node.label) {
                    // Only continue to traverse nodes which are relevant prefixes to insertion_set
                    continue;
                }

                for dir in crate::DIRECTIONS {
                    let child_label = node.get_child_label(dir)?;
                    if let Some(child_label) = child_label {
                        current_nodes.push(NodeKey(child_label));
                    }
                }
            }
        }
        Ok(load_count)
    }

    /// Preloads given nodes using breadth-first search.
    pub async fn bfs_preload_nodes<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
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

                for dir in crate::DIRECTIONS {
                    let child_label = node.get_child_label(dir)?;
                    if let Some(child_label) = child_label {
                        current_nodes.push(NodeKey(child_label));
                    }
                }
            }
        }
        Ok(load_count)
    }

    /// Inserts a batch of leaves recursively from a given node label.
    #[async_recursion]
    pub(crate) async fn recursive_batch_insert_leaves<S: Database + Sync + Send>(
        storage: &StorageManager<S>,
        node_label: Option<NodeLabel>,
        insertion_set: Vec<Node>,
        epoch: u64,
        insert_mode: InsertMode,
    ) -> Result<(TreeNode, u64), AkdError> {
        // Phase 1: Obtain the current root node of this subtree and count if a
        // node is inserted.
        let mut current_node;
        let mut num_inserted;

        match (node_label, &insertion_set[..]) {
            (Some(node_label), _) => {
                // Case 1: The node label is not None, meaning that there was an
                // existing node at this level of the tree.
                let mut existing_node =
                    TreeNode::get_from_storage(storage, &NodeKey(node_label), epoch).await?;

                // compute the longest common prefix between all nodes in the
                // insertion set and the current node, and check if new nodes
                // have a longest common prefix shorter than the current node.
                let insertion_lcp_label = get_longest_common_prefix(&insertion_set);
                let lcp_label = node_label.get_longest_common_prefix(insertion_lcp_label);
                if lcp_label.get_len() < node_label.get_len() {
                    // Case 1a: The existing node needs to be decompressed, by
                    // pushing it down one level (away from root) in the tree
                    // and replacing it with a new node whose label is equal to
                    // the longest common prefix.
                    current_node = create_interior_node_from_existing_node(
                        storage,
                        &mut existing_node,
                        lcp_label,
                        epoch,
                    )
                    .await?;
                    num_inserted = 1;
                } else {
                    // Case 1b: The existing node does not need to be
                    // decompressed as its label is longer than or equal to the
                    // longest common prefix of the insertion set.
                    current_node = existing_node;
                    num_inserted = 0;
                }
            }
            (None, [node]) => {
                // Case 2: The node label is None and the insertion set has a
                // single element, meaning that a new leaf node should be
                // created to represent the element.
                current_node = create_leaf_node(storage, node.label, &node.hash, epoch).await?;
                num_inserted = 1;
            }
            (None, _) => {
                // Case 3: The node label is None and the insertion still has
                // multiple elements, meaning that a new interior node should be
                // created with a label equal to the longest common prefix of
                // the insertion set.
                let lcp_label = get_longest_common_prefix(&insertion_set);
                current_node = create_interior_node(storage, lcp_label, epoch).await?;
                num_inserted = 1;
            }
        }

        // Phase 2: Partition the insertion set based on the direction the leaf
        // nodes are located in with respect to the current node and call this
        // function recursively on the left and right child nodes. The current
        // node is updated with the new child nodes.
        let (left_insertion_set, right_insertion_set) =
            partition_longest_common_prefix(insertion_set, current_node.label);

        if !left_insertion_set.is_empty() {
            let (mut left_node, left_num_inserted) = Self::recursive_batch_insert_leaves(
                storage,
                current_node.get_child_label(Direction::Left)?,
                left_insertion_set,
                epoch,
                insert_mode,
            )
            .await?;

            current_node.set_child(storage, &mut left_node).await?;
            num_inserted += left_num_inserted;
        }

        if !right_insertion_set.is_empty() {
            let (mut right_node, right_num_inserted) = Self::recursive_batch_insert_leaves(
                storage,
                current_node.get_child_label(Direction::Right)?,
                right_insertion_set,
                epoch,
                insert_mode,
            )
            .await?;

            current_node.set_child(storage, &mut right_node).await?;
            num_inserted += right_num_inserted;
        }

        // Phase 3: Update the hash of the current node and return it along with
        // the number of nodes inserted.
        current_node
            .update_node_hash::<_>(storage, NodeHashingMode::from(insert_mode))
            .await?;

        Ok((current_node, num_inserted))
    }

    /// Returns the Merkle membership proof for the trie as it stood at epoch
    // Assumes the verifier has access to the root at epoch
    pub async fn get_membership_proof<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
        _epoch: u64,
    ) -> Result<MembershipProof, AkdError> {
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
    pub async fn get_non_membership_proof<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<NonMembershipProof, AkdError> {
        let (longest_prefix_membership_proof, lcp_node_label) =
            self.get_membership_proof_and_node(storage, label).await?;
        let lcp_node: TreeNode =
            TreeNode::get_from_storage(storage, &NodeKey(lcp_node_label), self.get_latest_epoch())
                .await?;
        let longest_prefix = lcp_node.label;
        // load with placeholder nodes, to be replaced in the loop below
        let mut longest_prefix_children = [Node {
            label: EMPTY_LABEL,
            hash: crate::utils::empty_node_hash(),
        }; ARITY];
        for dir in DIRECTIONS {
            let child = lcp_node
                .get_child_node(storage, dir, self.latest_epoch)
                .await?;
            match child {
                None => {
                    continue;
                }
                Some(child) => {
                    let unwrapped_child: TreeNode = TreeNode::get_from_storage(
                        storage,
                        &NodeKey(child.label),
                        self.get_latest_epoch(),
                    )
                    .await?;
                    longest_prefix_children[dir as usize] = Node {
                        label: unwrapped_child.label,
                        hash: optional_child_state_hash(&Some(unwrapped_child)),
                    };
                }
            }
        }

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
    pub async fn get_append_only_proof<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyProof, AkdError> {
        let mut proofs = Vec::<SingleAppendOnlyProof>::new();
        let mut epochs = Vec::<u64>::new();
        // Suppose the epochs start_epoch and end_epoch exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.

        let node = TreeNode::get_from_storage(
            storage,
            &NodeKey(NodeLabel::root()),
            self.get_latest_epoch(),
        )
        .await?;

        for ep in start_epoch..end_epoch {
            let (fallable_load_count, time_s) = tic_toc(self.gather_audit_proof_nodes::<_>(
                vec![node.clone()],
                storage,
                ep,
                ep + 1,
            ))
            .await;
            let load_count = fallable_load_count?;
            if let Some(time) = time_s {
                info!(
                    "Preload of nodes for audit ({} objects loaded), took {} s",
                    load_count, time,
                );
            } else {
                info!(
                    "Preload of nodes for audit ({} objects loaded) completed.",
                    load_count
                );
            }
            storage.log_metrics(log::Level::Info).await;

            let (unchanged, leaves) = self
                .get_append_only_proof_helper::<_>(storage, node.clone(), ep, ep + 1)
                .await?;
            proofs.push(SingleAppendOnlyProof {
                inserted: leaves,
                unchanged_nodes: unchanged,
            });
            epochs.push(ep);
        }

        Ok(AppendOnlyProof { proofs, epochs })
    }

    fn determine_retrieval_nodes(
        node: &TreeNode,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Vec<NodeLabel> {
        if node.node_type == NodeType::Leaf {
            return vec![];
        }

        if node.get_latest_epoch() <= start_epoch {
            return vec![];
        }

        if node.min_descendant_epoch > end_epoch {
            return vec![];
        }

        match (node.left_child, node.right_child) {
            (Some(lc), None) => vec![lc],
            (None, Some(rc)) => vec![rc],
            (Some(lc), Some(rc)) => vec![lc, rc],
            _ => vec![],
        }
    }

    async fn gather_audit_proof_nodes<S: Database + Sync + Send>(
        &self,
        nodes: Vec<TreeNode>,
        storage: &StorageManager<S>,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<u64, AkdError> {
        let mut children_to_fetch: Vec<NodeKey> = nodes
            .iter()
            .flat_map(|node| Self::determine_retrieval_nodes(node, start_epoch, end_epoch))
            .map(NodeKey)
            .collect();

        let mut element_count = 0u64;
        while !children_to_fetch.is_empty() {
            let got = TreeNode::batch_get_from_storage(
                storage,
                &children_to_fetch,
                self.get_latest_epoch(),
            )
            .await?;
            element_count += got.len() as u64;
            children_to_fetch = got
                .iter()
                .flat_map(|node| Self::determine_retrieval_nodes(node, start_epoch, end_epoch))
                .map(NodeKey)
                .collect();
        }
        Ok(element_count)
    }

    #[async_recursion]
    async fn get_append_only_proof_helper<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        node: TreeNode,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyHelper, AkdError> {
        let mut unchanged = Vec::<Node>::new();
        let mut leaves = Vec::<Node>::new();

        if node.get_latest_epoch() <= start_epoch {
            if node.node_type == NodeType::Root {
                // this is the case where the root is unchanged since the last epoch
                return Ok((unchanged, leaves));
            }
            unchanged.push(Node {
                label: node.label,
                hash: optional_child_state_hash(&Some(node)),
            });

            return Ok((unchanged, leaves));
        }

        if node.min_descendant_epoch > end_epoch {
            return Ok((unchanged, leaves));
        }

        if node.node_type == NodeType::Leaf {
            leaves.push(Node {
                label: node.label,
                hash: node.hash,
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
                        let (mut inner_unchanged, mut inner_leaf) = self
                            .get_append_only_proof_helper::<_>(
                                storage,
                                child_node,
                                start_epoch,
                                end_epoch,
                            )
                            .await?;
                        unchanged.append(&mut inner_unchanged);
                        leaves.append(&mut inner_leaf);
                    }
                }
            }
        }
        Ok((unchanged, leaves))
    }

    // FIXME: these functions below should be moved into higher-level API
    /// Gets the root hash for this azks
    pub async fn get_root_hash<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
    ) -> Result<Digest, AkdError> {
        self.get_root_hash_safe::<_>(storage, self.get_latest_epoch())
            .await
    }

    /// Gets the root hash of the tree at the latest epoch if the passed epoch
    /// is equal to the latest epoch. Will return an error otherwise.
    pub async fn get_root_hash_safe<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        epoch: u64,
    ) -> Result<Digest, AkdError> {
        if self.latest_epoch != epoch {
            // cannot retrieve information for non-latest epoch
            return Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "Passed epoch ({}) was not the latest epoch ({}).",
                epoch, self.latest_epoch
            ))));
        }
        let root_node: TreeNode =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), self.latest_epoch)
                .await?;
        Ok(merge_digest_with_label_hash(
            &root_node.hash,
            root_node.label,
        ))
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

    /// Gets the sibling node of the passed node's child in the "opposite" of the passed direction.
    async fn get_sibling_node<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        curr_node: &TreeNode,
        other_dir: Direction,
        latest_epoch: u64,
    ) -> Result<Option<Node>, AkdError> {
        let child = curr_node
            .get_child_node(storage, other_dir, latest_epoch)
            .await?;
        if child.is_none() {
            return Ok(None);
        }

        // Find the sibling in the "other" direction
        for i_dir in DIRECTIONS {
            if i_dir == other_dir {
                continue;
            }
            let sibling = curr_node
                .get_child_node(storage, i_dir, latest_epoch)
                .await?;
            return Ok(Some(Node {
                label: optional_child_state_to_label(&sibling),
                hash: optional_child_state_hash(&sibling),
            }));
        }

        Ok(None)
    }

    /// This function returns the node label for the node whose label is the longest common
    /// prefix for the queried label. It also returns a membership proof for said label.
    /// This is meant to be used in both getting membership proofs and getting non-membership proofs.
    pub async fn get_membership_proof_and_node<S: Database + Sync + Send>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<(MembershipProof, NodeLabel), AkdError> {
        let mut layer_proofs = Vec::new();
        let latest_epoch = self.get_latest_epoch();

        // Perform a traversal from the root to the node corresponding to the queried label
        let mut curr_node =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), latest_epoch).await?;

        let mut dir = curr_node.label.get_dir(label);
        let mut equal = label == curr_node.label;
        let mut prev_node = curr_node.label;
        while !equal && dir != Direction::None {
            prev_node = curr_node.label;

            // Find the sibling node. Note that for ARITY = 2, this does not need to be
            // an array, as it can just be a single node.
            match self
                .get_sibling_node(storage, &curr_node, dir, latest_epoch)
                .await?
            {
                None => break,
                Some(sibling_node) => {
                    layer_proofs.push(LayerProof {
                        label: curr_node.label,
                        siblings: [sibling_node],
                        direction: dir,
                    });
                }
            };

            curr_node = TreeNode::get_from_storage(
                storage,
                &NodeKey(curr_node.get_child_label(dir)?.ok_or(AkdError::TreeNode(
                    TreeNodeError::NoDirection(curr_node.label, None),
                ))?),
                latest_epoch,
            )
            .await?;
            dir = curr_node.label.get_dir(label);
            equal = label == curr_node.label;
        }

        if !equal {
            let new_curr_node: TreeNode =
                TreeNode::get_from_storage(storage, &NodeKey(prev_node), latest_epoch).await?;
            curr_node = new_curr_node;

            layer_proofs.pop();
        }
        let hash_val = if curr_node.node_type == NodeType::Leaf {
            crate::hash::merge_with_int(curr_node.hash, curr_node.last_epoch)
        } else {
            curr_node.hash
        };

        Ok((
            MembershipProof {
                label: curr_node.label,
                hash_val,
                layer_proofs,
            },
            prev_node,
        ))
    }
}

type AppendOnlyHelper = (Vec<Node>, Vec<Node>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::byte_arr_from_u64;
    use crate::{
        auditor::audit_verify,
        client::{verify_membership, verify_nonmembership},
        storage::memory::AsyncInMemoryDatabase,
        EMPTY_VALUE,
    };
    use rand::{rngs::OsRng, seq::SliceRandom, RngCore};

    #[tokio::test]
    async fn test_batch_insert_basic() -> Result<(), AkdError> {
        let mut rng = OsRng;
        let num_nodes = 10;
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks1 = Azks::new::<_>(&db).await?;
        azks1.increment_epoch();

        let mut insertion_set: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut input = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut input);
            let hash = crate::hash::hash(&input);
            let node = Node { label, hash };
            insertion_set.push(node);
            Azks::recursive_batch_insert_leaves(
                &db,
                Some(NodeLabel::root()),
                vec![node],
                1,
                InsertMode::Directory,
            )
            .await?;
        }

        let database2 = AsyncInMemoryDatabase::new();
        let db2 = StorageManager::new_no_cache(&database2);
        let mut azks2 = Azks::new::<_>(&db2).await?;

        azks2
            .batch_insert_leaves(&db2, insertion_set, InsertMode::Directory)
            .await?;

        assert_eq!(
            azks1.get_root_hash::<_>(&db).await?,
            azks2.get_root_hash::<_>(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_insert_permuted() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks1 = Azks::new::<_>(&db).await?;
        azks1.increment_epoch();
        let mut insertion_set: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set.push(node);
            Azks::recursive_batch_insert_leaves(
                &db,
                Some(NodeLabel::root()),
                vec![node],
                1,
                InsertMode::Directory,
            )
            .await?;
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);

        let database2 = AsyncInMemoryDatabase::new();
        let db2 = StorageManager::new_no_cache(&database2);
        let mut azks2 = Azks::new(&db2).await?;

        azks2
            .batch_insert_leaves(&db2, insertion_set, InsertMode::Directory)
            .await?;

        assert_eq!(
            azks1.get_root_hash::<_>(&db).await?,
            azks2.get_root_hash::<_>(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_get_sibling_node() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set.push(node);
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;
        azks.batch_insert_leaves::<_>(&db, insertion_set.clone(), InsertMode::Directory)
            .await?;

        // Recursively traverse the tree and check that the sibling of each node is correct
        let root_node = TreeNode::get_from_storage(&db, &NodeKey(NodeLabel::root()), 1).await?;
        let mut nodes: Vec<TreeNode> = vec![root_node];
        while !nodes.is_empty() {
            let current_node = nodes.pop().unwrap();

            let left_child = current_node.get_child_node(&db, Direction::Left, 1).await?;
            let right_child = current_node
                .get_child_node(&db, Direction::Right, 1)
                .await?;

            match left_child {
                Some(left_child) => {
                    let sibling_label = azks
                        .get_sibling_node(&db, &current_node, Direction::Right, 1)
                        .await?
                        .unwrap()
                        .label;
                    assert_eq!(left_child.label, sibling_label);
                    nodes.push(left_child);
                }
                None => {}
            }

            match right_child {
                Some(right_child) => {
                    let sibling_label = azks
                        .get_sibling_node(&db, &current_node, Direction::Left, 1)
                        .await?
                        .unwrap()
                        .label;
                    assert_eq!(right_child.label, sibling_label);
                    nodes.push(right_child);
                }
                None => {}
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_permuted() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set.push(node);
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;
        azks.batch_insert_leaves::<_>(&db, insertion_set.clone(), InsertMode::Directory)
            .await?;

        let proof = azks
            .get_membership_proof(&db, insertion_set[0].label, 1)
            .await?;

        verify_membership(azks.get_root_hash::<_>(&db).await?, &proof)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_small() -> Result<(), AkdError> {
        for num_nodes in 1..10 {
            let mut insertion_set: Vec<Node> = vec![];

            for i in 0..num_nodes {
                let mut label_arr = [0u8; 32];
                label_arr[0] = i;
                let label = NodeLabel::new(label_arr, 256u32);
                let node = Node {
                    label,
                    hash: crate::hash::EMPTY_DIGEST,
                };
                insertion_set.push(node);
            }

            let database = AsyncInMemoryDatabase::new();
            let db = StorageManager::new_no_cache(&database);
            let mut azks = Azks::new::<_>(&db).await?;
            azks.batch_insert_leaves::<_>(&db, insertion_set.clone(), InsertMode::Directory)
                .await?;

            let proof = azks
                .get_membership_proof(&db, insertion_set[0].label, 1)
                .await?;

            verify_membership(azks.get_root_hash::<_>(&db).await?, &proof)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_failing() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set.push(node);
        }

        // Try randomly permuting
        insertion_set.shuffle(&mut rng);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;
        azks.batch_insert_leaves::<_>(&db, insertion_set.clone(), InsertMode::Directory)
            .await?;

        let mut proof = azks
            .get_membership_proof(&db, insertion_set[0].label, 1)
            .await?;
        let hash_val = crate::hash::hash(&EMPTY_VALUE);
        proof = MembershipProof {
            label: proof.label,
            hash_val,
            layer_proofs: proof.layer_proofs,
        };
        assert!(
            verify_membership(azks.get_root_hash::<_>(&db).await?, &proof).is_err(),
            "Membership proof does verify, despite being wrong"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_membership_proof_intermediate() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);

        let insertion_set: Vec<Node> = vec![
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b11 << 62), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
        ];

        let mut azks = Azks::new::<_>(&db).await?;
        azks.batch_insert_leaves::<_>(&db, insertion_set, InsertMode::Directory)
            .await?;
        let search_label = NodeLabel::new(byte_arr_from_u64(0b1111 << 60), 64);
        let proof = azks.get_non_membership_proof(&db, search_label).await?;
        assert!(
            verify_nonmembership(azks.get_root_hash::<_>(&db).await?, &proof).is_ok(),
            "Nonmembership proof does not verify"
        );
        Ok(())
    }

    // This test checks that a non-membership proof in a tree with 1 leaf verifies.
    #[tokio::test]
    async fn test_nonmembership_proof_very_small() -> Result<(), AkdError> {
        let num_nodes = 2;

        let mut insertion_set: Vec<Node> = vec![];

        for i in 0..num_nodes {
            let mut label_arr = [0u8; 32];
            label_arr[31] = i;
            let label = NodeLabel::new(label_arr, 256u32);
            let mut hash = crate::hash::EMPTY_DIGEST;
            hash[31] = i;
            let node = Node { label, hash };
            insertion_set.push(node);
        }
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;
        let search_label = insertion_set[0].label;
        azks.batch_insert_leaves::<_>(
            &db,
            insertion_set.clone()[1..2].to_vec(),
            InsertMode::Directory,
        )
        .await?;
        let proof = azks.get_non_membership_proof(&db, search_label).await?;

        verify_nonmembership(azks.get_root_hash::<_>(&db).await?, &proof)?;

        Ok(())
    }

    // This test verifies if a non-membership proof in a small tree of 2 leaves
    // verifies.
    #[tokio::test]
    async fn test_nonmembership_proof_small() -> Result<(), AkdError> {
        let num_nodes = 3;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set.push(node);
        }
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;
        let search_label = insertion_set[num_nodes - 1].label;
        azks.batch_insert_leaves::<_>(
            &db,
            insertion_set.clone()[0..num_nodes - 1].to_vec(),
            InsertMode::Directory,
        )
        .await?;
        let proof = azks.get_non_membership_proof(&db, search_label).await?;

        verify_nonmembership(azks.get_root_hash::<_>(&db).await?, &proof)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_nonmembership_proof() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set.push(node);
        }
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;
        let search_label = insertion_set[num_nodes - 1].label;
        azks.batch_insert_leaves::<_>(
            &db,
            insertion_set.clone()[0..num_nodes - 1].to_vec(),
            InsertMode::Directory,
        )
        .await?;
        let proof = azks.get_non_membership_proof(&db, search_label).await?;

        verify_nonmembership(azks.get_root_hash::<_>(&db).await?, &proof)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_append_only_proof_very_tiny() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;

        let insertion_set_1: Vec<Node> = vec![Node {
            label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
            hash: crate::hash::hash(&EMPTY_VALUE),
        }];
        azks.batch_insert_leaves::<_>(&db, insertion_set_1, InsertMode::Directory)
            .await?;
        let start_hash = azks.get_root_hash::<_>(&db).await?;

        let insertion_set_2: Vec<Node> = vec![Node {
            label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
            hash: crate::hash::hash(&EMPTY_VALUE),
        }];

        azks.batch_insert_leaves::<_>(&db, insertion_set_2, InsertMode::Directory)
            .await?;
        let end_hash = azks.get_root_hash::<_>(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 2).await?;
        audit_verify(vec![start_hash, end_hash], proof).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_append_only_proof_tiny() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;

        let insertion_set_1: Vec<Node> = vec![
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
        ];

        azks.batch_insert_leaves::<_>(&db, insertion_set_1, InsertMode::Directory)
            .await?;
        let start_hash = azks.get_root_hash::<_>(&db).await?;

        let insertion_set_2: Vec<Node> = vec![
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b1 << 62), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
            Node {
                label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
                hash: crate::hash::hash(&EMPTY_VALUE),
            },
        ];

        azks.batch_insert_leaves::<_>(&db, insertion_set_2, InsertMode::Directory)
            .await?;
        let end_hash = azks.get_root_hash::<_>(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 2).await?;
        audit_verify(vec![start_hash, end_hash], proof).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_append_only_proof() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = OsRng;

        let mut insertion_set_1: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set_1.push(node);
        }

        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(&database);
        let mut azks = Azks::new::<_>(&db).await?;
        azks.batch_insert_leaves::<_>(&db, insertion_set_1.clone(), InsertMode::Directory)
            .await?;

        let start_hash = azks.get_root_hash::<_>(&db).await?;

        let mut insertion_set_2: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set_2.push(node);
        }

        azks.batch_insert_leaves::<_>(&db, insertion_set_2.clone(), InsertMode::Directory)
            .await?;

        let middle_hash = azks.get_root_hash::<_>(&db).await?;

        let mut insertion_set_3: Vec<Node> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = Node { label, hash };
            insertion_set_3.push(node);
        }

        azks.batch_insert_leaves::<_>(&db, insertion_set_3.clone(), InsertMode::Directory)
            .await?;

        let end_hash = azks.get_root_hash::<_>(&db).await?;

        let proof = azks.get_append_only_proof(&db, 1, 3).await?;
        let hashes = vec![start_hash, middle_hash, end_hash];
        audit_verify(hashes, proof).await?;

        Ok(())
    }

    #[tokio::test]
    async fn future_epoch_throws_error() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();

        let db = StorageManager::new_no_cache(&database);
        let azks = Azks::new::<_>(&db).await?;

        let out = azks.get_root_hash_safe::<_>(&db, 123).await;

        assert!(matches!(
            out,
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(_)))
        ));
        Ok(())
    }
}
