// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! An implementation of an append-only zero knowledge set

use crate::hash::EMPTY_DIGEST;
use crate::helper_structs::LookupInfo;
use crate::storage::manager::StorageManager;
use crate::storage::types::StorageType;
use crate::tree_node::{
    new_interior_node, new_leaf_node, new_root_node, node_to_azks_value, node_to_label,
    NodeHashingMode, NodeKey, TreeNode, TreeNodeType,
};
use crate::Configuration;
use crate::{
    errors::{AkdError, DirectoryError, ParallelismError, TreeNodeError},
    storage::{Database, Storable},
    AppendOnlyProof, AzksElement, AzksValue, Digest, Direction, MembershipProof, NodeLabel,
    NonMembershipProof, PrefixOrdering, SiblingProof, SingleAppendOnlyProof, SizeOf, ARITY,
};
use async_recursion::async_recursion;
use log::info;
use std::cmp::Ordering;
#[cfg(feature = "greedy_lookup_preload")]
use std::collections::HashSet;
use std::convert::TryFrom;
use std::marker::Sync;
use std::ops::Deref;

/// The default azks key
pub const DEFAULT_AZKS_KEY: u8 = 1u8;

/// The default available parallelism for parallel batch insertions, used when
/// available parallelism cannot be determined at runtime. Should be > 1
#[cfg(feature = "parallel_insert")]
pub const DEFAULT_AVAILABLE_PARALLELISM: usize = 32;

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

fn get_parallel_levels() -> Option<u8> {
    #[cfg(not(feature = "parallel_insert"))]
    return None;

    #[cfg(feature = "parallel_insert")]
    {
        // Based on profiling results, the best performance is achieved when the
        // number of spawned tasks is equal to the number of available threads.
        // We therefore get the number of available threads and calculate the
        // number of levels that should be executed in parallel to give the
        // number of tasks closest to the number of threads. While there might
        // be other tasks that are running on the threads, this is a reasonable
        // approximation that should yield good performance in most cases.
        let available_parallelism = std::thread::available_parallelism()
            .map_or(DEFAULT_AVAILABLE_PARALLELISM, |v| v.into());
        // The number of tasks spawned at a level is the number of leaves at
        // the level. As we are using a binary tree, the number of leaves at a
        // level is 2^level. Therefore, the number of levels that should be
        // executed in parallel is the log2 of the number of available threads.
        let parallel_levels = (available_parallelism as f32).log2().ceil() as u8;

        info!(
            "Insert will be performed in parallel (available parallelism: {}, parallel levels: {})",
            available_parallelism, parallel_levels
        );
        Some(parallel_levels)
    }
}

/// An azks is built both by the [crate::directory::Directory] and the auditor.
/// However, both constructions have very minor differences, and the insert
/// mode enum is used to differentiate between the two.
#[derive(Debug, Clone, Copy)]
pub enum InsertMode {
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

/// A set of nodes to be inserted into the tree. This abstraction denotes
/// whether the nodes are binary searchable (i.e. all nodes have the same label
/// length, and are sorted).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum AzksElementSet {
    BinarySearchable(Vec<AzksElement>),
    Unsorted(Vec<AzksElement>),
}

impl Deref for AzksElementSet {
    type Target = Vec<AzksElement>;

    fn deref(&self) -> &Self::Target {
        match self {
            AzksElementSet::BinarySearchable(nodes) => nodes,
            AzksElementSet::Unsorted(nodes) => nodes,
        }
    }
}

impl From<Vec<AzksElement>> for AzksElementSet {
    fn from(mut nodes: Vec<AzksElement>) -> Self {
        if !nodes.is_empty()
            && nodes
                .iter()
                .all(|node| node.label.label_len == nodes[0].label.label_len)
        {
            nodes.sort_unstable();
            AzksElementSet::BinarySearchable(nodes)
        } else {
            AzksElementSet::Unsorted(nodes)
        }
    }
}

impl AzksElementSet {
    /// Partition node set into "left" and "right" sets, based on a given
    /// prefix label. Note: the label *must* be a common prefix of all nodes in
    /// the set.
    pub(crate) fn partition(self, prefix_label: NodeLabel) -> (AzksElementSet, AzksElementSet) {
        match self {
            AzksElementSet::BinarySearchable(mut nodes) => {
                // binary search for partition point
                let partition_point = nodes.partition_point(|candidate| {
                    match prefix_label.get_prefix_ordering(candidate.label) {
                        PrefixOrdering::WithZero | PrefixOrdering::Invalid => true,
                        PrefixOrdering::WithOne => false,
                    }
                });

                // split nodes vector at partition point
                let right = nodes.split_off(partition_point);
                let mut left = nodes;

                // drop nodes with invalid prefix ordering
                while left
                    .last()
                    .map(|node| prefix_label.get_prefix_ordering(node.label))
                    == Some(PrefixOrdering::Invalid)
                {
                    left.pop();
                }

                (
                    AzksElementSet::BinarySearchable(left),
                    AzksElementSet::BinarySearchable(right),
                )
            }
            AzksElementSet::Unsorted(nodes) => {
                let (left, right) =
                    nodes
                        .into_iter()
                        .fold((vec![], vec![]), |(mut left, mut right), node| {
                            match prefix_label.get_prefix_ordering(node.label) {
                                PrefixOrdering::WithZero => left.push(node),
                                PrefixOrdering::WithOne => right.push(node),
                                PrefixOrdering::Invalid => (),
                            };
                            (left, right)
                        });
                (
                    AzksElementSet::Unsorted(left),
                    AzksElementSet::Unsorted(right),
                )
            }
        }
    }

    /// Get the longest common prefix of all nodes in the set.
    pub(crate) fn get_longest_common_prefix<TC: Configuration>(&self) -> NodeLabel {
        match self {
            AzksElementSet::BinarySearchable(nodes) => {
                // the LCP of a set of sorted, equal length labels is the LCP of
                // the first and last label
                match (nodes.first(), nodes.last()) {
                    (Some(first), Some(last)) => {
                        first.label.get_longest_common_prefix::<TC>(last.label)
                    }
                    _ => TC::empty_label(),
                }
            }
            AzksElementSet::Unsorted(nodes) => {
                if nodes.is_empty() {
                    return TC::empty_label();
                }
                nodes.iter().skip(1).fold(nodes[0].label, |acc, node| {
                    node.label.get_longest_common_prefix::<TC>(acc)
                })
            }
        }
    }

    /// Check if the set contains a node with a given prefix.
    pub(crate) fn contains_prefix(&self, prefix_label: &NodeLabel) -> bool {
        match self {
            AzksElementSet::BinarySearchable(nodes) => nodes
                .binary_search_by(|candidate| {
                    match prefix_label.label_len == 0 || prefix_label.is_prefix_of(&candidate.label)
                    {
                        true => Ordering::Equal,
                        false => candidate.label.label_val.cmp(&prefix_label.label_val),
                    }
                })
                .is_ok(),
            AzksElementSet::Unsorted(nodes) => nodes
                .iter()
                .any(|node| prefix_label.is_prefix_of(&node.label)),
        }
    }
}

/// An append-only zero knowledge set, the data structure used to efficiently implement
/// a auditable key directory.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde_serialization",
    derive(serde::Deserialize, serde::Serialize)
)]
#[cfg_attr(feature = "serde_serialization", serde(bound = ""))]
pub struct Azks {
    /// The latest complete epoch
    pub latest_epoch: u64,
    /// The number of nodes is the total size of this tree
    pub num_nodes: u64,
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
    pub async fn new<TC: Configuration, S: Database>(
        storage: &StorageManager<S>,
    ) -> Result<Self, AkdError> {
        let root_node = new_root_node::<TC>();
        root_node.write_to_storage(storage, true).await?;

        let azks = Azks {
            latest_epoch: 0,
            num_nodes: 1,
        };

        Ok(azks)
    }

    /// Insert a batch of new leaves.
    pub async fn batch_insert_nodes<TC: Configuration, S: Database + 'static>(
        &mut self,
        storage: &StorageManager<S>,
        nodes: Vec<AzksElement>,
        insert_mode: InsertMode,
    ) -> Result<(), AkdError> {
        let azks_element_set = AzksElementSet::from(nodes);

        // preload the nodes that we will visit during the insertion
        let (_, time_s) = tic_toc(self.preload_nodes(storage, &azks_element_set)).await;
        if let Some(time) = time_s {
            info!("Preload of tree took {} s", time,);
        }

        // increment the current epoch
        self.increment_epoch();

        if !azks_element_set.is_empty() {
            // call recursive batch insert on the root
            let (root_node, is_new, num_inserted) = Self::recursive_batch_insert_nodes::<TC, _>(
                storage,
                Some(NodeLabel::root()),
                azks_element_set,
                self.latest_epoch,
                insert_mode,
                get_parallel_levels(),
            )
            .await?;
            root_node.write_to_storage(storage, is_new).await?;

            // update the number of nodes
            self.num_nodes += num_inserted;

            info!("Batch insert completed ({} new nodes)", num_inserted);
        }

        Ok(())
    }

    /// Inserts a batch of leaves recursively from a given node label. Note: it
    /// is the caller's responsibility to write the returned node to storage.
    /// This is done so that the caller may set the 'parent' field of a node
    /// before it is written to storage. The is_new flag indicates whether the
    /// returned node is new or not.
    #[async_recursion]
    pub(crate) async fn recursive_batch_insert_nodes<TC: Configuration, S: Database + 'static>(
        storage: &StorageManager<S>,
        node_label: Option<NodeLabel>,
        azks_element_set: AzksElementSet,
        epoch: u64,
        insert_mode: InsertMode,
        parallel_levels: Option<u8>,
    ) -> Result<(TreeNode, bool, u64), AkdError> {
        // Phase 1: Obtain the current root node of this subtree. If the node is
        // new, mark it as so and count it towards the number of inserted nodes.
        let mut current_node;
        let is_new;
        let mut num_inserted;

        match (node_label, &azks_element_set[..]) {
            (Some(node_label), _) => {
                // Case 1: The node label is not None, meaning that there was an
                // existing node at this level of the tree.
                let mut existing_node =
                    TreeNode::get_from_storage(storage, &NodeKey(node_label), epoch).await?;

                // compute the longest common prefix between all nodes in the
                // node set and the current node, and check if new nodes
                // have a longest common prefix shorter than the current node.
                let set_lcp_label = azks_element_set.get_longest_common_prefix::<TC>();
                let lcp_label = node_label.get_longest_common_prefix::<TC>(set_lcp_label);
                if lcp_label.get_len() < node_label.get_len() {
                    // Case 1a: The existing node needs to be decompressed, by
                    // pushing it down one level (away from root) in the tree
                    // and replacing it with a new node whose label is equal to
                    // the longest common prefix.
                    current_node = new_interior_node::<TC>(lcp_label, epoch);
                    current_node.set_child(&mut existing_node)?;
                    existing_node.write_to_storage(storage, false).await?;
                    is_new = true;
                    num_inserted = 1;
                } else {
                    // Case 1b: The existing node does not need to be
                    // decompressed as its label is longer than or equal to the
                    // longest common prefix of the node set.
                    current_node = existing_node;
                    is_new = false;
                    num_inserted = 0;
                }
            }
            (None, [node]) => {
                // Case 2: The node label is None and the node set has a
                // single element, meaning that a new leaf node should be
                // created to represent the element.
                current_node = new_leaf_node::<TC>(node.label, &node.value, epoch);
                is_new = true;
                num_inserted = 1;
            }
            (None, _) => {
                // Case 3: The node label is None and the insertion still has
                // multiple elements, meaning that a new interior node should be
                // created with a label equal to the longest common prefix of
                // the node set.
                let lcp_label = azks_element_set.get_longest_common_prefix::<TC>();
                current_node = new_interior_node::<TC>(lcp_label, epoch);
                is_new = true;
                num_inserted = 1;
            }
        }

        // Phase 2: Partition the node set based on the direction the leaf
        // nodes are located in with respect to the current node and call this
        // function recursively on the left and right child nodes. The current
        // node is updated with the new child nodes.
        let (left_azks_element_set, right_azks_element_set) =
            azks_element_set.partition(current_node.label);
        let child_parallel_levels =
            parallel_levels.and_then(|x| if x <= 1 { None } else { Some(x - 1) });

        // handle the left child
        let maybe_handle = if !left_azks_element_set.is_empty() {
            let storage_clone = storage.clone();
            let left_child_label = current_node.get_child_label(Direction::Left);
            let left_future = async move {
                Azks::recursive_batch_insert_nodes::<TC, _>(
                    &storage_clone,
                    left_child_label,
                    left_azks_element_set,
                    epoch,
                    insert_mode,
                    child_parallel_levels,
                )
                .await
            };

            if parallel_levels.is_some() {
                // spawn a task and return the handle if there are still levels
                // to be processed in parallel
                Some(tokio::task::spawn(left_future))
            } else {
                // else handle the left child in the current task
                let (mut left_node, left_is_new, left_num_inserted) = left_future.await?;

                current_node.set_child(&mut left_node)?;
                left_node.write_to_storage(storage, left_is_new).await?;
                num_inserted += left_num_inserted;
                None
            }
        } else {
            None
        };

        // handle the right child in the current task
        if !right_azks_element_set.is_empty() {
            let right_child_label = current_node.get_child_label(Direction::Right);
            let (mut right_node, right_is_new, right_num_inserted) =
                Azks::recursive_batch_insert_nodes::<TC, _>(
                    storage,
                    right_child_label,
                    right_azks_element_set,
                    epoch,
                    insert_mode,
                    child_parallel_levels,
                )
                .await?;

            current_node.set_child(&mut right_node)?;
            right_node.write_to_storage(storage, right_is_new).await?;
            num_inserted += right_num_inserted;
        }

        // join on the handle for the left child, if present
        if let Some(handle) = maybe_handle {
            let (mut left_node, left_is_new, left_num_inserted) = handle
                .await
                .map_err(|e| AkdError::Parallelism(ParallelismError::JoinErr(e.to_string())))??;
            current_node.set_child(&mut left_node)?;
            left_node.write_to_storage(storage, left_is_new).await?;
            num_inserted += left_num_inserted;
        }

        // Phase 3: Update the hash of the current node and return it along with
        // the number of nodes inserted.
        current_node
            .update_hash::<TC, _>(storage, NodeHashingMode::from(insert_mode))
            .await?;

        Ok((current_node, is_new, num_inserted))
    }

    #[cfg(feature = "greedy_lookup_preload")]
    async fn get_next_node_in_child_path_from_cache<S: Database + Send + Sync>(
        &self,
        storage: &StorageManager<S>,
        node: &TreeNode,
        target: &NodeLabel,
    ) -> Option<TreeNode> {
        match (node.left_child, node.right_child) {
            (Some(l), _) if l.is_prefix_of(target) => {
                match storage
                    .get_from_cache_only::<crate::tree_node::TreeNodeWithPreviousValue>(&NodeKey(l))
                    .await
                {
                    Some(crate::storage::types::DbRecord::TreeNode(tnpv)) => {
                        if let Ok(node) = tnpv.determine_node_to_get(self.latest_epoch) {
                            Some(node)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            (_, Some(r)) if r.is_prefix_of(target) => {
                match storage
                    .get_from_cache_only::<crate::tree_node::TreeNodeWithPreviousValue>(&NodeKey(r))
                    .await
                {
                    Some(crate::storage::types::DbRecord::TreeNode(tnpv)) => {
                        if let Ok(node) = tnpv.determine_node_to_get(self.latest_epoch) {
                            Some(node)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Builds all of the POSSIBLE paths along the route from root node to
    /// leaf node. This will be grossly over-estimating the true size of the
    /// tree and the number of nodes required to be fetched, however
    /// it allows a single batch-get call in necessary scenarios
    #[cfg(feature = "greedy_lookup_preload")]
    pub(crate) async fn build_lookup_maximal_node_set<S: Database + Send + Sync>(
        &self,
        storage: &StorageManager<S>,
        li: LookupInfo,
    ) -> Result<HashSet<NodeLabel>, AkdError> {
        let mut results = HashSet::new();
        let labels = [li.existent_label, li.marker_label, li.non_existent_label];

        let root_node: TreeNode =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), self.latest_epoch)
                .await?;

        for label in labels {
            let mut cnode = root_node.clone();
            // walk through the cache to find the next node in the tree which isn't already loaded
            while let Some(node) = self
                .get_next_node_in_child_path_from_cache(storage, &cnode, &label)
                .await
            {
                cnode = node;
            }
            // load the rest of the nodes in the path, as soon as a child node can't be resolved. In the worst-case
            // this is loading every possible node on the path (i.e. uninitialized cache)
            for len in cnode.label.label_len..256 {
                results.insert(label.get_prefix(len));
            }
        }

        Ok(results)
    }

    /// Preload for a single lookup operation by loading all of the nodes along
    /// the direct path, and the children of resolved nodes on the path. This
    /// minimizes the number of batch_get operations to the storage layer which are
    /// called
    #[cfg(feature = "greedy_lookup_preload")]
    pub(crate) async fn greedy_preload_lookup_nodes<S: Database + Send + Sync>(
        &self,
        storage: &StorageManager<S>,
        lookup_info: LookupInfo,
    ) -> Result<u64, AkdError> {
        let mut count = 0u64;
        let mut requested_count = 0u64;

        // First try and load ALL possible nodes on the direct paths between the root and the target labels
        // For a lookup proof, there's 3 targets
        //
        // * existent_label
        // * marker_label
        // * non_existent_label
        let nodes = self
            .build_lookup_maximal_node_set(storage, lookup_info)
            .await?
            .into_iter()
            .map(NodeKey)
            .collect::<Vec<_>>();
        requested_count += nodes.len() as u64;

        let nodes = TreeNode::batch_get_from_storage(storage, &nodes, self.latest_epoch).await?;
        count += nodes.len() as u64;

        // Now load the children of the nodes resolved on the direct path, which
        // for non-already-loaded children will be the siblings necessary to
        // generate the required proof structs.
        let children = nodes
            .into_iter()
            .flat_map(|node| match (node.left_child, node.right_child) {
                (Some(l), Some(r)) => vec![NodeKey(l), NodeKey(r)],
                _ => vec![],
            })
            .collect::<Vec<_>>();
        requested_count += children.len() as u64;

        let children =
            TreeNode::batch_get_from_storage(storage, &children, self.latest_epoch).await?;
        count += children.len() as u64;

        log::info!(
            "Greedy lookup proof preloading loaded {} of {} nodes",
            count,
            requested_count
        );

        Ok(count)
    }

    pub(crate) async fn preload_lookup_nodes<S: Database + Send + Sync>(
        &self,
        storage: &StorageManager<S>,
        lookup_infos: &[LookupInfo],
    ) -> Result<u64, AkdError> {
        // Collect lookup labels needed and convert them into Nodes for preloading.
        let lookup_nodes: Vec<AzksElement> = lookup_infos
            .iter()
            .flat_map(|li| vec![li.existent_label, li.marker_label, li.non_existent_label])
            .map(|l| AzksElement {
                label: l,
                value: AzksValue(EMPTY_DIGEST),
            })
            .collect();

        // Load nodes.
        self.preload_nodes(storage, &AzksElementSet::from(lookup_nodes))
            .await
    }

    /// Preloads given nodes using breadth-first search.
    pub(crate) async fn preload_nodes<S: Database>(
        &self,
        storage: &StorageManager<S>,
        azks_element_set: &AzksElementSet,
    ) -> Result<u64, AkdError> {
        if !storage.has_cache() {
            info!("No cache found, skipping preload");
            return Ok(0);
        }

        let mut load_count: u64 = 0;
        let mut current_nodes = vec![NodeKey(NodeLabel::root())];

        while !current_nodes.is_empty() {
            let nodes =
                TreeNode::batch_get_from_storage(storage, &current_nodes, self.get_latest_epoch())
                    .await?;
            load_count += nodes.len() as u64;

            // Now that states are loaded in the cache, we can read and access them.
            // Note, we perform directional loads to avoid accessing remote storage
            // individually for each node's state.
            current_nodes = nodes
                .iter()
                .filter(|node| azks_element_set.contains_prefix(&node.label))
                .flat_map(|node| {
                    [Direction::Left, Direction::Right]
                        .iter()
                        .filter_map(|dir| node.get_child_label(*dir).map(NodeKey))
                        .collect::<Vec<NodeKey>>()
                })
                .collect();
        }

        info!("Preload of tree ({} nodes) completed", load_count);

        Ok(load_count)
    }

    /// Returns the Merkle membership proof for the trie as it stood at epoch
    // Assumes the verifier has access to the root at epoch
    pub async fn get_membership_proof<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<MembershipProof, AkdError> {
        let (_, proof) = self
            .get_lcp_node_label_with_membership_proof::<TC, _>(storage, label)
            .await?;
        Ok(proof)
    }

    /// In a compressed trie, the proof consists of the longest prefix
    /// of the label that is included in the trie, as well as its children, to show that
    /// none of the children is equal to the given label.
    pub async fn get_non_membership_proof<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<NonMembershipProof, AkdError> {
        let (lcp_node_label, longest_prefix_membership_proof) = self
            .get_lcp_node_label_with_membership_proof::<TC, _>(storage, label)
            .await?;
        let lcp_node: TreeNode =
            TreeNode::get_from_storage(storage, &NodeKey(lcp_node_label), self.get_latest_epoch())
                .await?;
        let longest_prefix = lcp_node.label;

        let empty_azks_element = AzksElement {
            label: TC::empty_label(),
            value: TC::empty_node_hash(),
        };

        let mut longest_prefix_children = [empty_azks_element; ARITY];
        for (i, dir) in [Direction::Left, Direction::Right].iter().enumerate() {
            match lcp_node
                .get_child_node(storage, *dir, self.latest_epoch)
                .await?
            {
                None => {
                    longest_prefix_children[i] = empty_azks_element;
                }
                Some(child) => {
                    let unwrapped_child: TreeNode = TreeNode::get_from_storage(
                        storage,
                        &NodeKey(child.label),
                        self.get_latest_epoch(),
                    )
                    .await?;
                    longest_prefix_children[i] = AzksElement {
                        label: unwrapped_child.label,
                        value: node_to_azks_value::<TC>(
                            &Some(unwrapped_child),
                            NodeHashingMode::WithLeafEpoch,
                        ),
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

    /// An append-only proof for going from `start_epoch` to `end_epoch` consists of roots of subtrees
    /// the azks tree that remain unchanged from `start_epoch` to `end_epoch` and the leaves inserted into the
    /// tree after `start_epoch` and  up until `end_epoch`.
    /// If there is no errors, this function returns an `Ok` result, containing the
    ///  append-only proof and otherwise, it returns an [AkdError].
    ///
    /// **RESTRICTIONS**: Note that `start_epoch` and `end_epoch` are valid only when the following are true
    /// * `start_epoch` <= `end_epoch`
    /// * `start_epoch` and `end_epoch` are both existing epochs of this AZKS
    pub async fn get_append_only_proof<TC: Configuration, S: Database + 'static>(
        &self,
        storage: &StorageManager<S>,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<AppendOnlyProof, AkdError> {
        let latest_epoch = self.get_latest_epoch();
        if latest_epoch < end_epoch || end_epoch <= start_epoch {
            return Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "Start epoch must be less than end epoch, and end epoch must be at most the latest epoch. \
                Start epoch: {start_epoch}, end epoch: {end_epoch}, latest_epoch: {latest_epoch}."
            ))));
        }

        let mut proofs = Vec::<SingleAppendOnlyProof>::new();
        let mut epochs = Vec::<u64>::new();
        // Suppose the epochs start_epoch and end_epoch exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.

        let node =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), latest_epoch).await?;

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

            let (unchanged, leaves) = Self::get_append_only_proof_helper::<TC, _>(
                latest_epoch,
                storage,
                node.clone(),
                ep,
                ep + 1,
                0,
                get_parallel_levels(),
            )
            .await?;
            info!("Generated audit proof for {} -> {}", ep, ep + 1);
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
        if node.node_type == TreeNodeType::Leaf {
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

    async fn gather_audit_proof_nodes<S: Database>(
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
    #[allow(clippy::type_complexity)]
    async fn get_append_only_proof_helper<TC: Configuration, S: Database + 'static>(
        latest_epoch: u64,
        storage: &StorageManager<S>,
        node: TreeNode,
        start_epoch: u64,
        end_epoch: u64,
        level: u64,
        parallel_levels: Option<u8>,
    ) -> Result<AppendOnlyHelper, AkdError> {
        let mut unchanged = Vec::<AzksElement>::new();
        let mut leaves = Vec::<AzksElement>::new();

        if node.get_latest_epoch() <= start_epoch {
            if node.node_type == TreeNodeType::Root {
                // this is the case where the root is unchanged since the last epoch
                return Ok((unchanged, leaves));
            }
            unchanged.push(AzksElement {
                label: node.label,
                value: node_to_azks_value::<TC>(&Some(node), NodeHashingMode::WithLeafEpoch),
            });

            return Ok((unchanged, leaves));
        }

        if node.min_descendant_epoch > end_epoch {
            return Ok((unchanged, leaves));
        }

        if node.node_type == TreeNodeType::Leaf {
            leaves.push(AzksElement {
                label: node.label,
                value: node.hash,
            });
        } else {
            let maybe_task: Option<
                tokio::task::JoinHandle<Result<(Vec<AzksElement>, Vec<AzksElement>), AkdError>>,
            > = if let Some(left_child) = node.left_child {
                #[cfg(feature = "parallel_insert")]
                {
                    if parallel_levels.map(|p| p as u64 > level).unwrap_or(false) {
                        // we can parallelise further!
                        let storage_clone = storage.clone();
                        let tsk: tokio::task::JoinHandle<Result<_, AkdError>> =
                            tokio::spawn(async move {
                                let my_storage = storage_clone;
                                let child_node = TreeNode::get_from_storage(
                                    &my_storage,
                                    &NodeKey(left_child),
                                    latest_epoch,
                                )
                                .await?;
                                Self::get_append_only_proof_helper::<TC, _>(
                                    latest_epoch,
                                    &my_storage,
                                    child_node,
                                    start_epoch,
                                    end_epoch,
                                    level + 1,
                                    parallel_levels,
                                )
                                .await
                            });

                        Some(tsk)
                    } else {
                        // Enough parallelism already, STOP IT! Don't make me get the belt!
                        let child_node =
                            TreeNode::get_from_storage(storage, &NodeKey(left_child), latest_epoch)
                                .await?;
                        let (mut inner_unchanged, mut inner_leaf) =
                            Self::get_append_only_proof_helper::<TC, _>(
                                latest_epoch,
                                storage,
                                child_node,
                                start_epoch,
                                end_epoch,
                                level + 1,
                                parallel_levels,
                            )
                            .await?;
                        unchanged.append(&mut inner_unchanged);
                        leaves.append(&mut inner_leaf);
                        None
                    }
                }

                #[cfg(not(feature = "parallel_insert"))]
                {
                    // NO Parallelism, BAD! parallelism. Get your nose out of the garbage!
                    let child_node =
                        TreeNode::get_from_storage(storage, &NodeKey(left_child), latest_epoch)
                            .await?;
                    let (mut inner_unchanged, mut inner_leaf) =
                        Self::get_append_only_proof_helper::<TC, _>(
                            latest_epoch,
                            storage,
                            child_node,
                            start_epoch,
                            end_epoch,
                            level + 1,
                            parallel_levels,
                        )
                        .await?;
                    unchanged.append(&mut inner_unchanged);
                    leaves.append(&mut inner_leaf);
                    None
                }
            } else {
                None
            };

            if let Some(right_child) = node.right_child {
                let child_node =
                    TreeNode::get_from_storage(storage, &NodeKey(right_child), latest_epoch)
                        .await?;
                let (mut inner_unchanged, mut inner_leaf) =
                    Self::get_append_only_proof_helper::<TC, _>(
                        latest_epoch,
                        storage,
                        child_node,
                        start_epoch,
                        end_epoch,
                        level + 1,
                        parallel_levels,
                    )
                    .await?;
                unchanged.append(&mut inner_unchanged);
                leaves.append(&mut inner_leaf);
            }

            if let Some(task) = maybe_task {
                let (mut inner_unchanged, mut inner_leaf) = task.await.map_err(|join_err| {
                    AkdError::Parallelism(ParallelismError::JoinErr(join_err.to_string()))
                })??;
                unchanged.append(&mut inner_unchanged);
                leaves.append(&mut inner_leaf);
            }
        }
        Ok((unchanged, leaves))
    }

    /// Gets the root hash for this azks
    pub async fn get_root_hash<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
    ) -> Result<Digest, AkdError> {
        self.get_root_hash_safe::<TC, _>(storage, self.get_latest_epoch())
            .await
    }

    /// Gets the root hash of the tree at the latest epoch if the passed epoch
    /// is equal to the latest epoch. Will return an error otherwise.
    pub(crate) async fn get_root_hash_safe<TC: Configuration, S: Database>(
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
        Ok(TC::compute_root_hash_from_val(&root_node.hash))
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
    async fn get_child_azks_element_in_dir<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        curr_node: &TreeNode,
        dir: Direction,
        latest_epoch: u64,
    ) -> Result<AzksElement, AkdError> {
        // Find the sibling in the "other" direction
        let sibling = curr_node.get_child_node(storage, dir, latest_epoch).await?;
        Ok(AzksElement {
            label: node_to_label::<TC>(&sibling),
            value: node_to_azks_value::<TC>(&sibling, NodeHashingMode::WithLeafEpoch),
        })
    }

    /// This function returns the node label for the node whose label is the longest common
    /// prefix for the queried label. It also returns a membership proof for said label.
    /// This is meant to be used in both getting membership proofs and getting non-membership proofs.
    async fn get_lcp_node_label_with_membership_proof<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<(NodeLabel, MembershipProof), AkdError> {
        let mut sibling_proofs = Vec::new();
        let latest_epoch = self.get_latest_epoch();

        // Perform a traversal from the root to the node corresponding to the queried label
        let mut curr_node =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), latest_epoch).await?;

        let mut prefix_ordering = curr_node.label.get_prefix_ordering(label);
        let mut equal = label == curr_node.label;
        let mut prev_node = curr_node.clone();
        while !equal && prefix_ordering != PrefixOrdering::Invalid {
            let direction = Direction::try_from(prefix_ordering).map_err(|_| {
                AkdError::TreeNode(TreeNodeError::NoDirection(curr_node.label, None))
            })?;
            let child = curr_node
                .get_child_node(storage, direction, latest_epoch)
                .await?;
            if child.is_none() {
                // Special case, if the root node has a direction with no child there
                break;
            }

            // Find the sibling node. Note that for ARITY = 2, this does not need to be
            // an array, as it can just be a single node.
            let child_azks_element = self
                .get_child_azks_element_in_dir::<TC, _>(
                    storage,
                    &curr_node,
                    direction.other(),
                    latest_epoch,
                )
                .await?;
            sibling_proofs.push(SiblingProof {
                label: curr_node.label,
                siblings: [child_azks_element],
                direction,
            });

            prev_node = curr_node.clone();
            match curr_node
                .get_child_node(storage, direction, latest_epoch)
                .await?
            {
                Some(n) => curr_node = n,
                None => {
                    return Err(AkdError::TreeNode(TreeNodeError::NoChildAtEpoch(
                        latest_epoch,
                        direction,
                    )));
                }
            }
            prefix_ordering = curr_node.label.get_prefix_ordering(label);
            equal = label == curr_node.label;
        }

        if !equal {
            curr_node = prev_node;
            sibling_proofs.pop();
        }
        let hash_val = if curr_node.node_type == TreeNodeType::Leaf {
            AzksValue(TC::hash_leaf_with_commitment(curr_node.hash, curr_node.last_epoch).0)
        } else {
            curr_node.hash
        };

        Ok((
            curr_node.label,
            MembershipProof {
                label: curr_node.label,
                hash_val,
                sibling_proofs,
            },
        ))
    }
}

type AppendOnlyHelper = (Vec<AzksElement>, Vec<AzksElement>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::types::DbRecord;
    use crate::storage::StorageUtil;
    use crate::test_config;
    use crate::tree_node::TreeNodeWithPreviousValue;
    use crate::utils::byte_arr_from_u64;
    use crate::{
        auditor::audit_verify,
        client::{verify_membership_for_tests_only, verify_nonmembership_for_tests_only},
        storage::memory::AsyncInMemoryDatabase,
    };
    use itertools::Itertools;
    use rand::{rngs::StdRng, seq::SliceRandom, RngCore, SeedableRng};
    use std::time::Duration;

    #[cfg(feature = "greedy_lookup_preload")]
    test_config!(test_maximal_node_set_resolution);
    #[cfg(feature = "greedy_lookup_preload")]
    async fn test_maximal_node_set_resolution<TC: Configuration>() -> Result<(), AkdError> {
        let mut rng = StdRng::seed_from_u64(42);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let azks1 = Azks::new::<TC, _>(&db).await.unwrap();
        let label = NodeLabel {
            label_len: 256,
            label_val: [
                1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1,
                0, 1, 0, 1,
            ],
        };

        let lookup_info = LookupInfo {
            existent_label: label,
            marker_label: label,
            marker_version: 1,
            non_existent_label: label,
            value_state: crate::storage::types::ValueState {
                epoch: 1,
                label,
                username: crate::AkdLabel::random(&mut rng),
                value: crate::AkdValue::random(&mut rng),
                version: 1,
            },
        };

        let max_set = azks1
            .build_lookup_maximal_node_set(&db, lookup_info)
            .await
            .expect("Failed to build maximal set");

        // since the label is there 3 times, it should all resolve to the same data
        assert_eq!(256, max_set.len());
        Ok(())
    }

    test_config!(test_batch_insert_basic);
    async fn test_batch_insert_basic<TC: Configuration>() -> Result<(), AkdError> {
        let mut rng = StdRng::seed_from_u64(42);
        let num_nodes = 10;
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks1 = Azks::new::<TC, _>(&db).await?;
        azks1.increment_epoch();

        let mut azks_element_set: Vec<AzksElement> = vec![];
        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut input = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut input);
            let value = TC::hash(&input);
            let node = AzksElement {
                label,
                value: AzksValue(value),
            };
            azks_element_set.push(node);
            let (root_node, is_new, _) = Azks::recursive_batch_insert_nodes::<TC, _>(
                &db,
                Some(NodeLabel::root()),
                AzksElementSet::from(vec![node]),
                1,
                InsertMode::Directory,
                None,
            )
            .await?;
            root_node.write_to_storage(&db, is_new).await?;
        }

        let database2 = AsyncInMemoryDatabase::new();
        let db2 = StorageManager::new_no_cache(database2);
        let mut azks2 = Azks::new::<TC, _>(&db2).await?;

        azks2
            .batch_insert_nodes::<TC, _>(&db2, azks_element_set, InsertMode::Directory)
            .await?;

        assert_eq!(
            azks1.get_root_hash::<TC, _>(&db).await?,
            azks2.get_root_hash::<TC, _>(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    test_config!(test_batch_insert_root_hash);
    async fn test_batch_insert_root_hash<TC: Configuration>() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);

        // manually construct a 3-layer tree and compute the root hash
        let mut nodes = Vec::<AzksElement>::new();
        let mut leaves = Vec::<TreeNode>::new();
        let mut leaf_hashes = Vec::new();
        for i in 0u64..8u64 {
            let leaf_u64 = i << 61;
            let label = NodeLabel::new(byte_arr_from_u64(leaf_u64), 3u32);
            let value = AzksValue(TC::hash(&leaf_u64.to_be_bytes()));
            nodes.push(AzksElement { label, value });

            let new_leaf = new_leaf_node::<TC>(label, &value, 7 - i + 1);
            leaf_hashes.push((
                TC::hash_leaf_with_commitment(
                    AzksValue(TC::hash(&leaf_u64.to_be_bytes())),
                    7 - i + 1,
                ),
                new_leaf.label.value::<TC>(),
            ));
            leaves.push(new_leaf);
        }

        let mut layer_1_hashes = Vec::new();
        for (i, j) in (0u64..4).enumerate() {
            let left_child_hash = leaf_hashes[2 * i].clone();
            let right_child_hash = leaf_hashes[2 * i + 1].clone();
            layer_1_hashes.push((
                TC::compute_parent_hash_from_children(
                    &AzksValue(left_child_hash.0 .0),
                    &left_child_hash.1,
                    &AzksValue(right_child_hash.0 .0),
                    &right_child_hash.1,
                ),
                NodeLabel::new(byte_arr_from_u64(j << 62), 2u32).value::<TC>(),
            ));
        }

        let mut layer_2_hashes = Vec::new();
        for (i, j) in (0u64..2).enumerate() {
            let left_child_hash = layer_1_hashes[2 * i].clone();
            let right_child_hash = layer_1_hashes[2 * i + 1].clone();
            layer_2_hashes.push((
                TC::compute_parent_hash_from_children(
                    &AzksValue(left_child_hash.0 .0),
                    &left_child_hash.1,
                    &AzksValue(right_child_hash.0 .0),
                    &right_child_hash.1,
                ),
                NodeLabel::new(byte_arr_from_u64(j << 63), 1u32).value::<TC>(),
            ));
        }

        let expected = TC::compute_root_hash_from_val(&TC::compute_parent_hash_from_children(
            &AzksValue(layer_2_hashes[0].0 .0),
            &layer_2_hashes[0].1,
            &AzksValue(layer_2_hashes[1].0 .0),
            &layer_2_hashes[1].1,
        ));

        // create a 3-layer tree with batch insert operations and get root hash
        let mut azks = Azks::new::<TC, _>(&db).await?;
        for i in 0..8 {
            let node = nodes[7 - i];
            azks.batch_insert_nodes::<TC, _>(&db, vec![node], InsertMode::Directory)
                .await?;
        }

        let root_digest = azks.get_root_hash::<TC, _>(&db).await.unwrap();

        // assert root hash from batch insert matches manually computed root hash
        assert_eq!(root_digest, expected, "Root hash not equal to expected");
        Ok(())
    }

    test_config!(test_insert_permuted);
    async fn test_insert_permuted<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 10;
        let mut rng = StdRng::seed_from_u64(42);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks1 = Azks::new::<TC, _>(&db).await?;
        azks1.increment_epoch();
        let mut azks_element_set: Vec<AzksElement> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut value = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut value);
            let node = AzksElement {
                label,
                value: AzksValue(value),
            };
            azks_element_set.push(node);
            let (root_node, is_new, _) = Azks::recursive_batch_insert_nodes::<TC, _>(
                &db,
                Some(NodeLabel::root()),
                AzksElementSet::from(vec![node]),
                1,
                InsertMode::Directory,
                None,
            )
            .await?;
            root_node.write_to_storage(&db, is_new).await?;
        }

        // Try randomly permuting
        azks_element_set.shuffle(&mut rng);

        let database2 = AsyncInMemoryDatabase::new();
        let db2 = StorageManager::new_no_cache(database2);
        let mut azks2 = Azks::new::<TC, _>(&db2).await?;

        azks2
            .batch_insert_nodes::<TC, _>(&db2, azks_element_set, InsertMode::Directory)
            .await?;

        assert_eq!(
            azks1.get_root_hash::<TC, _>(&db).await?,
            azks2.get_root_hash::<TC, _>(&db2).await?,
            "Batch insert doesn't match individual insert"
        );

        Ok(())
    }

    test_config!(test_insert_num_nodes);
    async fn test_insert_num_nodes<TC: Configuration>() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database.clone());
        let mut azks = Azks::new::<TC, _>(&db).await?;

        // expected nodes inserted: 1 root
        let expected_num_nodes = 1;
        let azks_num_nodes = azks.num_nodes;
        let database_num_nodes = database
            .batch_get_type_direct::<TreeNodeWithPreviousValue>()
            .await?
            .len() as u64;

        assert_eq!(expected_num_nodes, azks_num_nodes);
        assert_eq!(expected_num_nodes, database_num_nodes);

        // insert 3 leaves
        let nodes = vec![
            NodeLabel::new(byte_arr_from_u64(0b0110 << 60), 64),
            NodeLabel::new(byte_arr_from_u64(0b0111 << 60), 64),
            NodeLabel::new(byte_arr_from_u64(0b0010 << 60), 64),
        ]
        .into_iter()
        .map(|label| AzksElement {
            label,
            value: AzksValue(EMPTY_DIGEST),
        })
        .collect();

        azks.batch_insert_nodes::<TC, _>(&db, nodes, InsertMode::Directory)
            .await?;

        // expected nodes inserted: 3 leaves, 2 internal nodes
        //                   -
        //          0
        //    0010     011
        //          0110  0111
        let expected_num_nodes = 5 + 1;
        let azks_num_nodes = azks.num_nodes;
        let database_num_nodes = database
            .batch_get_type_direct::<TreeNodeWithPreviousValue>()
            .await?
            .len() as u64;

        assert_eq!(expected_num_nodes, azks_num_nodes);
        assert_eq!(expected_num_nodes, database_num_nodes);

        // insert another 3 leaves
        let nodes = vec![
            NodeLabel::new(byte_arr_from_u64(0b1000 << 60), 64),
            NodeLabel::new(byte_arr_from_u64(0b0110 << 60), 64),
            NodeLabel::new(byte_arr_from_u64(0b0011 << 60), 64),
        ]
        .into_iter()
        .map(|label| AzksElement {
            label,
            value: AzksValue(EMPTY_DIGEST),
        })
        .collect();

        azks.batch_insert_nodes::<TC, _>(&db, nodes, InsertMode::Directory)
            .await?;

        // expected nodes inserted: 2 leaves, 1 internal node
        //                   -
        //          -               1000
        //    001         -
        //  -  0011     -   -
        let expected_num_nodes = 3 + 5 + 1;
        let azks_num_nodes = azks.num_nodes;
        let database_num_nodes = database
            .batch_get_type_direct::<TreeNodeWithPreviousValue>()
            .await?
            .len() as u64;

        assert_eq!(expected_num_nodes, azks_num_nodes);
        assert_eq!(expected_num_nodes, database_num_nodes);

        Ok(())
    }

    test_config!(test_preload_nodes_accuracy);
    async fn test_preload_nodes_accuracy<TC: Configuration>() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let storage_manager =
            StorageManager::new(database, Some(Duration::from_secs(180u64)), None, None);
        let mut azks = Azks::new::<TC, _>(&storage_manager)
            .await
            .expect("Failed to create azks!");
        azks.increment_epoch();

        // Construct our tree
        let root_label = NodeLabel::root();

        let left_label = NodeLabel::new(byte_arr_from_u64(1), 1);
        let left = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
            label: left_label,
            last_epoch: 1,
            min_descendant_epoch: 1,
            parent: root_label,
            node_type: TreeNodeType::Leaf,
            left_child: None,
            right_child: None,
            hash: AzksValue(EMPTY_DIGEST),
        }));
        let right_label = NodeLabel::new(byte_arr_from_u64(2), 2);
        let right = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
            label: right_label,
            last_epoch: 1,
            min_descendant_epoch: 1,
            parent: root_label,
            node_type: TreeNodeType::Leaf,
            left_child: None,
            right_child: None,
            hash: AzksValue(EMPTY_DIGEST),
        }));
        let root = DbRecord::TreeNode(TreeNodeWithPreviousValue::from_tree_node(TreeNode {
            label: root_label,
            last_epoch: 1,
            min_descendant_epoch: 1,
            parent: root_label,
            node_type: TreeNodeType::Root,
            left_child: Some(left_label),
            right_child: Some(right_label),
            hash: AzksValue(EMPTY_DIGEST),
        }));

        // Seed the database and cache with our tree
        storage_manager
            .batch_set(vec![root, left, right])
            .await
            .expect("Failed to seed database for preload test");

        // Preload nodes to populate storage manager cache
        let azks_element_set = AzksElementSet::from(vec![
            AzksElement {
                label: root_label,
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: left_label,
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: right_label,
                value: AzksValue(EMPTY_DIGEST),
            },
        ]);
        let expected_preload_count = 3u64;
        let actual_preload_count = azks
            .preload_nodes(&storage_manager, &azks_element_set)
            .await
            .expect("Failed to preload nodes");

        assert_eq!(
            expected_preload_count, actual_preload_count,
            "Preload count returned unexpected value!"
        );
        Ok(())
    }

    test_config!(test_azks_element_set_partition);
    async fn test_azks_element_set_partition<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 5;
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks1 = Azks::new::<TC, _>(&db).await?;
        azks1.increment_epoch();

        // manually construct both types of node sets with the same data
        let mut rng = StdRng::seed_from_u64(42);
        let nodes = gen_random_elements(num_nodes, &mut rng);
        let unsorted_set = AzksElementSet::Unsorted(nodes.clone());
        let bin_searchable_set = {
            let mut nodes = nodes;
            nodes.sort_unstable();
            AzksElementSet::BinarySearchable(nodes)
        };

        // assert that node sets always return the same partitions
        let assert_fun = |prefix_label: NodeLabel| match (
            unsorted_set.clone().partition(prefix_label),
            bin_searchable_set.clone().partition(prefix_label),
        ) {
            (
                (
                    AzksElementSet::Unsorted(mut left_unsorted),
                    AzksElementSet::Unsorted(mut right_unsorted),
                ),
                (
                    AzksElementSet::BinarySearchable(left_bin_searchable),
                    AzksElementSet::BinarySearchable(right_bin_searchable),
                ),
            ) => {
                left_unsorted.sort_unstable();
                right_unsorted.sort_unstable();
                assert_eq!(left_unsorted, *left_bin_searchable);
                assert_eq!(right_unsorted, *right_bin_searchable);
            }
            _ => panic!("Unexpected enum variant returned from partition call"),
        };

        let lcp_label = bin_searchable_set[0]
            .label
            .get_longest_common_prefix::<TC>(bin_searchable_set[num_nodes - 1].label);

        assert_fun(lcp_label);
        assert_fun(TC::empty_label());

        Ok(())
    }

    test_config!(test_azks_element_set_get_longest_common_prefix);
    async fn test_azks_element_set_get_longest_common_prefix<TC: Configuration>(
    ) -> Result<(), AkdError> {
        let num_nodes = 10;
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks1 = Azks::new::<TC, _>(&db).await?;
        azks1.increment_epoch();

        // manually construct both types of node sets with the same data
        let mut rng = StdRng::seed_from_u64(42);
        let nodes = gen_random_elements(num_nodes, &mut rng);
        let unsorted_set = AzksElementSet::Unsorted(nodes.clone());
        let bin_searchable_set = {
            let mut nodes = nodes;
            nodes.sort_unstable();
            AzksElementSet::BinarySearchable(nodes)
        };

        // assert that node sets always return the same LCP
        assert_eq!(
            unsorted_set.get_longest_common_prefix::<TC>(),
            bin_searchable_set.get_longest_common_prefix::<TC>()
        );

        Ok(())
    }

    test_config!(test_get_child_azks_element);
    async fn test_get_child_azks_element<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 5;
        let mut rng = StdRng::seed_from_u64(42);

        let mut azks_element_set: Vec<AzksElement> = vec![];

        for _ in 0..num_nodes {
            let label = crate::utils::random_label(&mut rng);
            let mut hash = crate::hash::EMPTY_DIGEST;
            rng.fill_bytes(&mut hash);
            let node = AzksElement {
                label,
                value: AzksValue(hash),
            };
            azks_element_set.push(node);
        }

        // Try tests against all permutations of the set
        for perm in azks_element_set.into_iter().permutations(num_nodes) {
            let database = AsyncInMemoryDatabase::new();
            let db = StorageManager::new_no_cache(database);
            let mut azks = Azks::new::<TC, _>(&db).await?;
            azks.batch_insert_nodes::<TC, _>(&db, perm, InsertMode::Directory)
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

                if let Some(left_child) = left_child {
                    let sibling_label = azks
                        .get_child_azks_element_in_dir::<TC, _>(
                            &db,
                            &current_node,
                            Direction::Left,
                            1,
                        )
                        .await?
                        .label;
                    assert_eq!(left_child.label, sibling_label);
                    nodes.push(left_child);
                }

                if let Some(right_child) = right_child {
                    println!("right_child.label: {:?}", right_child.label);
                    let sibling_label = azks
                        .get_child_azks_element_in_dir::<TC, _>(
                            &db,
                            &current_node,
                            Direction::Right,
                            1,
                        )
                        .await?
                        .label;
                    assert_eq!(right_child.label, sibling_label);
                    nodes.push(right_child);
                }
            }
        }

        Ok(())
    }

    test_config!(test_membership_proof_permuted);
    async fn test_membership_proof_permuted<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 10;

        let mut rng = StdRng::seed_from_u64(42);
        let mut azks_element_set = gen_random_elements(num_nodes, &mut rng);

        // Try randomly permuting
        azks_element_set.shuffle(&mut rng);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set.clone(), InsertMode::Directory)
            .await?;

        let proof = azks
            .get_membership_proof::<TC, _>(&db, azks_element_set[0].label)
            .await?;

        verify_membership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

        Ok(())
    }

    test_config!(test_membership_proof_small);
    async fn test_membership_proof_small<TC: Configuration>() -> Result<(), AkdError> {
        for num_nodes in 1..10 {
            let mut azks_element_set: Vec<AzksElement> = vec![];

            for i in 0..num_nodes {
                let mut label_arr = [0u8; 32];
                label_arr[0] = i;
                let label = NodeLabel::new(label_arr, 256u32);
                let node = AzksElement {
                    label,
                    value: AzksValue(EMPTY_DIGEST),
                };
                azks_element_set.push(node);
            }

            let database = AsyncInMemoryDatabase::new();
            let db = StorageManager::new_no_cache(database);
            let mut azks = Azks::new::<TC, _>(&db).await?;
            azks.batch_insert_nodes::<TC, _>(&db, azks_element_set.clone(), InsertMode::Directory)
                .await?;

            let proof = azks
                .get_membership_proof::<TC, _>(&db, azks_element_set[0].label)
                .await?;

            verify_membership_for_tests_only::<TC>(
                azks.get_root_hash::<TC, _>(&db).await?,
                &proof,
            )?;
        }
        Ok(())
    }

    test_config!(test_membership_proof_failing);
    async fn test_membership_proof_failing<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 10;

        let mut rng = StdRng::seed_from_u64(42);
        let mut azks_element_set = gen_random_elements(num_nodes, &mut rng);

        // Try randomly permuting
        azks_element_set.shuffle(&mut rng);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set.clone(), InsertMode::Directory)
            .await?;

        let mut proof = azks
            .get_membership_proof::<TC, _>(&db, azks_element_set[0].label)
            .await?;
        let hash_val = EMPTY_DIGEST;
        proof = MembershipProof {
            label: proof.label,
            hash_val: AzksValue(hash_val),
            sibling_proofs: proof.sibling_proofs,
        };
        assert!(
            verify_membership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)
                .is_err(),
            "Membership proof does verify, despite being wrong"
        );

        Ok(())
    }

    test_config!(test_nonmembership_proof_intermediate);
    async fn test_nonmembership_proof_intermediate<TC: Configuration>() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);

        let azks_element_set: Vec<AzksElement> = vec![
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b11 << 62), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
        ];

        let mut azks = Azks::new::<TC, _>(&db).await?;
        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set, InsertMode::Directory)
            .await?;
        let search_label = NodeLabel::new(byte_arr_from_u64(0b1111 << 60), 64);
        let proof = azks
            .get_non_membership_proof::<TC, _>(&db, search_label)
            .await?;
        assert!(
            verify_nonmembership_for_tests_only::<TC>(
                azks.get_root_hash::<TC, _>(&db).await?,
                &proof
            )
            .is_ok(),
            "Nonmembership proof does not verify"
        );
        Ok(())
    }

    // This test checks that a non-membership proof in a tree with 1 leaf verifies.
    test_config!(test_nonmembership_proof_very_small);
    async fn test_nonmembership_proof_very_small<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 2;

        let mut azks_element_set: Vec<AzksElement> = vec![];

        for i in 0..num_nodes {
            let mut label_arr = [0u8; 32];
            label_arr[31] = i;
            let label = NodeLabel::new(label_arr, 256u32);
            let mut hash = EMPTY_DIGEST;
            hash[31] = i;
            let node = AzksElement {
                label,
                value: AzksValue(hash),
            };
            azks_element_set.push(node);
        }
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        let search_label = azks_element_set[0].label;
        azks.batch_insert_nodes::<TC, _>(
            &db,
            azks_element_set.clone()[1..2].to_vec(),
            InsertMode::Directory,
        )
        .await?;
        let proof = azks
            .get_non_membership_proof::<TC, _>(&db, search_label)
            .await?;

        verify_nonmembership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

        Ok(())
    }

    // This test verifies if a non-membership proof in a small tree of 2 leaves
    // verifies.
    test_config!(test_nonmembership_proof_small);
    async fn test_nonmembership_proof_small<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 3;

        let mut rng = StdRng::seed_from_u64(42);
        let azks_element_set = gen_random_elements(num_nodes, &mut rng);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        let search_label = azks_element_set[num_nodes - 1].label;
        azks.batch_insert_nodes::<TC, _>(
            &db,
            azks_element_set.clone()[0..num_nodes - 1].to_vec(),
            InsertMode::Directory,
        )
        .await?;
        let proof = azks
            .get_non_membership_proof::<TC, _>(&db, search_label)
            .await?;

        verify_nonmembership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

        Ok(())
    }

    test_config!(test_nonmembership_proof);
    async fn test_nonmembership_proof<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 10;

        let mut rng = StdRng::seed_from_u64(42);
        let azks_element_set = gen_random_elements(num_nodes, &mut rng);
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        let search_label = azks_element_set[num_nodes - 1].label;
        azks.batch_insert_nodes::<TC, _>(
            &db,
            azks_element_set.clone()[0..num_nodes - 1].to_vec(),
            InsertMode::Directory,
        )
        .await?;
        let proof = azks
            .get_non_membership_proof::<TC, _>(&db, search_label)
            .await?;

        verify_nonmembership_for_tests_only::<TC>(azks.get_root_hash::<TC, _>(&db).await?, &proof)?;

        Ok(())
    }

    test_config!(test_append_only_proof_very_tiny);
    async fn test_append_only_proof_very_tiny<TC: Configuration>() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;

        let azks_element_set_1: Vec<AzksElement> = vec![AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
            value: AzksValue(EMPTY_DIGEST),
        }];
        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set_1, InsertMode::Directory)
            .await?;
        let start_hash = azks.get_root_hash::<TC, _>(&db).await?;

        let azks_element_set_2: Vec<AzksElement> = vec![AzksElement {
            label: NodeLabel::new(byte_arr_from_u64(0b01 << 62), 64),
            value: AzksValue(EMPTY_DIGEST),
        }];

        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set_2, InsertMode::Directory)
            .await?;
        let end_hash = azks.get_root_hash::<TC, _>(&db).await?;

        let proof = azks.get_append_only_proof::<TC, _>(&db, 1, 2).await?;
        audit_verify::<TC>(vec![start_hash, end_hash], proof).await?;

        Ok(())
    }

    test_config!(test_append_only_proof_tiny);
    async fn test_append_only_proof_tiny<TC: Configuration>() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;

        let azks_element_set_1: Vec<AzksElement> = vec![
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b0), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b1 << 63), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
        ];

        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set_1, InsertMode::Directory)
            .await?;
        let start_hash = azks.get_root_hash::<TC, _>(&db).await?;

        let azks_element_set_2: Vec<AzksElement> = vec![
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b1 << 62), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
            AzksElement {
                label: NodeLabel::new(byte_arr_from_u64(0b111 << 61), 64),
                value: AzksValue(EMPTY_DIGEST),
            },
        ];

        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set_2, InsertMode::Directory)
            .await?;
        let end_hash = azks.get_root_hash::<TC, _>(&db).await?;

        let proof = azks.get_append_only_proof::<TC, _>(&db, 1, 2).await?;
        audit_verify::<TC>(vec![start_hash, end_hash], proof).await?;
        Ok(())
    }

    test_config!(test_append_only_proof);
    async fn test_append_only_proof<TC: Configuration>() -> Result<(), AkdError> {
        let num_nodes = 10;

        let mut rng = StdRng::seed_from_u64(42);
        let azks_element_set_1 = gen_random_elements(num_nodes, &mut rng);

        let database = AsyncInMemoryDatabase::new();
        let db = StorageManager::new_no_cache(database);
        let mut azks = Azks::new::<TC, _>(&db).await?;
        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set_1.clone(), InsertMode::Directory)
            .await?;

        let start_hash = azks.get_root_hash::<TC, _>(&db).await?;

        let azks_element_set_2 = gen_random_elements(num_nodes, &mut rng);
        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set_2.clone(), InsertMode::Directory)
            .await?;

        let middle_hash = azks.get_root_hash::<TC, _>(&db).await?;

        let azks_element_set_3: Vec<AzksElement> = gen_random_elements(num_nodes, &mut rng);
        azks.batch_insert_nodes::<TC, _>(&db, azks_element_set_3.clone(), InsertMode::Directory)
            .await?;

        let end_hash = azks.get_root_hash::<TC, _>(&db).await?;

        let proof = azks.get_append_only_proof::<TC, _>(&db, 1, 3).await?;
        let hashes = vec![start_hash, middle_hash, end_hash];
        audit_verify::<TC>(hashes, proof).await?;

        Ok(())
    }

    test_config!(future_epoch_throws_error);
    async fn future_epoch_throws_error<TC: Configuration>() -> Result<(), AkdError> {
        let database = AsyncInMemoryDatabase::new();

        let db = StorageManager::new_no_cache(database);
        let azks = Azks::new::<TC, _>(&db).await?;

        let out = azks.get_root_hash_safe::<TC, _>(&db, 123).await;

        assert!(matches!(
            out,
            Err(AkdError::Directory(DirectoryError::InvalidEpoch(_)))
        ));
        Ok(())
    }

    fn gen_random_elements(num_nodes: usize, rng: &mut StdRng) -> Vec<AzksElement> {
        (0..num_nodes)
            .map(|_| {
                let label = crate::utils::random_label(rng);
                let mut value = EMPTY_DIGEST;
                rng.fill_bytes(&mut value);
                AzksElement {
                    label,
                    value: AzksValue(value),
                }
            })
            .collect()
    }
}
