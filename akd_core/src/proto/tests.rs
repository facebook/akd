// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Tests of the protobuf conversion logic

use super::specs::types::*;
use super::*;
use rand::{thread_rng, Rng};

// ================= Test helpers ================= //

fn random_hash() -> [u8; 32] {
    thread_rng().gen::<[u8; 32]>()
}

fn random_node() -> crate::Node {
    crate::Node {
        label: random_label(),
        hash: random_hash(),
    }
}

fn random_label() -> crate::NodeLabel {
    crate::NodeLabel {
        label_val: random_hash(),
        label_len: thread_rng().gen::<u32>(),
    }
}

// ================= Test cases ================= //

#[test]
fn test_convert_nodelabel() {
    let original = random_label();

    let protobuf: NodeLabel = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_node() {
    let original = random_node();

    let protobuf: Node = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_layer_proof() {
    let original = crate::LayerProof {
        label: random_label(),
        siblings: [random_node()],
        direction: Some(1),
    };

    let protobuf: LayerProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_membership_proof() {
    let original = crate::MembershipProof {
        label: random_label(),
        hash_val: random_hash(),
        layer_proofs: vec![crate::LayerProof {
            label: random_label(),
            siblings: [random_node()],
            direction: Some(1),
        }],
    };

    let protobuf: MembershipProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_non_membership_proof() {
    let original = crate::NonMembershipProof {
        label: random_label(),
        longest_prefix: random_label(),
        longest_prefix_children: [random_node(), random_node()],
        longest_prefix_membership_proof: crate::MembershipProof {
            label: random_label(),
            hash_val: random_hash(),
            layer_proofs: vec![crate::LayerProof {
                label: random_label(),
                siblings: [random_node()],
                direction: Some(1),
            }],
        },
    };

    let protobuf: NonMembershipProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_lookup_proof() {
    let mut rng = thread_rng();
    let original = crate::LookupProof {
        epoch: rng.gen(),
        plaintext_value: crate::AkdValue(random_hash().to_vec()),
        version: rng.gen(),
        existence_vrf_proof: random_hash().to_vec(),
        existence_proof: crate::MembershipProof {
            label: random_label(),
            hash_val: random_hash(),
            layer_proofs: vec![crate::LayerProof {
                label: random_label(),
                siblings: [random_node()],
                direction: Some(1),
            }],
        },
        marker_vrf_proof: random_hash().to_vec(),
        marker_proof: crate::MembershipProof {
            label: random_label(),
            hash_val: random_hash(),
            layer_proofs: vec![crate::LayerProof {
                label: random_label(),
                siblings: [random_node()],
                direction: Some(1),
            }],
        },
        freshness_vrf_proof: random_hash().to_vec(),
        freshness_proof: crate::NonMembershipProof {
            label: random_label(),
            longest_prefix: random_label(),
            longest_prefix_children: [random_node(), random_node()],
            longest_prefix_membership_proof: crate::MembershipProof {
                label: random_label(),
                hash_val: random_hash(),
                layer_proofs: vec![crate::LayerProof {
                    label: random_label(),
                    siblings: [random_node()],
                    direction: Some(1),
                }],
            },
        },
        commitment_proof: random_hash().to_vec(),
    };

    let protobuf: LookupProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_update_proof() {
    let mut rng = thread_rng();
    let original = crate::UpdateProof {
        epoch: rng.gen(),
        plaintext_value: crate::AkdValue(random_hash().to_vec()),
        version: rng.gen(),
        existence_vrf_proof: random_hash().to_vec(),
        existence_at_ep: crate::MembershipProof {
            label: random_label(),
            hash_val: random_hash(),
            layer_proofs: vec![crate::LayerProof {
                label: random_label(),
                siblings: [random_node()],
                direction: Some(1),
            }],
        },
        previous_version_vrf_proof: Some(random_hash().to_vec()),
        previous_version_stale_at_ep: Some(crate::MembershipProof {
            label: random_label(),
            hash_val: random_hash(),
            layer_proofs: vec![crate::LayerProof {
                label: random_label(),
                siblings: [random_node()],
                direction: Some(1),
            }],
        }),
        commitment_proof: random_hash().to_vec(),
    };

    let protobuf: UpdateProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_history_proof() {
    fn non_membership_proof() -> crate::NonMembershipProof {
        crate::NonMembershipProof {
            label: random_label(),
            longest_prefix: random_label(),
            longest_prefix_children: [random_node(), random_node()],
            longest_prefix_membership_proof: crate::MembershipProof {
                label: random_label(),
                hash_val: random_hash(),
                layer_proofs: vec![crate::LayerProof {
                    label: random_label(),
                    siblings: [random_node()],
                    direction: Some(1),
                }],
            },
        }
    }

    fn upd_proof() -> crate::UpdateProof {
        let mut rng = thread_rng();
        crate::UpdateProof {
            epoch: rng.gen(),
            plaintext_value: crate::AkdValue(random_hash().to_vec()),
            version: rng.gen(),
            existence_vrf_proof: random_hash().to_vec(),
            existence_at_ep: crate::MembershipProof {
                label: random_label(),
                hash_val: random_hash(),
                layer_proofs: vec![crate::LayerProof {
                    label: random_label(),
                    siblings: [random_node()],
                    direction: Some(1),
                }],
            },
            previous_version_vrf_proof: Some(random_hash().to_vec()),
            previous_version_stale_at_ep: Some(crate::MembershipProof {
                label: random_label(),
                hash_val: random_hash(),
                layer_proofs: vec![crate::LayerProof {
                    label: random_label(),
                    siblings: [random_node()],
                    direction: Some(1),
                }],
            }),
            commitment_proof: random_hash().to_vec(),
        }
    }

    let original = crate::HistoryProof {
        update_proofs: vec![upd_proof(), upd_proof(), upd_proof()],
        next_few_vrf_proofs: vec![
            random_hash().to_vec(),
            random_hash().to_vec(),
            random_hash().to_vec(),
        ],
        non_existence_of_next_few: vec![
            non_membership_proof(),
            non_membership_proof(),
            non_membership_proof(),
        ],
        future_marker_vrf_proofs: vec![
            random_hash().to_vec(),
            random_hash().to_vec(),
            random_hash().to_vec(),
        ],
        non_existence_of_future_markers: vec![
            non_membership_proof(),
            non_membership_proof(),
            non_membership_proof(),
        ],
    };

    let protobuf: HistoryProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_single_append_only_proof() {
    let inserted = [random_node(), random_node(), random_node()];
    let unchanged_nodes = [
        random_node(),
        random_node(),
        random_node(),
        random_node(),
        random_node(),
        random_node(),
    ];
    let original = crate::SingleAppendOnlyProof {
        inserted: inserted.to_vec(),
        unchanged_nodes: unchanged_nodes.to_vec(),
    };

    let protobuf: SingleAppendOnlyProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}
