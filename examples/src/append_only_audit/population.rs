// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Epoch content definitions and server-side publish logic.
//!
//! Each epoch in a key-transparency deployment is a mix of new registrations
//! and key rotations by existing users. The batches here are intentionally
//! varied so that the append-only proof spans a non-trivial series of tree
//! mutations — making it a realistic test for the auditor.

use super::AkdDir;
use akd::hash::Digest;
use akd::{AkdLabel, AkdValue, EpochHash};
use anyhow::Result;

/// One epoch's worth of changes: a list of (label, value) pairs to publish.
/// An existing label increments its version; a new label is registered fresh.
struct EpochContent {
    /// Human-readable description for display purposes.
    description: &'static str,
    /// The (label, value) entries to commit in this epoch.
    entries: &'static [(&'static str, &'static str)],
}

/// Eight pre-defined epoch batches. The `--epochs` flag selects how many of
/// these to publish before running the audit, from the front of the list.
const EPOCH_CONTENTS: &[EpochContent] = &[
    EpochContent {
        description: "alice, bob, carol register",
        entries: &[
            ("alice@example.com", "alice_key_v1"),
            ("bob@example.com", "bob_key_v1"),
            ("carol@example.com", "carol_key_v1"),
        ],
    },
    EpochContent {
        description: "alice rotates; dave joins",
        entries: &[
            ("alice@example.com", "alice_key_v2"),
            ("dave@example.com", "dave_key_v1"),
        ],
    },
    EpochContent {
        description: "bob rotates; erin joins",
        entries: &[
            ("bob@example.com", "bob_key_v2"),
            ("erin@example.com", "erin_key_v1"),
        ],
    },
    EpochContent {
        description: "carol rotates; frank joins",
        entries: &[
            ("carol@example.com", "carol_key_v2"),
            ("frank@example.com", "frank_key_v1"),
        ],
    },
    EpochContent {
        description: "dave and erin both rotate",
        entries: &[
            ("dave@example.com", "dave_key_v2"),
            ("erin@example.com", "erin_key_v2"),
        ],
    },
    EpochContent {
        description: "alice (3rd key), frank rotates",
        entries: &[
            ("alice@example.com", "alice_key_v3"),
            ("frank@example.com", "frank_key_v2"),
        ],
    },
    EpochContent {
        description: "grace joins; bob gets 3rd key",
        entries: &[
            ("grace@example.com", "grace_key_v1"),
            ("bob@example.com", "bob_key_v3"),
        ],
    },
    EpochContent {
        description: "heidi joins",
        entries: &[("heidi@example.com", "heidi_key_v1")],
    },
];

/// Publishes epoch number `idx` (0-based) and returns:
///   - the assigned epoch number (1-based, assigned by the directory)
///   - the resulting root hash
///   - the number of changes committed in this epoch
pub(super) async fn publish_epoch(
    dir: &AkdDir,
    idx: usize,
) -> Result<(u64, Digest, usize)> {
    let content = &EPOCH_CONTENTS[idx];
    let entries: Vec<(AkdLabel, AkdValue)> = content
        .entries
        .iter()
        .map(|(label, value)| (AkdLabel::from(*label), AkdValue::from(*value)))
        .collect();

    let change_count = entries.len();
    let EpochHash(epoch, root_hash) = dir.publish(entries).await?;
    Ok((epoch, root_hash, change_count))
}

/// Returns the human-readable description for epoch index `idx`.
pub(super) fn describe_epoch(idx: usize) -> String {
    EPOCH_CONTENTS[idx].description.to_string()
}
