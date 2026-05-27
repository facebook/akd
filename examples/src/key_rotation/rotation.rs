// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Rotation event types, planning logic, and epoch-level publishing.

use super::AkdDir;
use akd::hash::Digest;
use akd::{AkdLabel, AkdValue, EpochHash};
use anyhow::Result;
use std::fmt;

/// The business reason behind a key rotation.
///
/// In a real key-transparency system, clients that have cached a user's old
/// public key should be notified of the reason for the change so they can
/// decide whether to accept the new binding automatically or flag it for
/// manual review.
#[derive(Debug, Clone)]
pub(super) enum RotationReason {
    /// The user got a new device and generated a fresh key pair on it.
    DeviceUpgrade,
    /// The user's device was lost, stolen, or suspected compromised.
    SecurityIncident,
    /// A periodic rotation mandated by the user's security policy.
    ScheduledRotation,
    /// The user lost access to their primary device and recovered via backup.
    AccountRecovery,
}

impl fmt::Display for RotationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RotationReason::DeviceUpgrade => write!(f, "Device upgrade"),
            RotationReason::SecurityIncident => write!(f, "Security incident"),
            RotationReason::ScheduledRotation => write!(f, "Scheduled rotation"),
            RotationReason::AccountRecovery => write!(f, "Account recovery"),
        }
    }
}

/// A single planned rotation, before it has been committed to the directory.
pub(super) struct RotationEvent {
    /// 1-based index within the sequence of rotations for this user.
    pub(super) index: usize,
    pub(super) reason: RotationReason,
    /// The key name that will be stored as the new AkdValue.
    /// In production this would be raw public-key bytes; here we use a
    /// human-readable string for clarity.
    pub(super) key_name: String,
}

/// A rotation that has been committed to the directory and assigned an epoch.
pub(super) struct PublishedRotation {
    pub(super) event: RotationEvent,
    pub(super) epoch: u64,
    pub(super) root_hash: Digest,
}

/// Cycles through the four `RotationReason` variants to assign a realistic
/// motive to each rotation event, then generates a unique key name for each.
pub(super) fn plan_rotations(count: usize) -> Vec<RotationEvent> {
    let reasons = [
        RotationReason::DeviceUpgrade,
        RotationReason::SecurityIncident,
        RotationReason::ScheduledRotation,
        RotationReason::AccountRecovery,
    ];

    (1..=count)
        .map(|i| {
            let reason = reasons[(i - 1) % reasons.len()].clone();
            let key_name = format!("alice_key_rotation_{i}");
            RotationEvent {
                index: i,
                reason,
                key_name,
            }
        })
        .collect()
}

/// Publishes a single rotation event as a new epoch.
///
/// The label ("alice@example.com") stays constant; only the value changes.
/// Publishing the same label again increments its version counter in the tree —
/// the previous value is NOT deleted: it remains provable in history proofs.
pub(super) async fn apply_rotation(
    dir: &AkdDir,
    label: &AkdLabel,
    event: RotationEvent,
) -> Result<PublishedRotation> {
    let value = AkdValue::from(event.key_name.as_str());
    let EpochHash(epoch, root_hash) = dir.publish(vec![(label.clone(), value)]).await?;

    println!(
        "  rotation {:>2} — epoch {:>2} — {:20} — key: \"{}\"",
        event.index,
        epoch,
        event.reason.to_string(),
        event.key_name
    );

    Ok(PublishedRotation {
        event,
        epoch,
        root_hash,
    })
}
