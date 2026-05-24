// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Demonstrates the core AKD client workflow: publish a user pool, request a
//! lookup proof from the server for a chosen label, and verify it on the client
//! side without trusting the server.
//!
//! Module layout:
//!   setup.rs  — directory initialisation and entry-batch construction
//!   proofs.rs — server-side LookupProof generation
//!   client.rs — client-side proof verification and result display
//!
//! Run with:
//!   cargo run -p examples -- basic-lookup
//!   cargo run -p examples -- basic-lookup --label bob@example.com --users 6

mod client;
mod proofs;
mod setup;

use anyhow::{bail, Result};
use clap::Parser;

/// Concrete directory type shared across this module's sub-files.
/// Using a type alias keeps the generics out of every function signature.
type AkdDir = akd::directory::Directory<
    akd::WhatsAppV1Configuration,
    akd::storage::memory::AsyncInMemoryDatabase,
    akd::ecvrf::HardCodedAkdVRF,
>;

#[derive(Parser, Debug, Clone)]
#[clap(
    author,
    about = "Publish a pool of users then verify a client lookup proof for a chosen label"
)]
pub(crate) struct Args {
    /// Label (email address) to look up after publishing.
    /// Must belong to one of the users seeded by --users.
    #[arg(long, default_value = "alice@example.com")]
    label: String,

    /// Number of users to seed into the directory (1–10).
    /// Entries are drawn in order from a fixed pool of example accounts.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u8).range(1..=10))]
    users: u8,
}

pub(crate) async fn run(args: Args) -> Result<()> {
    // ── 1. Directory initialisation ──────────────────────────────────────────
    let akd = setup::init_directory().await?;
    println!("[setup]   Directory initialised (WhatsAppV1Configuration, in-memory storage).");

    // ── 2. Build and publish the user batch ──────────────────────────────────
    let (label_strings, entries) = setup::build_entries(args.users);

    // Guard: the requested label must actually be in the published batch.
    if !label_strings.contains(&args.label) {
        bail!(
            "'{}' is not in the published user pool.\n\
             Published labels: {}",
            args.label,
            label_strings.join(", ")
        );
    }

    let epoch_hash = setup::publish_batch(&akd, entries).await?;
    println!(
        "[publish] Epoch {} committed — {} users, root hash: {}",
        epoch_hash.epoch(),
        label_strings.len(),
        hex::encode(epoch_hash.hash())
    );

    // ── 3. Server generates a lookup proof ───────────────────────────────────
    let label = akd::AkdLabel::from(args.label.as_str());
    let response = proofs::request_lookup(&akd, label.clone()).await?;
    println!(
        "[server]  LookupProof generated for '{}' at epoch {}.",
        args.label,
        response.epoch_hash.epoch()
    );

    // ── 4. Client verifies the proof ─────────────────────────────────────────
    // In production the client receives the epoch_hash from a trusted third
    // party (transparency log / auditor), not from the server that supplied
    // the proof.
    let verified = client::verify(&akd, label, response).await?;
    client::display(&verified);

    Ok(())
}
