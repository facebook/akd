// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! CLI subcommand for key directory scaling benchmarks.
//!
//! Measures how generation times and verification times scale with directory size.
//!
//! ```text
//! cargo run -p examples --release -- scaling-bench --sizes 10,14,17
//! ```
//!
//! ## Adding a new key directory implementation
//!
//! 1. Create a new file (e.g. `my_kd_setup.rs`) implementing
//!    `akd_traits::bench::BenchmarkSetup` and [`cache::BenchCache`] for your
//!    directory type.
//! 2. Add `mod my_kd_setup;` in this file.
//! 3. Add a match arm in `run()` for `--impl my-kd`.
//!
//! Then run:
//! ```text
//! cargo run -p examples --release -- scaling-bench --impl my-kd --sizes 10,14
//! ```

mod akd_setup;
mod cache;
mod runner;
mod table;

use clap::Parser;

use cache::BenchCache;

/// Operations that can be benchmarked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Publish,
    PublishUpdate,
    Lookup,
    LookupVerify,
    History,
    Audit,
    AuditVerify,
    Setup,
}

impl Op {
    fn all() -> Vec<Op> {
        vec![
            Op::Publish,
            Op::PublishUpdate,
            Op::Lookup,
            Op::LookupVerify,
            Op::History,
            Op::Audit,
            Op::AuditVerify,
        ]
    }

    fn from_str(s: &str) -> Option<Op> {
        match s {
            "publish" => Some(Op::Publish),
            "publish_update" => Some(Op::PublishUpdate),
            "lookup" => Some(Op::Lookup),
            "lookup_verify" => Some(Op::LookupVerify),
            "history" => Some(Op::History),
            "audit" => Some(Op::Audit),
            "audit_verify" => Some(Op::AuditVerify),
            _ => None,
        }
    }
}

/// Output format for benchmark results.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum Format {
    #[default]
    Table,
    Csv,
    Json,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct Args {
    /// Comma-separated log2 directory sizes to benchmark (e.g. 10,14,17 means 2^10, 2^14, 2^17)
    #[clap(long, default_value = "10,14,17")]
    sizes: String,

    /// Comma-separated operations (publish,publish_update,lookup,lookup_verify,history,audit,audit_verify)
    #[clap(long, default_value = "all")]
    ops: String,

    /// Output format: table, csv, json
    #[clap(long, default_value = "table")]
    format: String,

    /// Log2 of entries per update epoch (e.g. 7 means 2^7=128 entries)
    #[clap(long, default_value = "7")]
    updates_per_epoch: u32,

    /// Number of iterations for timing (median of N runs)
    #[clap(long, default_value = "3")]
    iterations: usize,

    /// Key directory implementation to benchmark (e.g. "akd")
    #[clap(long = "impl", default_value = "akd")]
    impl_name: String,

    /// Disable database caching (force fresh setup)
    #[clap(long)]
    no_cache: bool,

    /// Clear all cached databases and exit
    #[clap(long)]
    clear_cache: bool,

    /// Sweep mode: comma-separated log2 values for updates-per-epoch (e.g. 5,7,9,10,12)
    #[clap(long)]
    sweep_updates_per_epoch: Option<String>,
}

impl Args {
    fn parse_sizes(&self) -> Vec<usize> {
        self.sizes
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .map(|exp| 1usize << exp)
            .collect()
    }

    fn parse_ops(&self) -> Vec<Op> {
        if self.ops.trim() == "all" {
            return Op::all();
        }
        self.ops
            .split(',')
            .filter_map(|s| Op::from_str(s.trim()))
            .collect()
    }

    fn parse_format(&self) -> Option<Format> {
        match self.format.trim() {
            "table" => Some(Format::Table),
            "csv" => Some(Format::Csv),
            "json" => Some(Format::Json),
            _ => None,
        }
    }

    fn parse_sweep_m_values(&self) -> Option<Vec<usize>> {
        self.sweep_updates_per_epoch.as_ref().map(|s| {
            s.split(',')
                .filter_map(|v| v.trim().parse::<u32>().ok())
                .map(|exp| 1usize << exp)
                .collect()
        })
    }
}

async fn run_with<S: BenchCache>(args: &Args, format: Format, sizes: &[usize], ops: &[Op]) {
    let use_cache = !args.no_cache;

    // Sweep mode: vary updates-per-epoch for a fixed N
    if let Some(m_values) = args.parse_sweep_m_values() {
        if m_values.is_empty() {
            eprintln!("Error: no valid M values in --sweep-updates-per-epoch");
            return;
        }
        let size = sizes[0]; // Use first size as fixed N
        let sweep_results =
            runner::run_sweep_updates::<S>(size, &m_values, args.iterations, use_cache).await;

        match format {
            Format::Table | Format::Json => {
                table::print_sweep_table(&sweep_results, size, args.iterations)
            }
            Format::Csv => table::print_sweep_csv(&sweep_results),
        }
        return;
    }

    let updates_per_epoch = 1usize << args.updates_per_epoch;
    let results =
        runner::run_benchmarks::<S>(sizes, ops, updates_per_epoch, args.iterations, use_cache)
            .await;

    match format {
        Format::Table => {
            println!("Key Directory Scaling Benchmarks: {}", S::name());
            println!("{}", "=".repeat(24 + S::name().len()));
            println!();
            table::print_table(&results, sizes, ops);
        }
        Format::Csv => table::print_csv(&results, sizes, ops),
        Format::Json => table::print_json(&results, sizes, ops),
    }
}

pub(crate) async fn run(args: Args) {
    if args.clear_cache {
        cache::clear();
        return;
    }

    let sizes = args.parse_sizes();
    let ops = args.parse_ops();

    if sizes.is_empty() {
        eprintln!("Error: no valid sizes provided");
        return;
    }
    if ops.is_empty() {
        eprintln!("Error: no valid operations provided");
        return;
    }
    if args.iterations < 1 {
        eprintln!("Error: iterations must be at least 1");
        return;
    }
    let format = match args.parse_format() {
        Some(f) => f,
        None => {
            eprintln!(
                "Error: invalid format '{}' (expected: table, csv, json)",
                args.format
            );
            return;
        }
    };

    match args.impl_name.as_str() {
        "akd" => run_with::<akd_setup::AkdSetup>(&args, format, &sizes, &ops).await,
        other => eprintln!("Unknown implementation '{other}'. Available: akd"),
    }
}
