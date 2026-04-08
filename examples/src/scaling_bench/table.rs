// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Table formatting and CSV/JSON output for scaling benchmark results.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::time::Duration;

use super::Op;

/// Key for looking up results: (operation, directory_size).
pub(crate) type ResultKey = (Op, usize);

/// All benchmark results: maps (op, size) to a timing duration.
pub(crate) type Results = HashMap<ResultKey, Duration>;

/// Row descriptor: label and the operation to look up.
struct Row {
    label: &'static str,
    op: Op,
}

/// All rows to display in the table.
fn table_rows(ops: &[Op]) -> Vec<Row> {
    let mut rows = Vec::new();

    // Setup is always recorded
    rows.push(Row {
        label: "Setup",
        op: Op::Setup,
    });

    if ops.contains(&Op::Publish) {
        rows.push(Row {
            label: "Publish N",
            op: Op::Publish,
        });
    }
    if ops.contains(&Op::PublishUpdate) {
        rows.push(Row {
            label: "Publish update",
            op: Op::PublishUpdate,
        });
    }
    if ops.contains(&Op::Lookup) {
        rows.push(Row {
            label: "Lookup gen",
            op: Op::Lookup,
        });
    }
    if ops.contains(&Op::LookupVerify) {
        rows.push(Row {
            label: "Lookup verify",
            op: Op::LookupVerify,
        });
    }
    if ops.contains(&Op::History) {
        rows.push(Row {
            label: "History gen (5 ep)",
            op: Op::History,
        });
    }
    if ops.contains(&Op::Audit) {
        rows.push(Row {
            label: "Audit gen",
            op: Op::Audit,
        });
    }
    if ops.contains(&Op::AuditVerify) {
        rows.push(Row {
            label: "Audit verify",
            op: Op::AuditVerify,
        });
    }

    rows
}

/// Format a Duration for display.
fn format_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros < 1_000 {
        format!("{} us", micros)
    } else if micros < 1_000_000 {
        format!("{:.1} ms", micros as f64 / 1_000.0)
    } else {
        format!("{:.2} s", micros as f64 / 1_000_000.0)
    }
}

/// Format a directory size as 2^k if it's a power of two, otherwise with commas.
fn format_n(n: usize) -> String {
    if n.is_power_of_two() && n > 1 {
        format!("2^{}", n.trailing_zeros())
    } else {
        let s = n.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect()
    }
}

/// Print the results as a formatted table.
pub(crate) fn print_table(results: &Results, sizes: &[usize], ops: &[Op]) {
    let rows = table_rows(ops);
    if rows.is_empty() {
        return;
    }

    // Compute column widths
    let label_width = rows.iter().map(|r| r.label.len()).max().unwrap_or(0);
    let col_width = 12;

    // Header
    let mut header = String::new();
    write!(header, "{:width$}", "", width = label_width + 1).unwrap();
    for &size in sizes {
        write!(
            header,
            "| N={:<width$}",
            format_n(size),
            width = col_width - 3
        )
        .unwrap();
    }
    println!("{header}");

    // Separator
    let mut sep = String::new();
    for _ in 0..=label_width {
        sep.push('-');
    }
    for _ in sizes {
        sep.push('+');
        for _ in 0..col_width {
            sep.push('-');
        }
    }
    println!("{sep}");

    // Data rows
    for row in &rows {
        let mut line = String::new();
        write!(line, "{:<width$} ", row.label, width = label_width).unwrap();
        for &size in sizes {
            let key = (row.op, size);
            let cell = match results.get(&key) {
                Some(d) => format_duration(*d),
                None => "-".to_string(),
            };
            write!(line, "| {:<width$}", cell, width = col_width - 1).unwrap();
        }
        println!("{line}");
    }
}

/// Print the results as CSV to stdout.
pub(crate) fn print_csv(results: &Results, sizes: &[usize], ops: &[Op]) {
    let rows = table_rows(ops);

    // Header
    print!("metric");
    for &size in sizes {
        print!(",N={size}");
    }
    println!();

    // Data
    for row in &rows {
        print!("{}", row.label);
        for &size in sizes {
            let key = (row.op, size);
            let cell = match results.get(&key) {
                Some(d) => format!("{:.3}", d.as_secs_f64() * 1000.0),
                None => String::new(),
            };
            print!(",{cell}");
        }
        println!();
    }
}

/// Print the results as JSON to stdout.
pub(crate) fn print_json(results: &Results, sizes: &[usize], ops: &[Op]) {
    let rows = table_rows(ops);

    println!("[");
    for (ri, row) in rows.iter().enumerate() {
        println!("  {{");
        println!("    \"metric\": \"{}\",", row.label);
        println!("    \"values\": {{");
        for (si, &size) in sizes.iter().enumerate() {
            let key = (row.op, size);
            let value = match results.get(&key) {
                Some(d) => format!("{:.3}", d.as_secs_f64() * 1000.0),
                None => "null".to_string(),
            };
            let comma = if si + 1 < sizes.len() { "," } else { "" };
            println!("      \"{size}\": {value}{comma}");
        }
        println!("    }},");
        println!("    \"unit\": \"ms\"");
        let comma = if ri + 1 < rows.len() { "," } else { "" };
        println!("  }}{comma}");
    }
    println!("]");
}

/// Print sweep results as an ASCII bar chart table.
pub(crate) fn print_sweep_table(results: &[(usize, Duration)], size: usize, iterations: usize) {
    let bar_width = 50;
    let blocks = ['█', '▉', '▊', '▋', '▌', '▍', '▎', '▏'];

    let max_time = results
        .iter()
        .map(|(_, d)| d.as_nanos())
        .max()
        .unwrap_or(1)
        .max(1);

    println!(
        "Publish update time vs M (N={}, median of {} iteration{})",
        format_n(size),
        iterations,
        if iterations == 1 { "" } else { "s" }
    );

    // Header
    println!(" {:>6} | {:>10} |", "M", "Time");
    println!("--------+------------+{}", "-".repeat(bar_width + 1));

    for &(m, duration) in results {
        let m_label = format_n(m);
        let time_str = format_duration(duration);
        let ratio = duration.as_nanos() as f64 / max_time as f64;
        let bar_float = ratio * bar_width as f64;
        let full_blocks = bar_float as usize;
        let remainder = ((bar_float - full_blocks as f64) * 8.0).min(7.0) as usize;

        let mut bar = String::new();
        for _ in 0..full_blocks {
            bar.push('█');
        }
        if remainder > 0 && full_blocks < bar_width {
            bar.push(blocks[8 - remainder]);
        }

        println!(" {:>6} | {:>10} | {}", m_label, time_str, bar);
    }
}

/// Print sweep results as CSV.
pub(crate) fn print_sweep_csv(results: &[(usize, Duration)]) {
    println!("m,time_ms");
    for &(m, duration) in results {
        println!("{},{:.3}", m, duration.as_secs_f64() * 1000.0);
    }
}
