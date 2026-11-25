//! `bytebroom-scan`: a read-only look at what ByteBroom would offer to clean on this PC.
//!
//! It finds the scanner's locations, scans every green and amber rule, measures the red tier, and
//! prints the totals, the 20 largest items and what it could not read. It has no option that
//! deletes, moves or recycles anything, and it writes nothing: the list names the owner's files,
//! so it is only printed to this terminal.
//!
//! Run it in your project folder with `cargo run --release -p bytebroom-scan`.

// Printing to the terminal is this tool's whole job.
#![allow(clippy::print_stdout)]

use bytebroom_core::rules::Tier;
use bytebroom_core::scan::{ScanOptions, scan};
use bytebroom_core::summary::{human_bytes, summarize};
use bytebroom_core::walk::WalkOptions;
use bytebroom_core::win::locations::locations;
use bytebroom_core::win::red::red_sizes;
use bytebroom_core::win::system_layout;
use std::time::{Instant, SystemTime};

/// How many of the largest items to list.
const LARGEST: usize = 20;

fn tier_heading(tier: Tier) -> &'static str {
    match tier {
        Tier::Green => "Green (ticked for you; Windows or the app rebuilds these)",
        Tier::Amber => "Amber (never ticked for you; you choose)",
        Tier::Red => "Red (sizes only; freed later through Windows' own tools)",
    }
}

fn main() {
    println!("ByteBroom scan {}: read-only.", bytebroom_core::VERSION);
    println!("Nothing on this PC is changed by this scan.");
    println!();

    let layout = system_layout();
    let at = locations(&layout);
    println!("Looking in:");
    for (which, path) in at.scanned() {
        println!("  {:<22} {path}", which.label());
    }
    for drive in &at.other_drives {
        println!("  {:<22} {drive}", "another fixed drive");
    }
    for skipped in &at.skipped {
        println!("  Not scanned: {} ({})", skipped.which.label(), skipped.why);
    }
    println!();

    let started = Instant::now();
    let opts = ScanOptions {
        now: SystemTime::now(),
        cancel: None,
    };
    let report = scan(&at, &layout, &opts);
    let red = red_sizes(&at, &layout, &WalkOptions::default());
    println!("Scanned in {:.1} s.", started.elapsed().as_secs_f64());
    println!();

    let summary = summarize(&report.findings, LARGEST);
    for tier in [Tier::Green, Tier::Amber] {
        println!("{}", tier_heading(tier));
        for c in summary.categories.iter().filter(|c| c.rule.tier == tier) {
            println!(
                "  {:<34} {:>7} items  {:>12}",
                c.rule.label,
                c.items,
                human_bytes(c.bytes)
            );
        }
        println!();
    }
    println!("{}", tier_heading(Tier::Red));
    for r in &red {
        println!("  {:<34} {:>27}", r.rule.label, r.size.describe());
    }
    println!();

    println!("Totals (a file found by two rules, or inside another item, counts once):");
    for t in &summary.tiers {
        println!(
            "  {:<34} {:>7} items  {:>12}",
            t.tier.name(),
            t.items,
            human_bytes(t.bytes)
        );
    }
    println!(
        "  {:<34} {:>27}",
        "Ticked for you (green)",
        human_bytes(summary.pre_ticked_bytes)
    );
    println!();

    println!("The {LARGEST} largest items:");
    for &i in &summary.largest {
        let f = &report.findings[i];
        let mut note = String::new();
        if f.cloud {
            note.push_str("  [cloud file]");
        }
        if let Some(kept) = &f.duplicate_of {
            note.push_str(&format!("  [copy of {kept}]"));
        }
        println!(
            "  {:>12}  {:<6} {:<30} {}{note}",
            human_bytes(f.bytes),
            f.tier.name(),
            f.rule.label,
            f.path
        );
    }
    println!();

    let w = &report.walked;
    println!("What the scan could not or would not read:");
    println!(
        "  Folders it could not read (access denied): {}",
        w.unreadable
    );
    println!(
        "  Links and junctions not followed:          {}",
        w.links_skipped
    );
    println!(
        "  Protected or never-listed items skipped:   {}",
        w.protected_skipped
    );
    println!(
        "  Names it could not handle safely:          {}",
        w.odd_names
    );
    println!("  Folders that changed during the scan:      {}", w.changed);
    println!(
        "  Folders too deep to enter:                 {}",
        w.depth_limited
    );
    if report.cancelled {
        println!("  The scan was stopped early; totals are incomplete.");
    }
    println!();
    println!("This list names your files. It was only printed here; ByteBroom saved it nowhere.");
}
