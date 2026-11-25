//! What Rust sends to the page: display data only. Paths go out as text to show; the page sends
//! back only the IDs (see `boundary.rs`).

use crate::boundary::FindingId;
use crate::session::Snapshot;
use bytebroom_core::red::{RedFinding, RedSize};
use bytebroom_core::rules::Tier;
use bytebroom_core::scan::Finding;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// One finding as the page lists it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingView {
    /// What the page sends back to choose it.
    pub id: FindingId,
    /// The rule's ID (the category).
    pub rule: &'static str,
    /// The category's name.
    pub label: &'static str,
    /// "green" or "amber".
    pub tier: &'static str,
    /// The full path, to show.
    pub path: String,
    /// The item's own name.
    pub name: String,
    /// Bytes the scan counted.
    pub bytes: u64,
    /// Files the scan counted.
    pub files: u64,
    /// Newest change, in seconds since 1970.
    pub newest: u64,
    /// A folder (with everything in it).
    pub is_folder: bool,
    /// Part of it is a cloud placeholder.
    pub cloud: bool,
    /// Ticked when first shown (green only).
    pub pre_ticked: bool,
    /// For a duplicate, the copy that is kept.
    pub duplicate_of: Option<String>,
}

/// One red-tier area: a size only.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedView {
    /// The area's name.
    pub label: &'static str,
    /// Its size in words ("3.2 GB", "not present", "needs admin").
    pub size: String,
    /// Its size in bytes, when known.
    pub bytes: Option<u64>,
}

/// A location that is not scanned.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedView {
    /// Which location.
    pub location: &'static str,
    /// Why.
    pub why: String,
}

/// The scan, as the page polls it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanView {
    /// The scan's number.
    pub scan: u32,
    /// "idle", "scanning", "hashing", "done" or "cancelled".
    pub phase: &'static str,
    /// The findings' version; the page passes it back to skip an unchanged list.
    pub version: u32,
    /// Milliseconds since the scan started (its total once finished).
    pub elapsed_ms: u64,
    /// Number of findings so far.
    pub items: usize,
    /// Their bytes.
    pub bytes: u64,
    /// The findings, only when they changed since the version the page has.
    pub findings: Option<Vec<FindingView>>,
    /// Red-tier sizes, once measured.
    pub red: Option<Vec<RedView>>,
    /// Locations that are not scanned.
    pub skipped: Vec<SkippedView>,
}

fn seconds(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Green => "green",
        Tier::Amber => "amber",
        Tier::Red => "red",
    }
}

/// A finding's view, with the ID the page will send back.
pub fn finding_view(scan: u32, index: usize, f: &Finding) -> FindingView {
    FindingView {
        id: FindingId {
            scan,
            index: u32::try_from(index).unwrap_or(u32::MAX),
        },
        rule: f.rule.id,
        label: f.rule.label,
        tier: tier_name(f.tier),
        path: f.path.to_string(),
        name: f.path.parts().last().cloned().unwrap_or_default(),
        bytes: f.bytes,
        files: f.files,
        newest: seconds(f.newest),
        is_folder: f.is_folder,
        cloud: f.cloud,
        pre_ticked: f.pre_ticked,
        duplicate_of: f.duplicate_of.as_ref().map(ToString::to_string),
    }
}

fn red_view(r: &RedFinding) -> RedView {
    RedView {
        label: r.rule.label,
        size: r.size.describe(),
        bytes: match r.size {
            RedSize::Bytes { bytes, .. } => Some(bytes),
            _ => None,
        },
    }
}

/// The page's view of `snap`. The list is included only if it changed since `seen`.
pub fn scan_view(snap: &Snapshot, seen: u32) -> ScanView {
    let findings = (seen != snap.version).then(|| {
        snap.findings
            .iter()
            .enumerate()
            .map(|(n, f)| finding_view(snap.scan, n, f))
            .collect()
    });
    ScanView {
        scan: snap.scan,
        phase: snap.phase.name(),
        version: snap.version,
        elapsed_ms: u64::try_from(snap.elapsed.as_millis()).unwrap_or(u64::MAX),
        items: snap.findings.len(),
        bytes: snap.findings.iter().map(|f| f.bytes).sum(),
        findings,
        red: snap.red.as_ref().map(|r| r.iter().map(red_view).collect()),
        skipped: snap
            .skipped
            .iter()
            .map(|s| SkippedView {
                location: s.which.label(),
                why: s.why.clone(),
            })
            .collect(),
    }
}
