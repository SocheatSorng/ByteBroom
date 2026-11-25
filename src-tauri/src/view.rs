//! What Rust sends to the page: display data only. Paths go out as text to show; the page sends
//! back only the IDs (see `boundary.rs`).

use crate::boundary::{FindingId, PreviewId};
use crate::session::{Ready, Snapshot};
use bytebroom_core::act::ActionResult;
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::SystemLayout;
use bytebroom_core::preview::{NotOffered, Note, not_offered, note};
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
    /// Why it can't be chosen (cloud file, can't be cleaned here), if so.
    pub not_offered: Option<&'static str>,
    /// A label to show beside it (a virtual machine disk), if any.
    pub note: Option<&'static str>,
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
pub struct UnscannedView {
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
    pub skipped: Vec<UnscannedView>,
}

/// One item in a preview.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewItem {
    /// The finding.
    pub id: FindingId,
    /// Its path, to show.
    pub path: String,
    /// Bytes the scan counted.
    pub bytes: u64,
    /// "green" or "amber".
    pub tier: &'static str,
}

/// What one action would do.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionView {
    /// "delete", "move" or "recycle".
    pub action: &'static str,
    /// The items, as chosen.
    pub items: Vec<PreviewItem>,
    /// Items actually acted on (an item inside a chosen folder goes with the folder).
    pub targets: usize,
    /// Bytes the scan counted for them.
    pub bytes: u64,
    /// Bytes that come back as soon as the clean ends.
    pub freed_now: u64,
    /// Bytes that come back only after the Recycle Bin is emptied.
    pub freed_after_emptying_bin: u64,
}

/// A chosen item that will not be cleaned, and why.
#[derive(Debug, Clone, Serialize)]
pub struct LeftOutView {
    /// The finding.
    pub id: FindingId,
    /// Its path, to show.
    pub path: String,
    /// Why, in words.
    pub why: &'static str,
}

/// The preview the owner confirms.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewView {
    /// What the page sends to `clean` to confirm exactly this.
    pub id: PreviewId,
    /// One entry per action.
    pub actions: Vec<ActionView>,
    /// Green items are chosen: one confirm covers them.
    pub confirm_green: bool,
    /// Amber items chosen: a second confirm lists every one.
    pub confirm_amber: Vec<PreviewItem>,
    /// Chosen items that will not be cleaned.
    pub left_out: Vec<LeftOutView>,
    /// Where moved items go.
    pub move_to: Option<String>,
    /// Bytes that come back as soon as the clean ends.
    pub freed_now: u64,
    /// Nothing would be acted on.
    pub empty: bool,
}

fn action_name(a: bytebroom_core::preview::Action) -> &'static str {
    use bytebroom_core::preview::Action;
    match a {
        Action::Delete => "delete",
        Action::Move => "move",
        Action::Recycle => "recycle",
    }
}

/// The page's view of a preview.
pub fn preview_view(ready: &Ready) -> PreviewView {
    let scan = ready.id.scan;
    let item = |n: usize| {
        let f = &ready.findings[n];
        PreviewItem {
            id: finding_id(scan, n),
            path: f.path.to_string(),
            bytes: f.bytes,
            tier: tier_name(f.tier),
        }
    };
    let pv = &ready.preview;
    PreviewView {
        id: ready.id,
        actions: pv
            .actions
            .iter()
            .map(|a| ActionView {
                action: action_name(a.action),
                items: a.items.iter().map(|n| item(*n)).collect(),
                targets: a.plan.targets.len(),
                bytes: a.plan.bytes,
                freed_now: a.freed_now,
                freed_after_emptying_bin: a.freed_after_emptying_bin,
            })
            .collect(),
        confirm_green: pv.confirm_green,
        confirm_amber: pv.confirm_amber.iter().map(|n| item(*n)).collect(),
        left_out: pv
            .left_out
            .iter()
            .map(|(n, why)| LeftOutView {
                id: item(*n).id,
                path: ready.findings[*n].path.to_string(),
                why: why.describe(),
            })
            .collect(),
        move_to: pv.move_to.as_ref().map(ToString::to_string),
        freed_now: pv.freed_now(),
        empty: pv.is_empty(),
    }
}

/// An item that stayed, and why.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedView {
    /// Its path, to show.
    pub path: String,
    /// Why it stayed, in words.
    pub reason: String,
}

/// What one action did.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionDone {
    /// "delete", "move" or "recycle".
    pub action: &'static str,
    /// Files and folders that are gone from where they were.
    pub removed: usize,
    /// Bytes that really came back.
    pub bytes_freed: u64,
    /// Bytes now in the Recycle Bin (they come back when it is emptied).
    pub bytes_recycled: u64,
    /// Bytes moved to the destination.
    pub bytes_moved: u64,
    /// Items that stayed, and why.
    pub skipped: Vec<SkippedView>,
    /// Items that are gone but need a look (e.g. not found in the bin afterwards).
    pub warnings: Vec<SkippedView>,
}

/// The result screen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanView {
    /// One entry per action.
    pub actions: Vec<ActionDone>,
    /// Bytes that came back now (deleted, and moved to another drive).
    pub freed_now: u64,
    /// Bytes in the Recycle Bin (they come back when it is emptied).
    pub recycled: u64,
    /// Where moved items went.
    pub move_to: Option<String>,
}

fn skipped_view(s: &bytebroom_core::engine::Skipped) -> SkippedView {
    SkippedView {
        path: s.path.to_string(),
        reason: s.reason.to_string(),
    }
}

/// The page's view of what a clean did. Honest: only the engine's own counts.
pub fn clean_view(results: &[ActionResult], move_to: Option<&WinPath>) -> CleanView {
    let actions: Vec<ActionDone> = results
        .iter()
        .map(|r| ActionDone {
            action: action_name(r.action),
            removed: r.outcome.removed.len(),
            bytes_freed: r.outcome.bytes_freed,
            bytes_recycled: r.outcome.bytes_recycled,
            bytes_moved: r.outcome.bytes_moved,
            skipped: r.outcome.skipped.iter().map(skipped_view).collect(),
            warnings: r.outcome.warnings.iter().map(skipped_view).collect(),
        })
        .collect();
    CleanView {
        freed_now: actions.iter().map(|a| a.bytes_freed + a.bytes_moved).sum(),
        recycled: actions.iter().map(|a| a.bytes_recycled).sum(),
        actions,
        move_to: move_to.map(ToString::to_string),
    }
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

fn finding_id(scan: u32, index: usize) -> FindingId {
    FindingId {
        scan,
        index: u32::try_from(index).unwrap_or(u32::MAX),
    }
}

/// A finding's view, with the ID the page will send back.
pub fn finding_view(scan: u32, index: usize, f: &Finding, layout: &SystemLayout) -> FindingView {
    FindingView {
        id: finding_id(scan, index),
        not_offered: not_offered(f, layout).map(NotOffered::describe),
        note: note(f).map(Note::describe),
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
pub fn scan_view(snap: &Snapshot, seen: u32, layout: &SystemLayout) -> ScanView {
    let findings = (seen != snap.version).then(|| {
        snap.findings
            .iter()
            .enumerate()
            .map(|(n, f)| finding_view(snap.scan, n, f, layout))
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
            .map(|s| UnscannedView {
                location: s.which.label(),
                why: s.why.clone(),
            })
            .collect(),
    }
}
