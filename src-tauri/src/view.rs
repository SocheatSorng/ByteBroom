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

/// One red-tier action, as the window offers it (texts from `bytebroom_core::red_actions`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedActionView {
    /// The fixed choice the page sends back.
    pub id: crate::boundary::RedActionId,
    /// The button's text.
    pub title: &'static str,
    /// What it frees.
    pub frees: &'static str,
    /// Whether, and how, it can be undone.
    pub undo: &'static str,
    /// The word the owner types to confirm (decision 7).
    pub confirm_word: &'static str,
    /// Said before a helper action: a restore point comes first.
    pub restore_note: Option<&'static str>,
    /// Whether Windows will ask for administrator rights (UAC).
    pub needs_admin: bool,
}

/// Every red-tier action the window offers. Pure.
pub fn red_action_views() -> Vec<RedActionView> {
    crate::boundary::RedActionId::ALL
        .into_iter()
        .map(|id| {
            let a = id.action();
            RedActionView {
                id,
                title: a.title(),
                frees: a.frees(),
                undo: a.undo(),
                confirm_word: a.confirm_word(),
                restore_note: a.restore_note(),
                needs_admin: a.admin_action().is_some(),
            }
        })
        .collect()
}

/// What a red-tier action did, with the red sizes measured again.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedActionResult {
    /// What happened, in words for the owner.
    pub message: String,
    /// The red-tier sizes, measured again afterwards.
    pub red: Vec<RedView>,
}

/// The red sizes as the page shows them.
pub fn red_views(red: &[RedFinding]) -> Vec<RedView> {
    red.iter().map(red_view).collect()
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
    /// Set when the clean worked but the history could not record what it recycled.
    pub history_note: Option<String>,
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
        // The engine's `bytes_freed` already includes moved bytes that really came back (another
        // drive, no other hard links); adding `bytes_moved` would count a move twice (owner's
        // real test: 1.2 GB moved showed as 2.4 GB back).
        freed_now: actions.iter().map(|a| a.bytes_freed).sum(),
        recycled: actions.iter().map(|a| a.bytes_recycled).sum(),
        actions,
        move_to: move_to.map(ToString::to_string),
        history_note: None,
    }
}

/// One move in the history.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MovedView {
    /// Its place in its clean, for `put_back`.
    pub item: u32,
    /// The file's name.
    pub name: String,
    /// Where it was (and goes back to).
    pub from: String,
    /// Where it is now.
    pub to: String,
    /// Size in bytes.
    pub bytes: u64,
    /// When it was put back (seconds since 1970), or `None` while it is still moved.
    pub put_back_at: Option<u64>,
    /// Why "Put back" can't be offered now (still moved only), or `None` if it can.
    pub unavailable: Option<&'static str>,
}

/// One clean's moves.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveGroupView {
    /// Its place in the list, for `put_back`.
    pub group: u32,
    /// When it moved them (seconds since 1970).
    pub when: u64,
    /// The moves, oldest first.
    pub items: Vec<MovedView>,
    /// How many are still moved and can be put back now.
    pub can_put_back: usize,
}

/// One item ByteBroom sent to the Recycle Bin.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecycledView {
    /// When (seconds since 1970).
    pub when: u64,
    /// Its name.
    pub name: String,
    /// Where it was.
    pub original: String,
    /// Size in bytes.
    pub bytes: u64,
}

/// The History view: moves by clean (newest first) and recycled items (newest first).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryView {
    /// The list's number: `put_back` IDs from any other list are refused.
    pub list: u32,
    /// One entry per clean that moved files.
    pub moves: Vec<MoveGroupView>,
    /// Recycled items.
    pub recycled: Vec<RecycledView>,
}

fn file_name(p: &WinPath) -> String {
    p.parts().last().cloned().unwrap_or_default()
}

/// Build the History view. `unavailable` says why a still-moved file can't be put back now
/// (only a quick look; putting back checks everything again).
pub fn history_view(
    list: u32,
    groups: &[Vec<bytebroom_core::history::MoveRecord>],
    recycled: &[bytebroom_core::history::RecycledRecord],
    unavailable: &dyn Fn(&bytebroom_core::relocate::JournalEntry) -> Option<&'static str>,
) -> HistoryView {
    let moves = groups
        .iter()
        .enumerate()
        .map(|(g, recs)| {
            let items: Vec<MovedView> = recs
                .iter()
                .enumerate()
                .map(|(i, r)| MovedView {
                    item: u32::try_from(i).unwrap_or(u32::MAX),
                    name: file_name(&r.entry.source),
                    from: r.entry.source.to_string(),
                    to: r.entry.dest.to_string(),
                    bytes: r.entry.size,
                    put_back_at: r.undone,
                    unavailable: if r.undone.is_some() {
                        None
                    } else {
                        unavailable(&r.entry)
                    },
                })
                .collect();
            MoveGroupView {
                group: u32::try_from(g).unwrap_or(u32::MAX),
                when: recs.iter().map(|r| r.entry.time).min().unwrap_or(0),
                can_put_back: items
                    .iter()
                    .filter(|m| m.put_back_at.is_none() && m.unavailable.is_none())
                    .count(),
                items,
            }
        })
        .collect();
    let recycled = recycled
        .iter()
        .rev()
        .map(|r| RecycledView {
            when: r.time,
            name: file_name(&r.original),
            original: r.original.to_string(),
            bytes: r.size,
        })
        .collect();
    HistoryView {
        list,
        moves,
        recycled,
    }
}

/// What a put-back did, in words, and the history afterwards.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutBackView {
    /// For the owner.
    pub message: String,
    /// The history, read again.
    pub history: HistoryView,
}

/// The owner's words for a put-back's results: how many went back, and each one that didn't,
/// with why.
pub fn put_back_message(
    wanted: &[bytebroom_core::relocate::JournalEntry],
    results: &[bytebroom_core::history::UndoResult],
) -> String {
    use bytebroom_core::history::UndoResult;
    let back = results
        .iter()
        .filter(|r| !matches!(r, UndoResult::Refused(_)))
        .count();
    let mut text = if wanted.len() == 1 {
        if back == 1 {
            format!("{} is back where it was.", file_name(&wanted[0].source))
        } else {
            format!("{} was not put back.", file_name(&wanted[0].source))
        }
    } else {
        format!("Put back {back} of {} files.", wanted.len())
    };
    for (e, r) in wanted.iter().zip(results) {
        match r {
            UndoResult::PutBack => {}
            UndoResult::PutBackNotRecorded(_) => text.push_str(&format!(
                "\n{}: put back, but the history could not record it.",
                file_name(&e.source)
            )),
            UndoResult::Refused(why) => {
                text.push_str(&format!("\n{}: {why}.", file_name(&e.source)));
            }
        }
    }
    text
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytebroom_core::engine::Outcome;
    use bytebroom_core::preview::Action;

    fn result(action: Action, freed: u64, recycled: u64, moved: u64) -> ActionResult {
        ActionResult {
            action,
            outcome: Outcome {
                bytes_freed: freed,
                bytes_recycled: recycled,
                bytes_moved: moved,
                ..Outcome::default()
            },
        }
    }

    /// Owner's real test: a 1.2 GB move to another drive showed "2.4 GB back". The engine counts
    /// a move that frees space in both `bytes_moved` and `bytes_freed`; only the latter is space
    /// back.
    #[test]
    fn space_back_counts_a_move_once_and_the_bin_not_at_all() {
        let gb = 1024 * 1024 * 1024;
        let view = clean_view(
            &[
                result(Action::Delete, 26 * 1024 * 1024, 0, 0),
                result(Action::Move, gb, 0, gb),
                result(Action::Recycle, 0, 5000, 0),
            ],
            None,
        );
        assert_eq!(view.freed_now, gb + 26 * 1024 * 1024);
        assert_eq!(view.recycled, 5000);
        // A move within one drive moves bytes but frees none.
        let same_drive = clean_view(&[result(Action::Move, 0, 0, gb)], None);
        assert_eq!(same_drive.freed_now, 0);
    }

    fn moved(n: u64, undone: Option<u64>) -> bytebroom_core::history::MoveRecord {
        bytebroom_core::history::MoveRecord {
            entry: bytebroom_core::relocate::JournalEntry {
                clean: Some(1),
                time: 100 + n,
                sha256: "0F".repeat(32),
                size: n,
                source: WinPath::parse(&format!("C:\\Users\\Ann\\Downloads\\f{n}.iso")).unwrap(),
                dest: WinPath::parse(&format!("D:\\Keep\\f{n}.iso")).unwrap(),
            },
            undone,
        }
    }

    #[test]
    fn the_history_offers_put_back_only_for_files_still_moved_and_reachable() {
        use bytebroom_core::history::RecycledRecord;
        let groups = vec![vec![moved(1, None), moved(2, Some(500)), moved(3, None)]];
        let recycled = vec![
            RecycledRecord {
                clean: 1,
                time: 10,
                size: 5,
                original: WinPath::parse("C:\\Users\\Ann\\Downloads\\old.msi").unwrap(),
                in_bin: WinPath::parse("C:\\$Recycle.Bin\\S-1\\$R1.msi").unwrap(),
            },
            RecycledRecord {
                clean: 2,
                time: 20,
                size: 6,
                original: WinPath::parse("C:\\Users\\Ann\\Downloads\\new.msi").unwrap(),
                in_bin: WinPath::parse("C:\\$Recycle.Bin\\S-1\\$R2.msi").unwrap(),
            },
        ];
        let unplugged = |e: &bytebroom_core::relocate::JournalEntry| {
            (e.size == 3).then_some("the moved file isn't there")
        };
        let v = history_view(7, &groups, &recycled, &unplugged);
        assert_eq!(v.list, 7);
        let g = &v.moves[0];
        assert_eq!((g.group, g.when, g.can_put_back), (0, 101, 1));
        assert_eq!(g.items[0].name, "f1.iso");
        assert_eq!(g.items[0].unavailable, None);
        assert_eq!(g.items[1].put_back_at, Some(500));
        assert_eq!(
            g.items[1].unavailable, None,
            "a put-back file needs no reason"
        );
        assert_eq!(g.items[2].unavailable, Some("the moved file isn't there"));
        // Recycled items, newest first.
        assert_eq!(v.recycled[0].name, "new.msi");
        assert_eq!(v.recycled[1].original, "C:\\Users\\Ann\\Downloads\\old.msi");
    }

    #[test]
    fn the_put_back_message_says_how_many_and_why_not() {
        use bytebroom_core::history::UndoResult;
        let one = [moved(1, None).entry];
        assert_eq!(
            put_back_message(&one, &[UndoResult::PutBack]),
            "f1.iso is back where it was."
        );
        assert_eq!(
            put_back_message(
                &one,
                &[UndoResult::Refused("it was already put back".into())]
            ),
            "f1.iso was not put back.\nf1.iso: it was already put back."
        );
        let two = [moved(1, None).entry, moved(2, None).entry];
        let text = put_back_message(
            &two,
            &[
                UndoResult::PutBackNotRecorded("disk full".into()),
                UndoResult::Refused("something is already at the original place".into()),
            ],
        );
        assert!(text.starts_with("Put back 1 of 2 files."), "{text}");
        assert!(text.contains("f1.iso: put back, but the history could not record it."));
        assert!(text.contains("f2.iso: something is already at the original place."));
    }
}
