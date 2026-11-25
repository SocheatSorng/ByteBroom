//! From the owner's choices (a finding and an action each) to a preview of exactly what a clean
//! would do. Pure: no disk access, so every case is tested on made-up findings.
//!
//! The preview says, per action, which items it would act on, how many bytes the scan counted,
//! and how many bytes would **really** come back now:
//!
//! - **Delete:** all of them.
//! - **Move** (only to another drive): all of them, on the drive they leave.
//! - **Recycle Bin:** none until the bin is emptied, because each drive's bin is on that drive.
//!
//! It also lists what needs confirming (one confirm for green items; a second one listing every
//! amber item) and the chosen items that can't be cleaned, with the reason. Red-tier items, unknown
//! items and contradictory choices refuse the whole preview, so a bad request never half-runs.

use crate::clean::{CleanPlan, SelectError, plan_clean};
use crate::paths::WinPath;
use crate::policy::{SystemLayout, denied_reason};
use crate::rules::{Tier, VM_DISK_EXTENSIONS};
use crate::scan::Finding;
use std::fmt;

/// What to do with a chosen item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    /// Send it to the Recycle Bin.
    Recycle,
    /// Delete it for good.
    Delete,
    /// Move it to a folder on another drive.
    Move,
}

impl Action {
    /// Every action, in the order a preview lists them.
    pub const ALL: [Action; 3] = [Action::Delete, Action::Move, Action::Recycle];
}

/// One of the owner's choices: a finding (by its place in the scan) and an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice {
    /// The finding's index in the scan's findings.
    pub index: usize,
    /// What to do with it.
    pub action: Action,
}

/// Why a finding is shown but can't be chosen, or why a chosen item was left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotOffered {
    /// A cloud placeholder (e.g. OneDrive): its bytes may not be on this disk, and ByteBroom never
    /// acts on placeholders.
    CloudFile,
    /// Its rule's folder is a place a clean may not use as its root (directly in the profile or
    /// at a drive root), so it can't be cleaned here (security review F5).
    CantCleanHere,
    /// A duplicate whose kept copy is also chosen: no copy would be left, so this one stays.
    LastCopy,
    /// Chosen for a move, but it is already on the destination's drive (moving it there would
    /// free nothing).
    SameDriveMove,
}

impl NotOffered {
    /// Plain words for the owner.
    pub fn describe(self) -> &'static str {
        match self {
            Self::CloudFile => "cloud file (OneDrive): not on this disk, so not offered",
            Self::CantCleanHere => "can't be cleaned here",
            Self::LastCopy => "its kept copy is also chosen, so this copy stays",
            Self::SameDriveMove => "already on the destination's drive: moving frees nothing",
        }
    }
}

/// A label shown beside a finding (owner's decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// A virtual machine disk: deleting it removes the VM; moving it is suggested instead.
    VmDisk,
}

impl Note {
    /// Plain words for the owner.
    pub fn describe(self) -> &'static str {
        match self {
            Self::VmDisk => "virtual machine disk: deleting it removes the VM (moving it is safer)",
        }
    }
}

/// Whether a finding can be chosen at all, and why not. Pure.
pub fn not_offered(f: &Finding, layout: &SystemLayout) -> Option<NotOffered> {
    if f.cloud {
        return Some(NotOffered::CloudFile);
    }
    if denied_reason(&f.root, layout).is_some() {
        return Some(NotOffered::CantCleanHere);
    }
    None
}

/// The label shown beside a finding, if any. Pure.
pub fn note(f: &Finding) -> Option<Note> {
    let name = f.path.parts().last()?;
    let (_, ext) = name.rsplit_once('.')?;
    (!f.is_folder
        && VM_DISK_EXTENSIONS
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e)))
    .then_some(Note::VmDisk)
}

/// Why a preview can't be made at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewError {
    /// Nothing was chosen.
    Empty,
    /// A chosen number is not a finding.
    Unknown(usize),
    /// A red-tier item was chosen; those are freed only through Windows' own tools.
    RedTier(usize),
    /// The same item was chosen twice with different actions.
    ChosenTwice(usize),
    /// An item is inside another chosen item that has a different action, so one would undo
    /// the other.
    Conflict {
        /// The inner item.
        inner: usize,
        /// The item it is inside.
        outer: usize,
    },
    /// Items are chosen for a move but no destination was picked.
    NoDestination,
    /// The scan's own selection rules refused it (a finding not inside its root).
    Select(SelectError),
}

impl fmt::Display for PreviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "nothing is chosen"),
            Self::Unknown(n) => write!(f, "item {n} is not in the scan"),
            Self::RedTier(_) => write!(
                f,
                "Windows' own areas are freed in a later version, through Windows' own tools"
            ),
            Self::ChosenTwice(_) => write!(f, "an item was chosen twice with different actions"),
            Self::Conflict { .. } => write!(
                f,
                "an item is inside another chosen item with a different action; choose one"
            ),
            Self::NoDestination => write!(f, "choose a folder on another drive to move to"),
            Self::Select(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PreviewError {}

/// What one action would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPlan {
    /// The action.
    pub action: Action,
    /// The chosen items it covers (by index), in the order chosen; items inside another chosen
    /// item are covered by that item.
    pub items: Vec<usize>,
    /// The roots and targets the engine would get.
    pub plan: CleanPlan,
    /// Bytes that come back as soon as the clean ends.
    pub freed_now: u64,
    /// Bytes that come back only after the Recycle Bin is emptied.
    pub freed_after_emptying_bin: u64,
}

/// The whole preview.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Preview {
    /// One entry per action that has items, in [`Action::ALL`] order.
    pub actions: Vec<ActionPlan>,
    /// Green items are chosen: one confirm covers them all.
    pub confirm_green: bool,
    /// Amber items chosen (by index): a second confirm lists every one.
    pub confirm_amber: Vec<usize>,
    /// Chosen items left out, and why.
    pub left_out: Vec<(usize, NotOffered)>,
    /// Where moved items go.
    pub move_to: Option<WinPath>,
}

impl Preview {
    /// Bytes that come back as soon as the clean ends.
    pub fn freed_now(&self) -> u64 {
        self.actions.iter().map(|a| a.freed_now).sum()
    }

    /// True when nothing would be acted on.
    pub fn is_empty(&self) -> bool {
        self.actions.iter().all(|a| a.plan.targets.is_empty())
    }
}

/// Build the preview for `choices` over the scan's `findings`. `move_to` is the folder the owner
/// picked for moves (already checked to be a real folder on a fixed drive). Pure.
pub fn preview(
    findings: &[Finding],
    choices: &[Choice],
    move_to: Option<&WinPath>,
    layout: &SystemLayout,
) -> Result<Preview, PreviewError> {
    if choices.is_empty() {
        return Err(PreviewError::Empty);
    }
    // Each item once; the same item with two different actions is a contradiction.
    let mut chosen: Vec<Choice> = Vec::new();
    for c in choices {
        let f = findings
            .get(c.index)
            .ok_or(PreviewError::Unknown(c.index))?;
        if f.tier == Tier::Red {
            return Err(PreviewError::RedTier(c.index));
        }
        match chosen.iter().find(|o| o.index == c.index) {
            Some(o) if o.action != c.action => return Err(PreviewError::ChosenTwice(c.index)),
            Some(_) => {}
            None => chosen.push(*c),
        }
    }
    if chosen.iter().any(|c| c.action == Action::Move) && move_to.is_none() {
        return Err(PreviewError::NoDestination);
    }

    // Items that can't be acted on stay out, with the reason.
    let mut left_out: Vec<(usize, NotOffered)> = Vec::new();
    for c in &chosen {
        let f = &findings[c.index];
        let why = not_offered(f, layout).or_else(|| {
            (c.action == Action::Move
                && move_to.is_some_and(|d| d.drive().eq_ignore_ascii_case(&f.path.drive())))
            .then_some(NotOffered::SameDriveMove)
        });
        if let Some(why) = why {
            left_out.push((c.index, why));
        }
    }
    chosen.retain(|c| !left_out.iter().any(|(i, _)| *i == c.index));

    // A duplicate stays when its kept copy (or a folder holding it) is chosen too, whatever
    // the action, so one copy is always left.
    let paths_chosen: Vec<&WinPath> = chosen.iter().map(|c| &findings[c.index].path).collect();
    let last_copies: Vec<usize> = chosen
        .iter()
        .filter(|c| {
            findings[c.index].duplicate_of.as_ref().is_some_and(|kept| {
                paths_chosen
                    .iter()
                    .any(|p| kept.is_at_or_inside_ignore_case(p))
            })
        })
        .map(|c| c.index)
        .collect();
    for i in &last_copies {
        left_out.push((*i, NotOffered::LastCopy));
    }
    chosen.retain(|c| !last_copies.contains(&c.index));

    // An item inside another chosen item must share its action, or one would undo the other.
    for inner in &chosen {
        for outer in &chosen {
            let (fi, fo) = (&findings[inner.index], &findings[outer.index]);
            if inner.index != outer.index
                && inner.action != outer.action
                && fi.path.is_at_or_inside_ignore_case(&fo.path)
            {
                return Err(PreviewError::Conflict {
                    inner: inner.index,
                    outer: outer.index,
                });
            }
        }
    }

    let mut out = Preview {
        left_out,
        move_to: move_to.cloned(),
        ..Preview::default()
    };
    for action in Action::ALL {
        let items: Vec<usize> = chosen
            .iter()
            .filter(|c| c.action == action)
            .map(|c| c.index)
            .collect();
        if items.is_empty() {
            continue;
        }
        let plan = plan_clean(findings, &items).map_err(PreviewError::Select)?;
        let (freed_now, freed_after_emptying_bin) = match action {
            Action::Delete | Action::Move => (plan.bytes, 0),
            Action::Recycle => (0, plan.bytes),
        };
        out.actions.push(ActionPlan {
            action,
            items,
            plan,
            freed_now,
            freed_after_emptying_bin,
        });
    }
    out.confirm_green = chosen.iter().any(|c| findings[c.index].tier == Tier::Green);
    out.confirm_amber = chosen
        .iter()
        .filter(|c| findings[c.index].tier == Tier::Amber)
        .map(|c| c.index)
        .collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RULES;
    use std::time::UNIX_EPOCH;

    fn p(s: &str) -> WinPath {
        WinPath::parse(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }

    fn layout() -> SystemLayout {
        SystemLayout {
            system_root: p("C:\\Windows"),
            program_files: vec![p("C:\\Program Files"), p("C:\\Program Files (x86)")],
            program_data: p("C:\\ProgramData"),
            profiles_dir: p("C:\\Users"),
            profile_roots: vec![p("C:\\Users\\Ann")],
            extra_denied: Vec::new(),
        }
    }

    fn f(rule: &str, root: &str, name: &str, bytes: u64) -> Finding {
        let rule = RULES
            .iter()
            .find(|r| r.id == rule)
            .unwrap_or_else(|| unreachable!("{rule}"));
        Finding {
            rule,
            tier: rule.tier,
            root: p(root),
            path: p(&format!("{root}\\{name}")),
            is_folder: false,
            bytes,
            files: 1,
            newest: UNIX_EPOCH,
            cloud: false,
            pre_ticked: rule.pre_ticked(),
            duplicate_of: None,
            identity: None,
        }
    }

    const TEMP: &str = "C:\\Users\\Ann\\AppData\\Local\\Temp";
    const DL: &str = "C:\\Users\\Ann\\Downloads";

    /// 0 green temp (C:), 1 amber installer (C:), 2 amber large file on D:, 3 green folder in
    /// temp, 4 large file inside that folder, 5 cloud file, 6 F5 (rule folder is the profile),
    /// 7 duplicate whose kept copy is 1, 8 red.
    fn findings() -> Vec<Finding> {
        let mut v = vec![
            f("user-temp", TEMP, "a.tmp", 10),
            f("old-installers", DL, "setup.exe", 100),
            f("large-files", "D:\\Media", "film.mkv", 1000),
            f("user-temp", TEMP, "extract", 50),
            f("large-files", &format!("{TEMP}\\extract"), "x.iso", 40),
            f("large-files", "C:\\Users\\Ann\\OneDrive", "big.zip", 500),
            f("large-files", "C:\\Users\\Ann", "loose.vhdx", 700),
            f("duplicates", "C:\\Users\\Ann\\Documents", "setup.exe", 100),
            f("recycle-bin", "C:\\$Recycle.Bin", "x", 1),
        ];
        v[3].is_folder = true;
        v[5].cloud = true;
        v[7].duplicate_of = Some(p(&format!("{DL}\\setup.exe")));
        v[8].tier = Tier::Red;
        v
    }

    fn ch(index: usize, action: Action) -> Choice {
        Choice { index, action }
    }

    fn run(choices: &[Choice], move_to: Option<&str>) -> Result<Preview, PreviewError> {
        let dest = move_to.map(p);
        preview(&findings(), choices, dest.as_ref(), &layout())
    }

    #[test]
    fn freed_space_per_action_and_drive() {
        use Action::*;
        // (choices, move destination, freed now, freed after emptying the bin)
        let table: &[(&[Choice], Option<&str>, u64, u64)] = &[
            (&[ch(0, Delete)], None, 10, 0),
            (&[ch(0, Recycle)], None, 0, 10),
            (&[ch(1, Recycle)], None, 0, 100),
            (&[ch(1, Delete)], None, 100, 0),
            (&[ch(1, Move)], Some("D:\\Keep"), 100, 0),
            (&[ch(2, Move)], Some("E:\\Keep"), 1000, 0),
            (&[ch(2, Recycle)], None, 0, 1000),
            (
                &[ch(0, Delete), ch(1, Recycle), ch(2, Move)],
                Some("E:\\K"),
                1010,
                100,
            ),
            // The inner large file is covered (and counted) by its folder.
            (&[ch(3, Delete), ch(4, Delete)], None, 50, 0),
        ];
        for (choices, dest, now, later) in table {
            let pv = run(choices, *dest).unwrap_or_else(|e| unreachable!("{choices:?}: {e}"));
            assert_eq!(pv.freed_now(), *now, "{choices:?}");
            let after: u64 = pv.actions.iter().map(|a| a.freed_after_emptying_bin).sum();
            assert_eq!(after, *later, "{choices:?}");
            assert!(pv.left_out.is_empty(), "{choices:?}");
        }
    }

    #[test]
    fn green_needs_one_confirm_and_amber_lists_every_item() {
        use Action::*;
        let pv = run(&[ch(0, Delete), ch(3, Delete)], None).unwrap_or_default();
        assert!(pv.confirm_green);
        assert!(pv.confirm_amber.is_empty());
        let pv = run(&[ch(1, Recycle), ch(2, Recycle)], None).unwrap_or_default();
        assert!(!pv.confirm_green);
        assert_eq!(pv.confirm_amber, vec![1, 2]);
        let pv = run(&[ch(0, Delete), ch(2, Recycle)], None).unwrap_or_default();
        assert!(pv.confirm_green);
        assert_eq!(pv.confirm_amber, vec![2]);
    }

    #[test]
    fn items_that_cant_be_cleaned_are_left_out_with_the_reason() {
        use Action::*;
        let pv = run(&[ch(0, Delete), ch(5, Delete), ch(6, Recycle)], None).unwrap_or_default();
        assert_eq!(
            pv.left_out,
            vec![(5, NotOffered::CloudFile), (6, NotOffered::CantCleanHere)]
        );
        assert_eq!(pv.actions.len(), 1);
        assert_eq!(pv.actions[0].items, vec![0]);
        // Only left-out items: a preview that acts on nothing.
        let pv = run(&[ch(5, Delete)], None).unwrap_or_default();
        assert!(pv.is_empty());
        // A move to the drive the item is already on.
        let pv = run(&[ch(2, Move), ch(1, Move)], Some("D:\\Keep")).unwrap_or_default();
        assert_eq!(pv.left_out, vec![(2, NotOffered::SameDriveMove)]);
        assert_eq!(pv.actions[0].items, vec![1]);
    }

    #[test]
    fn a_duplicate_stays_when_its_kept_copy_is_chosen_whatever_the_actions() {
        use Action::*;
        for (a, b) in [(Delete, Delete), (Delete, Recycle), (Recycle, Move)] {
            let pv = run(&[ch(1, a), ch(7, b)], Some("D:\\K")).unwrap_or_default();
            assert_eq!(pv.left_out, vec![(7, NotOffered::LastCopy)], "{a:?} {b:?}");
            let acted: Vec<usize> = pv.actions.iter().flat_map(|x| x.items.clone()).collect();
            assert_eq!(acted, vec![1]);
        }
        // The duplicate alone is fine.
        let pv = run(&[ch(7, Delete)], None).unwrap_or_default();
        assert!(pv.left_out.is_empty());
    }

    #[test]
    fn bad_requests_refuse_the_whole_preview() {
        use Action::*;
        assert_eq!(run(&[], None), Err(PreviewError::Empty));
        assert_eq!(run(&[ch(99, Delete)], None), Err(PreviewError::Unknown(99)));
        assert_eq!(
            run(&[ch(0, Delete), ch(8, Delete)], None),
            Err(PreviewError::RedTier(8))
        );
        assert_eq!(
            run(&[ch(0, Delete), ch(0, Recycle)], None),
            Err(PreviewError::ChosenTwice(0))
        );
        assert_eq!(run(&[ch(1, Move)], None), Err(PreviewError::NoDestination));
        assert_eq!(
            run(&[ch(3, Delete), ch(4, Move)], Some("D:\\K")),
            Err(PreviewError::Conflict { inner: 4, outer: 3 })
        );
        // The same choice twice is fine (counted once).
        let pv = run(&[ch(0, Delete), ch(0, Delete)], None).unwrap_or_default();
        assert_eq!(pv.freed_now(), 10);
    }

    #[test]
    fn every_action_tier_and_drive_case_is_decided() {
        // Exhaustive over action x tier x (same drive / other drive) for one item: either a
        // preview with the expected freed bytes, or a clear refusal, never anything else.
        let base = findings();
        for action in Action::ALL {
            for tier in [Tier::Green, Tier::Amber, Tier::Red] {
                for dest in ["C:\\K", "D:\\K"] {
                    let mut v = base.clone();
                    v[0].tier = tier;
                    let r = preview(&v, &[ch(0, action)], Some(&p(dest)), &layout());
                    match (tier, action, dest) {
                        (Tier::Red, ..) => assert_eq!(r, Err(PreviewError::RedTier(0))),
                        (_, Action::Move, "C:\\K") => {
                            let pv = r.unwrap_or_default();
                            assert_eq!(pv.left_out, vec![(0, NotOffered::SameDriveMove)]);
                            assert!(pv.is_empty());
                        }
                        (_, Action::Recycle, _) => {
                            assert_eq!(r.map(|pv| pv.freed_now()), Ok(0));
                        }
                        _ => assert_eq!(r.map(|pv| pv.freed_now()), Ok(10)),
                    }
                }
            }
        }
    }

    #[test]
    fn vm_disks_get_their_label_and_f5_items_are_not_offered() {
        let v = findings();
        assert_eq!(note(&v[6]), Some(Note::VmDisk));
        assert_eq!(note(&v[2]), None);
        for ext in VM_DISK_EXTENSIONS {
            let mut x = v[2].clone();
            x.path = p(&format!("D:\\Media\\disk.{}", ext.to_uppercase()));
            assert_eq!(note(&x), Some(Note::VmDisk), "{ext}");
        }
        assert_eq!(
            not_offered(&v[6], &layout()),
            Some(NotOffered::CantCleanHere)
        );
        assert_eq!(not_offered(&v[5], &layout()), Some(NotOffered::CloudFile));
        // A file directly at a drive root's rule folder (like D:\Video.vkl).
        let mut d = v[2].clone();
        d.root = p("D:\\");
        d.path = p("D:\\Video.vkl");
        assert_eq!(not_offered(&d, &layout()), Some(NotOffered::CantCleanHere));
        assert_eq!(not_offered(&v[0], &layout()), None);
    }
}
