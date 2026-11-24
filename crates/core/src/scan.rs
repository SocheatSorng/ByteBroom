//! From rules to findings: walk each rule's folders and say what could be cleaned.
//!
//! Only reads. A finding is one item **directly inside** a rule's folder (`root`): a file, or a
//! folder with everything in it. That item is exactly what a clean would act on, inside a root the
//! rule owns, and the phase 1 engine checks it again at the moment of action.
//!
//! Every folder a rule names is opened without following it and must be a real folder at exactly
//! the expected place; a link anywhere on the way means the folder is not scanned. The walker
//! already refuses links, "never listed" names and the hard floor below each root.
//!
//! Large files and duplicates share one search walk of the profile and the other drives.
//! Duplicates are hashed only after their sizes match, never for cloud placeholders (reading one
//! would download it), and never in AppData, `.git` or build folders, which are full of identical
//! files their apps need. The red tier (task 6) is not produced here yet.

use crate::duplicates::{Candidate, find_duplicates};
use crate::locations::Locations;
use crate::paths::WinPath;
use crate::policy::{SystemLayout, denied_reason};
use crate::rules::{
    BUILD_FOLDER_NAMES, Base, DUPLICATE_HEAD_BYTES, DUPLICATE_MIN_BYTES, Find, LARGE_FILE_BYTES,
    Look, OLD_INSTALLER_DAYS, Place, RULES, Rule, Tier, base_folder, name_matches,
};
use crate::walk::{Item, Step, WalkOptions, WalkSummary};
use crate::win::hash::Sha256;
use crate::win::walk::walk;
use crate::win::{Access, open_no_follow};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Settings for one scan.
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions<'a> {
    /// The time ages are measured from (a parameter, so tests can move it).
    pub now: SystemTime,
    /// When set to `true`, the scan stops as soon as it can.
    pub cancel: Option<&'a AtomicBool>,
}

/// One thing that could be cleaned.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The rule that found it.
    pub rule: &'static Rule,
    /// Its tier (the rule's).
    pub tier: Tier,
    /// The rule's folder it sits directly inside: the root a clean of it would use.
    pub root: WinPath,
    /// The file or folder itself.
    pub path: WinPath,
    /// A folder (its sizes cover everything inside it).
    pub is_folder: bool,
    /// Bytes of its files, each hard-linked file once.
    pub bytes: u64,
    /// Number of files.
    pub files: u64,
    /// The newest change date among its files (a folder with no files: its own date).
    pub newest: SystemTime,
    /// Some of it is a cloud placeholder whose bytes may not be on this disk.
    pub cloud: bool,
    /// Ticked when shown (green only).
    pub pre_ticked: bool,
    /// For a duplicate: the copy that is kept.
    pub duplicate_of: Option<WinPath>,
}

/// The result of a scan.
#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    /// What could be cleaned, in rule order.
    pub findings: Vec<Finding>,
    /// Totals of every walk (counts only, never names).
    pub walked: WalkSummary,
    /// The scan stopped early.
    pub cancelled: bool,
}

/// Sizes added up for one item.
#[derive(Debug, Clone, Copy)]
struct Tally {
    is_folder: bool,
    bytes: u64,
    files: u64,
    newest_file: Option<SystemTime>,
    own_date: SystemTime,
    cloud: bool,
}

impl Tally {
    fn new(is_folder: bool, own_date: SystemTime) -> Self {
        Self {
            is_folder,
            bytes: 0,
            files: 0,
            newest_file: None,
            own_date,
            cloud: false,
        }
    }

    fn add_file(&mut self, len: u64, modified: SystemTime, repeat: bool, cloud: bool) {
        self.files += 1;
        if !repeat {
            self.bytes += len;
        }
        self.cloud |= cloud;
        self.newest_file = Some(self.newest_file.map_or(modified, |n| n.max(modified)));
    }

    fn newest(&self) -> SystemTime {
        self.newest_file.unwrap_or(self.own_date)
    }
}

fn add_summary(total: &mut WalkSummary, s: &WalkSummary) {
    total.files += s.files;
    total.folders += s.folders;
    total.bytes += s.bytes;
    total.hard_link_repeats += s.hard_link_repeats;
    total.unreadable += s.unreadable;
    total.links_skipped += s.links_skipped;
    total.protected_skipped += s.protected_skipped;
    total.odd_names += s.odd_names;
    total.depth_limited += s.depth_limited;
    total.changed += s.changed;
    total.cancelled |= s.cancelled;
}

struct Scanner<'a> {
    at: &'a Locations,
    layout: &'a SystemLayout,
    opts: WalkOptions<'a>,
    now: SystemTime,
    report: ScanReport,
    /// Files from the shared large-file and duplicate search, once it has run.
    search: Option<Vec<SearchFile>>,
}

/// A file the large-file and duplicate search kept.
#[derive(Debug, Clone)]
struct SearchFile {
    path: WinPath,
    len: u64,
    modified: SystemTime,
    cloud: bool,
    /// It may be hashed and offered as a duplicate.
    duplicate_candidate: bool,
}

impl Scanner<'_> {
    fn stopped(&self) -> bool {
        self.report.cancelled || self.opts.cancelled()
    }

    /// Walk `root`, adding to the totals. Errors (the root vanished, access denied) count as
    /// one unreadable folder.
    fn walk(&mut self, root: &WinPath, max_depth: Option<usize>, visit: impl FnMut(&Item) -> Step) {
        let mut opts = self.opts;
        if let Some(d) = max_depth {
            opts.max_depth = d;
        }
        match walk(root, self.layout, &opts, visit) {
            Ok(s) => {
                self.report.cancelled |= s.cancelled;
                add_summary(&mut self.report.walked, &s);
            }
            Err(_) => self.report.walked.unreadable += 1,
        }
    }

    /// `path` as Windows spells it, if it is a real folder at exactly that place and off the
    /// hard floor. Anything else (missing, a link here or on the way, a file) gives `None`.
    fn real_folder(&self, path: &WinPath) -> Option<WinPath> {
        let o = open_no_follow(path, Access::Inspect).ok()?;
        let ok = !o.resolved.is_reparse_point
            && o.is_directory
            && o.resolved.final_path.eq_ignore_case(path)
            && denied_reason(&o.resolved.final_path, self.layout).is_none();
        ok.then_some(o.resolved.final_path)
    }

    /// The real folders a place stands for, with each `*` filled by every real subfolder.
    fn expand(&mut self, place: &Place) -> Vec<WinPath> {
        let Some(base) = base_folder(place.base, self.at).cloned() else {
            return Vec::new();
        };
        let mut current = vec![base];
        for part in place.parts() {
            let mut next = Vec::new();
            for dir in current {
                if part == "*" {
                    if let Some(dir) = self.real_folder(&dir) {
                        let mut subs = Vec::new();
                        self.walk(&dir, Some(1), |item| {
                            if let Item::Folder { path, .. } = item {
                                subs.push((*path).clone());
                            }
                            Step::Skip
                        });
                        next.extend(subs);
                    }
                } else if let Ok(child) = dir.join(part) {
                    next.push(child);
                }
            }
            current = next;
        }
        current.iter().filter_map(|p| self.real_folder(p)).collect()
    }

    /// One tally per item directly inside `root`, covering everything below it.
    fn tally_children(&mut self, root: &WinPath) -> BTreeMap<String, Tally> {
        let depth_of_children = root.parts().len();
        let mut items: BTreeMap<String, Tally> = BTreeMap::new();
        self.walk(root, None, |item| {
            match item {
                Item::Folder {
                    path,
                    depth,
                    modified,
                } => {
                    if *depth == 1
                        && let Some(name) = path.parts().get(depth_of_children)
                    {
                        items
                            .entry(name.clone())
                            .or_insert_with(|| Tally::new(true, *modified));
                    }
                }
                Item::File(f) => {
                    if let Some(name) = f.path.parts().get(depth_of_children) {
                        items
                            .entry(name.clone())
                            .or_insert_with(|| Tally::new(f.depth > 1, f.modified))
                            .add_file(f.len, f.modified, f.repeat, f.cloud);
                    }
                }
            }
            Step::Enter
        });
        items
    }

    /// Sizes of everything inside the folder `path`.
    fn tally_folder(&mut self, path: &WinPath, own_date: SystemTime) -> Tally {
        let mut t = Tally::new(true, own_date);
        self.walk(path, None, |item| {
            if let Item::File(f) = item {
                t.add_file(f.len, f.modified, f.repeat, f.cloud);
            }
            Step::Enter
        });
        t
    }

    fn push(&mut self, rule: &'static Rule, root: &WinPath, path: WinPath, t: &Tally) {
        if rule.fresh_hours > 0 {
            let cut = self
                .now
                .checked_sub(Duration::from_secs(rule.fresh_hours * 3600))
                .unwrap_or(UNIX_EPOCH);
            if t.newest() > cut {
                return;
            }
        }
        self.report.findings.push(Finding {
            rule,
            tier: rule.tier,
            root: root.clone(),
            path,
            is_folder: t.is_folder,
            bytes: t.bytes,
            files: t.files,
            newest: t.newest(),
            cloud: t.cloud,
            pre_ticked: rule.pre_ticked(),
            duplicate_of: None,
        });
    }

    fn contents(&mut self, rule: &'static Rule, places: &[Place]) {
        for place in places {
            for root in self.expand(place) {
                if self.stopped() {
                    return;
                }
                for (name, t) in self.tally_children(&root) {
                    if let Ok(path) = root.join(&name) {
                        self.push(rule, &root, path, &t);
                    }
                }
            }
        }
    }

    fn files(&mut self, rule: &'static Rule, places: &[Place], names: &[&str]) {
        for place in places {
            for root in self.expand(place) {
                let mut hits = Vec::new();
                self.walk(&root, Some(1), |item| {
                    if let Item::File(f) = item
                        && let Some(name) = f.path.parts().last()
                        && names.iter().any(|p| name_matches(p, name))
                    {
                        let mut t = Tally::new(false, f.modified);
                        t.add_file(f.len, f.modified, f.repeat, f.cloud);
                        hits.push((f.path.clone(), t));
                    }
                    Step::Skip
                });
                for (path, t) in hits {
                    self.push(rule, &root, path, &t);
                }
            }
        }
    }

    /// The trusted roots for the search areas: each once, and none inside another (Downloads
    /// is usually inside the profile), so no file is reported twice.
    fn area_roots(&self, areas: &[Base]) -> Vec<WinPath> {
        let mut roots: Vec<WinPath> = Vec::new();
        for area in areas {
            let found: Vec<WinPath> = match area {
                Base::OtherDrives => self.at.other_drives.clone(),
                b => base_folder(*b, self.at).cloned().into_iter().collect(),
            };
            for r in found {
                if !roots.iter().any(|q| r.is_at_or_inside_ignore_case(q)) {
                    roots.retain(|q| !q.is_at_or_inside_ignore_case(&r));
                    roots.push(r);
                }
            }
        }
        roots
    }

    fn old_installers(&mut self, rule: &'static Rule, areas: &[Base], exts: &[&str]) {
        let cut = self
            .now
            .checked_sub(Duration::from_secs(OLD_INSTALLER_DAYS * 24 * 3600))
            .unwrap_or(UNIX_EPOCH);
        for area in self.area_roots(areas) {
            let Some(root) = self.real_folder(&area) else {
                continue;
            };
            let mut hits = Vec::new();
            self.walk(&root, None, |item| {
                if let Item::File(f) = item
                    && f.modified <= cut
                    && f.path.parts().last().is_some_and(|n| {
                        n.rsplit_once('.')
                            .is_some_and(|(_, e)| exts.iter().any(|x| x.eq_ignore_ascii_case(e)))
                    })
                {
                    let mut t = Tally::new(false, f.modified);
                    t.add_file(f.len, f.modified, f.repeat, f.cloud);
                    hits.push((f.path.clone(), t));
                }
                Step::Enter
            });
            // Each installer is its own item, so the clean's root is the folder it sits in.
            for (path, t) in hits {
                if let Some(folder) = parent(&path) {
                    self.push(rule, &folder, path, &t);
                }
            }
        }
    }

    fn build_folders(&mut self, rule: &'static Rule, areas: &[Base], names: &[&str]) {
        for area in self.area_roots(areas) {
            if area.is_drive_root() {
                // A drive root is never "a real folder" for the floor check, but it is a fine
                // place to start a read-only search.
            } else if self.real_folder(&area).is_none() {
                continue;
            }
            let mut hits = Vec::new();
            let layout = self.layout;
            self.walk(&area, None, |item| {
                let Item::Folder { path, modified, .. } = item else {
                    return Step::Enter;
                };
                let Some(name) = path.parts().last() else {
                    return Step::Enter;
                };
                if name.eq_ignore_ascii_case(".git") {
                    return Step::Skip; // nothing to find inside, and often large
                }
                if names.iter().any(|n| n.eq_ignore_ascii_case(name))
                    && let Some(project) = parent(path)
                    && has_git(&project, layout)
                {
                    hits.push(((*path).clone(), project, *modified));
                    return Step::Skip;
                }
                Step::Enter
            });
            for (path, project, modified) in hits {
                if self.stopped() {
                    return;
                }
                let t = self.tally_folder(&path, modified);
                self.push(rule, &project, path, &t);
            }
        }
    }

    /// One walk for large files and duplicates (both rules search the same areas). Keeps only
    /// files either rule can use; hard-link repeats are left out, so one file is one item.
    fn search_files(&mut self, areas: &[Base]) -> Vec<SearchFile> {
        if let Some(found) = &self.search {
            return found.clone();
        }
        let mut found = Vec::new();
        let app_data = self
            .at
            .profile
            .as_ref()
            .and_then(|p| p.join("AppData").ok());
        for area in self.area_roots(areas) {
            if !area.is_drive_root() && self.real_folder(&area).is_none() {
                continue;
            }
            self.walk(&area, None, |item| {
                let Item::File(f) = item else {
                    return Step::Enter;
                };
                let large = f.len >= LARGE_FILE_BYTES;
                let duplicate_candidate = f.len >= DUPLICATE_MIN_BYTES
                    && !f.cloud
                    && !app_data
                        .as_ref()
                        .is_some_and(|a| f.path.is_at_or_inside_ignore_case(a))
                    && !in_build_or_git_folder(&f.path);
                if !f.repeat && (large || duplicate_candidate) {
                    found.push(SearchFile {
                        path: f.path.clone(),
                        len: f.len,
                        modified: f.modified,
                        cloud: f.cloud,
                        duplicate_candidate,
                    });
                }
                Step::Enter
            });
        }
        self.search = Some(found.clone());
        found
    }

    fn single_file(&mut self, rule: &'static Rule, path: &WinPath, t: &Tally) -> bool {
        match parent(path) {
            Some(folder) => {
                self.push(rule, &folder, path.clone(), t);
                true
            }
            None => false,
        }
    }

    fn large_files(&mut self, rule: &'static Rule, areas: &[Base]) {
        for f in self.search_files(areas) {
            if f.len >= LARGE_FILE_BYTES {
                let mut t = Tally::new(false, f.modified);
                t.add_file(f.len, f.modified, false, f.cloud);
                self.single_file(rule, &f.path, &t);
            }
        }
    }

    fn duplicates(&mut self, rule: &'static Rule, areas: &[Base]) {
        let candidates: Vec<Candidate> = self
            .search_files(areas)
            .into_iter()
            .filter(|f| f.duplicate_candidate)
            .map(|f| Candidate {
                path: f.path,
                len: f.len,
                modified: f.modified,
            })
            .collect();
        let opts = self.opts;
        let extras = find_duplicates(
            candidates,
            |c| {
                (!opts.cancelled())
                    .then(|| hash_file(c, Some(DUPLICATE_HEAD_BYTES)))
                    .flatten()
            },
            |c| (!opts.cancelled()).then(|| hash_file(c, None)).flatten(),
        );
        if opts.cancelled() {
            self.report.cancelled = true;
            return;
        }
        for e in extras {
            let mut t = Tally::new(false, e.copy.modified);
            t.add_file(e.copy.len, e.copy.modified, false, false);
            if self.single_file(rule, &e.copy.path, &t)
                && let Some(last) = self.report.findings.last_mut()
            {
                last.duplicate_of = Some(e.kept);
            }
        }
    }

    fn run(&mut self, rule: &'static Rule) {
        match rule.look {
            Look::Contents(places) => self.contents(rule, places),
            Look::Files { places, names } => self.files(rule, places, names),
            Look::Search {
                areas,
                find: Find::OldInstallers(exts),
            } => self.old_installers(rule, areas, exts),
            Look::Search {
                areas,
                find: Find::BuildFolders(names),
            } => self.build_folders(rule, areas, names),
            Look::Search {
                areas,
                find: Find::LargeFiles,
            } => self.large_files(rule, areas),
            Look::Search {
                areas,
                find: Find::Duplicates,
            } => self.duplicates(rule, areas),
            // Task 6.
            Look::SizeOnly(_) => {}
        }
    }
}

/// The folder that holds `path` (`None` for a drive root).
fn parent(path: &WinPath) -> Option<WinPath> {
    let (_, up) = path.parts().split_last()?;
    up.iter()
        .try_fold(WinPath::drive_root(path.drive()), |p, part| {
            p.join(part).ok()
        })
}

/// Below a `.git` folder or a build-output folder (by name), where identical files are normal.
fn in_build_or_git_folder(path: &WinPath) -> bool {
    let parts = path.parts();
    parts[..parts.len().saturating_sub(1)].iter().any(|p| {
        p.eq_ignore_ascii_case(".git")
            || BUILD_FOLDER_NAMES.iter().any(|n| p.eq_ignore_ascii_case(n))
    })
}

/// SHA-256 (Windows CNG) of a file's first `limit` bytes, or of all of it. The file is opened
/// without following it and read through that handle; it must still be a plain file of the
/// length the walk saw, at the same place. Anything else (locked, denied, changed) gives `None`.
fn hash_file(c: &Candidate, limit: Option<usize>) -> Option<String> {
    let opened = open_no_follow(&c.path, Access::Read).ok()?;
    if opened.resolved.is_reparse_point
        || opened.is_directory
        || opened.size != c.len
        || !opened.resolved.final_path.eq_ignore_case(&c.path)
    {
        return None;
    }
    let mut reader = opened.reader().ok()?;
    let mut sha = Sha256::new()?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut left = limit.unwrap_or(usize::MAX);
    while left > 0 {
        let want = buf.len().min(left);
        let n = reader.read(&mut buf[..want]).ok()?;
        if n == 0 {
            break;
        }
        if !sha.update(&buf[..n]) {
            return None;
        }
        left -= n;
    }
    sha.finish_hex()
}

/// `project` holds a real `.git` (a folder, or the file a worktree or submodule uses).
fn has_git(project: &WinPath, layout: &SystemLayout) -> bool {
    project.join(".git").is_ok_and(|git| {
        denied_reason(&git, layout).is_none()
            && open_no_follow(&git, Access::Inspect).is_ok_and(|o| !o.resolved.is_reparse_point)
    })
}

/// Scan the green and amber rules in `at`. Only reads.
pub fn scan(at: &Locations, layout: &SystemLayout, opts: &ScanOptions) -> ScanReport {
    let mut s = Scanner {
        at,
        layout,
        opts: WalkOptions {
            cancel: opts.cancel,
            ..WalkOptions::default()
        },
        now: opts.now,
        report: ScanReport::default(),
        search: None,
    };
    for rule in RULES.iter() {
        if s.stopped() {
            s.report.cancelled = true;
            break;
        }
        s.run(rule);
    }
    if s.stopped() {
        s.report.cancelled = true;
    }
    s.report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> WinPath {
        WinPath::parse(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }

    #[test]
    fn parent_walks_one_level_up() {
        assert_eq!(parent(&p("C:\\a\\b")), Some(p("C:\\a")));
        assert_eq!(parent(&p("C:\\a")), Some(p("C:\\")));
        assert_eq!(parent(&p("C:\\")), None);
    }

    #[test]
    fn a_tally_counts_hard_links_once_and_keeps_the_newest_file_date() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1000);
        let mut t = Tally::new(true, t0);
        assert_eq!(t.newest(), t0);
        t.add_file(10, UNIX_EPOCH + Duration::from_secs(5), false, false);
        t.add_file(10, UNIX_EPOCH + Duration::from_secs(9), true, true);
        assert_eq!((t.bytes, t.files, t.cloud), (10, 2, true));
        // The folder's own (later) date does not count once it holds files.
        assert_eq!(t.newest(), UNIX_EPOCH + Duration::from_secs(9));
    }
}
