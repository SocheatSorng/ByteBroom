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
//! Large files and duplicates share one search walk of the profile and the other drives. It never
//! enters an `AppData` folder (app disk images and databases live there), and never offers a cloud
//! placeholder. Duplicates are hashed only after their sizes match, never for cloud placeholders
//! (reading one would download it), and never in `.git` or build folders, which are full of
//! identical files their apps need. The red tier is measured separately (`win::red`).

use crate::duplicates::{Candidate, find_duplicates};
use crate::locations::Locations;
use crate::paths::WinPath;
use crate::policy::{SystemLayout, denied_reason};
use crate::rules::{
    BUILD_FOLDER_NAMES, BUILD_FOLDERS, Base, DUPLICATE_HEAD_BYTES, DUPLICATE_MIN_BYTES, Find,
    LARGE_FILE_BYTES, Look, OLD_INSTALLER_DAYS, Place, RULES, Rule, Tier, base_folder,
    name_matches,
};
use crate::walk::{FileEntry, FileId, Item, Step, WalkOptions, WalkSummary};
use crate::win::hash::Sha256;
use crate::win::walk::walk;
use crate::win::{Access, open_no_follow};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// For a single file: which file the scan saw (security review F1). A clean checks it is
    /// still the same file, unchanged, right before acting. `None` for folders, and on file
    /// systems without file IDs.
    pub identity: Option<FileIdentity>,
}

/// A file as the scan saw it: its Windows file number, length and last change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// Windows' number for the file.
    pub id: FileId,
    /// Its length in bytes.
    pub len: u64,
    /// When its contents last changed.
    pub modified: SystemTime,
}

/// The result of a scan.
#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    /// What could be cleaned, in rule order, except that duplicates come last (see
    /// [`scan_in_steps`]).
    pub findings: Vec<Finding>,
    /// Totals of every walk (counts only, never names).
    pub walked: WalkSummary,
    /// The scan stopped early.
    pub cancelled: bool,
    /// How long each step took, in order (for the owner and for speed work; no names).
    pub steps: Vec<StepTime>,
}

/// How long one step of a scan took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepTime {
    /// The step: a rule's label, or the shared search walk.
    pub step: &'static str,
    /// Its wall-clock time.
    pub took: Duration,
}

/// The name of the shared walk in [`ScanReport::steps`].
pub const SEARCH_WALK_STEP: &str = "Search walk (large files, duplicates, build folders)";

/// Sizes added up for one item.
#[derive(Debug, Clone, Copy)]
struct Tally {
    is_folder: bool,
    bytes: u64,
    files: u64,
    newest_file: Option<SystemTime>,
    own_date: SystemTime,
    cloud: bool,
    /// The latest creation, write or change time of anything in it, folders included: what the
    /// "fresh" rule (decision 4) looks at.
    activity: Option<SystemTime>,
    /// Part of it was not seen (unreadable, changed during the scan, too deep), so its activity
    /// is unknown.
    incomplete: bool,
    /// For a single file, which file it is.
    identity: Option<FileIdentity>,
}

impl Tally {
    fn new(is_folder: bool, own_date: SystemTime) -> Self {
        Self {
            identity: None,
            is_folder,
            bytes: 0,
            files: 0,
            newest_file: None,
            own_date,
            cloud: false,
            activity: None,
            incomplete: false,
        }
    }

    fn touch(&mut self, when: SystemTime) {
        self.activity = Some(self.activity.map_or(when, |a| a.max(when)));
    }

    /// Changed within `hours` of `now`, or not fully seen: either way, not offered by a rule
    /// that keeps fresh items.
    fn too_fresh(&self, now: SystemTime, hours: u64) -> bool {
        let cut = now
            .checked_sub(Duration::from_secs(hours * 3600))
            .unwrap_or(UNIX_EPOCH);
        self.incomplete || self.newest() > cut || self.activity.is_some_and(|a| a > cut)
    }

    fn add_file(&mut self, len: u64, modified: SystemTime, repeat: bool, cloud: bool) {
        self.files += 1;
        if !repeat {
            self.bytes += len;
        }
        self.cloud |= cloud;
        self.newest_file = Some(self.newest_file.map_or(modified, |n| n.max(modified)));
    }

    /// A tally for one file the walk found, with its identity.
    fn of_file(f: &FileEntry) -> Self {
        let mut t = Self::new(false, f.modified);
        t.add_file(f.len, f.modified, f.repeat, f.cloud);
        t.identity = f.id.map(|id| FileIdentity {
            id,
            len: f.len,
            modified: f.modified,
        });
        t
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
    /// What the shared search walk found, once it has run.
    search: Option<Search>,
}

/// What the one walk of the search areas found, for the three rules that search.
#[derive(Debug, Clone, Default)]
struct Search {
    /// Files large enough for the large-file or duplicate rule.
    files: Vec<SearchFile>,
    /// Build folders beside their project: (the folder, its project, its own date).
    build_folders: Vec<(WinPath, WinPath, SystemTime)>,
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
    /// Windows' number for it.
    id: Option<FileId>,
}

impl SearchFile {
    fn tally(&self) -> Tally {
        let mut t = Tally::new(false, self.modified);
        t.add_file(self.len, self.modified, false, self.cloud);
        t.identity = self.id.map(|id| FileIdentity {
            id,
            len: self.len,
            modified: self.modified,
        });
        t
    }
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

    /// Where a read-only search may start: a drive root, or a real folder at exactly that place
    /// (not a link here or on the way). Unlike [`Self::real_folder`] this does not apply the hard
    /// floor to the area itself, because the profile root is on the floor as a delete *target*
    /// yet is exactly where searches start. Areas come from the trusted [`Locations`], findings
    /// inside get their own roots, and the walker still refuses the floor below the area.
    fn search_root(&self, area: &WinPath) -> Option<WinPath> {
        if area.is_drive_root() {
            return Some(area.clone());
        }
        let o = open_no_follow(area, Access::Inspect).ok()?;
        let ok = !o.resolved.is_reparse_point
            && o.is_directory
            && o.resolved.final_path.eq_ignore_case(area);
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
                    modified,
                    activity,
                    ..
                } => {
                    // Every folder, at any depth, counts toward its top item's activity.
                    if let Some(name) = path.parts().get(depth_of_children) {
                        items
                            .entry(name.clone())
                            .or_insert_with(|| Tally::new(true, *modified))
                            .touch(*activity);
                    }
                }
                Item::File(f) => {
                    if let Some(name) = f.path.parts().get(depth_of_children) {
                        if f.depth == 1 {
                            let mut t = Tally::of_file(f);
                            t.touch(f.activity);
                            items.insert(name.clone(), t);
                        } else {
                            let t = items
                                .entry(name.clone())
                                .or_insert_with(|| Tally::new(true, f.modified));
                            t.add_file(f.len, f.modified, f.repeat, f.cloud);
                            t.touch(f.activity);
                        }
                    }
                }
                Item::Incomplete { path, .. } => {
                    if let Some(name) = path.parts().get(depth_of_children) {
                        items
                            .entry(name.clone())
                            .or_insert_with(|| Tally::new(true, UNIX_EPOCH))
                            .incomplete = true;
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
        if rule.fresh_hours > 0 && t.too_fresh(self.now, rule.fresh_hours) {
            return;
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
            identity: if t.is_folder { None } else { t.identity },
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
                        hits.push((f.path.clone(), Tally::of_file(f)));
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
            let Some(root) = self.search_root(&area) else {
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
                    hits.push((f.path.clone(), Tally::of_file(f)));
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

    fn build_folders(&mut self, rule: &'static Rule) {
        for (path, project, modified) in self.search().build_folders {
            if self.stopped() {
                return;
            }
            let t = self.tally_folder(&path, modified);
            self.push(rule, &project, path, &t);
        }
    }

    /// The areas every search rule (other than old installers, which only look in Downloads)
    /// covers, so one walk serves them all.
    fn search_areas() -> Vec<Base> {
        let mut areas = Vec::new();
        for rule in RULES.iter() {
            if let Look::Search { areas: a, find } = rule.look
                && !matches!(find, Find::OldInstallers(_))
            {
                for base in a {
                    if !areas.contains(base) {
                        areas.push(*base);
                    }
                }
            }
        }
        areas
    }

    /// One walk of the search areas for large files, duplicates and build folders: walking big
    /// drives is mostly seek time, so walking them once instead of twice matters. Keeps only what
    /// those rules can use; hard-link repeats are left out, so one file is one item.
    ///
    /// The walk never enters `AppData` (app disk images and databases), `.git` (repository data,
    /// often large) or a build folder it has found (offered as one item; its contents would only
    /// repeat it).
    fn search(&mut self) -> Search {
        if let Some(found) = &self.search {
            return found.clone();
        }
        let started = Instant::now();
        let mut found = Search::default();
        let layout = self.layout;
        for area in self.area_roots(&Self::search_areas()) {
            let Some(area) = self.search_root(&area) else {
                continue;
            };
            let build_folders = &mut found.build_folders;
            let files = &mut found.files;
            self.walk(&area, None, |item| {
                let f = match item {
                    Item::Folder { path, modified, .. } => {
                        let Some(name) = path.parts().last() else {
                            return Step::Enter;
                        };
                        // App data (any profile's, on any drive) holds disk images and databases
                        // whose apps break without them (WSL's ext4.vhdx, Docker's data). Their
                        // caches are offered by the green and amber rules instead.
                        if name.eq_ignore_ascii_case("AppData") || name.eq_ignore_ascii_case(".git")
                        {
                            return Step::Skip;
                        }
                        if let Some(kind) = BUILD_FOLDERS
                            .iter()
                            .find(|k| k.name.eq_ignore_ascii_case(name))
                            && let Some(project) = parent(path)
                            && has_git(&project, layout)
                            && has_marker(&project, kind.markers)
                        {
                            build_folders.push(((*path).clone(), project, *modified));
                            return Step::Skip;
                        }
                        return Step::Enter;
                    }
                    Item::File(f) => f,
                    Item::Incomplete { .. } => return Step::Enter,
                };
                // A cloud placeholder's bytes may not be on this disk, and the engine never acts
                // on placeholders (they are reparse points): not offered as a large file.
                let large = f.len >= LARGE_FILE_BYTES && !f.cloud;
                let duplicate_candidate =
                    f.len >= DUPLICATE_MIN_BYTES && !f.cloud && !in_build_or_git_folder(&f.path);
                if !f.repeat && (large || duplicate_candidate) {
                    files.push(SearchFile {
                        path: f.path.clone(),
                        len: f.len,
                        modified: f.modified,
                        cloud: f.cloud,
                        duplicate_candidate,
                        id: f.id,
                    });
                }
                Step::Enter
            });
        }
        self.report.steps.push(StepTime {
            step: SEARCH_WALK_STEP,
            took: started.elapsed(),
        });
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

    fn large_files(&mut self, rule: &'static Rule) {
        for f in self.search().files {
            if f.len >= LARGE_FILE_BYTES {
                self.single_file(rule, &f.path, &f.tally());
            }
        }
    }

    fn duplicates(&mut self, rule: &'static Rule) {
        let search = self.search().files;
        let by_path: HashMap<&WinPath, &SearchFile> = search.iter().map(|f| (&f.path, f)).collect();
        let candidates: Vec<Candidate> = search
            .iter()
            .filter(|f| f.duplicate_candidate)
            .map(|f| Candidate {
                path: f.path.clone(),
                len: f.len,
                modified: f.modified,
            })
            .collect();
        let opts = self.opts;
        // Hash ahead, in parallel per drive: first the heads of files that share a size, then
        // the whole of files that share a size and a head. `find_duplicates` then groups exactly
        // as before, reading the hashes from these maps.
        let mut by_size: HashMap<u64, Vec<&Candidate>> = HashMap::new();
        for c in &candidates {
            by_size.entry(c.len).or_default().push(c);
        }
        let need_head: Vec<&Candidate> = by_size
            .into_values()
            .filter(|g| g.len() > 1)
            .flatten()
            .collect();
        let heads = hash_all(&need_head, Some(DUPLICATE_HEAD_BYTES), &opts);
        let mut by_head: HashMap<(u64, &String), Vec<&Candidate>> = HashMap::new();
        for c in &need_head {
            if let Some(h) = heads.get(&c.path) {
                by_head.entry((c.len, h)).or_default().push(c);
            }
        }
        let need_full: Vec<&Candidate> = by_head
            .into_values()
            .filter(|g| g.len() > 1)
            .flatten()
            .collect();
        let fulls = hash_all(&need_full, None, &opts);
        let extras = find_duplicates(
            candidates.clone(),
            |c| heads.get(&c.path).cloned(),
            |c| fulls.get(&c.path).cloned(),
        );
        if opts.cancelled() {
            self.report.cancelled = true;
            return;
        }
        for e in extras {
            let Some(found) = by_path.get(&e.copy.path) else {
                continue;
            };
            if self.single_file(rule, &e.copy.path, &found.tally())
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
            // These three share one walk of the same areas (see `search`).
            Look::Search {
                find: Find::BuildFolders(_),
                ..
            } => self.build_folders(rule),
            Look::Search {
                find: Find::LargeFiles,
                ..
            } => self.large_files(rule),
            Look::Search {
                find: Find::Duplicates,
                ..
            } => self.duplicates(rule),
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
    // Large reads: duplicate candidates are big files, often on spinning disks.
    let mut buf = vec![0u8; 1024 * 1024];
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

/// Hash each candidate (`limit` bytes from the start, or all of it), one thread per drive: drives
/// are separate disks, so reading them at the same time is close to free, while two readers on
/// one spinning disk would only fight over the head. A file that can't be hashed (locked, changed)
/// is left out. Stops early when the scan is cancelled.
fn hash_all(
    candidates: &[&Candidate],
    limit: Option<usize>,
    opts: &WalkOptions,
) -> HashMap<WinPath, String> {
    let mut by_drive: BTreeMap<char, Vec<&Candidate>> = BTreeMap::new();
    for c in candidates {
        by_drive.entry(c.path.drive()).or_default().push(c);
    }
    let cancel = opts.cancel;
    let cancelled = || cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed));
    let mut out = HashMap::new();
    std::thread::scope(|scope| {
        let workers: Vec<_> = by_drive
            .into_values()
            .map(|files| {
                scope.spawn(move || {
                    let mut done = Vec::with_capacity(files.len());
                    for c in files {
                        if cancelled() {
                            break;
                        }
                        if let Some(h) = hash_file(c, limit) {
                            done.push((c.path.clone(), h));
                        }
                    }
                    done
                })
            })
            .collect();
        for worker in workers {
            // A worker that panicked hashed nothing usable; its files simply drop out.
            if let Ok(done) = worker.join() {
                out.extend(done);
            }
        }
    });
    out
}

/// `project` holds a real `.git` (a folder, or the file a worktree or submodule uses).
fn has_git(project: &WinPath, layout: &SystemLayout) -> bool {
    project.join(".git").is_ok_and(|git| {
        denied_reason(&git, layout).is_none()
            && open_no_follow(&git, Access::Inspect).is_ok_and(|o| !o.resolved.is_reparse_point)
    })
}

/// `project` directly holds a file matching one of `markers` (e.g. `package.json`, `*.csproj`).
fn has_marker(project: &WinPath, markers: &[&str]) -> bool {
    crate::win::list_children(project).is_ok_and(|names| {
        names
            .iter()
            .any(|n| markers.iter().any(|m| name_matches(m, n)))
    })
}

/// The 24-hour rule again, right before acting (security review F1): the names of the items
/// directly inside `root` that a rule keeping items fresh for `hours` would **not** offer now,
/// because something in them changed within `hours` of `now` or part of them can't be read.
/// `None` when `root` itself is no longer a real folder there, so nothing in it can be checked.
/// Only reads.
pub fn too_fresh_now(
    root: &WinPath,
    layout: &SystemLayout,
    now: SystemTime,
    hours: u64,
) -> Option<std::collections::BTreeSet<String>> {
    let at = Locations::default();
    let mut s = Scanner {
        at: &at,
        layout,
        opts: WalkOptions::default(),
        now,
        report: ScanReport::default(),
        search: None,
    };
    let root = s.real_folder(root)?;
    let items = s.tally_children(&root);
    if s.report.walked.unreadable > 0 && items.is_empty() {
        return None;
    }
    Some(
        items
            .into_iter()
            .filter(|(_, t)| t.too_fresh(now, hours))
            .map(|(name, _)| name)
            .collect(),
    )
}

/// SHA-256 of the whole file at `path`, which must still be a plain file of `len` bytes there.
/// Used to check, right before acting, that a duplicate still matches its kept copy. Only reads.
pub fn hash_whole_file(path: &WinPath, len: u64) -> Option<String> {
    hash_file(
        &Candidate {
            path: path.clone(),
            len,
            modified: UNIX_EPOCH,
        },
        None,
    )
}

/// Scan the green and amber rules in `at`. Only reads.
pub fn scan(at: &Locations, layout: &SystemLayout, opts: &ScanOptions) -> ScanReport {
    scan_in_steps(at, layout, opts, |_| {})
}

/// The duplicate rule: the slow one, which hashes files, so it runs last.
fn is_duplicates(rule: &Rule) -> bool {
    matches!(
        rule.look,
        Look::Search {
            find: Find::Duplicates,
            ..
        }
    )
}

/// [`scan`] in two steps: `first` gets every finding but the duplicates as soon as they are
/// ready, and the full report is returned once hashing is done. Duplicates always come last in
/// the findings, so a finding's place in the first report is its place in the full one.
pub fn scan_in_steps(
    at: &Locations,
    layout: &SystemLayout,
    opts: &ScanOptions,
    first: impl FnOnce(&ScanReport),
) -> ScanReport {
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
    // The shared walk first, timed on its own, so each rule's time below is its own work.
    s.search();
    let (later, now): (Vec<&'static Rule>, Vec<&'static Rule>) =
        RULES.iter().partition(|r| is_duplicates(r));
    let mut first = Some(first);
    for rule in now.into_iter().chain(later) {
        if is_duplicates(rule)
            && let Some(first) = first.take()
        {
            first(&s.report);
        }
        if s.stopped() {
            s.report.cancelled = true;
            break;
        }
        let started = Instant::now();
        s.run(rule);
        if rule.tier != Tier::Red {
            s.report.steps.push(StepTime {
                step: rule.label,
                took: started.elapsed(),
            });
        }
    }
    if s.stopped() {
        s.report.cancelled = true;
    }
    // Stopped before the duplicate rule: the first step is still reported.
    if let Some(first) = first.take() {
        first(&s.report);
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
