//! The scan session: one scan at a time on a background thread, its findings kept here in Rust.
//!
//! Each scan gets a new number, and the page refers to a finding by `(scan, index)`. A finding is
//! looked up only if its scan is the current one, so an ID from an earlier scan is refused even
//! when its index still exists. Duplicates arrive as a second step and are added after the other
//! findings (see `bytebroom_core::scan::scan_in_steps`), so indexes handed out by the first step
//! keep naming the same findings.

use crate::boundary::{Action, Choice, FindingId, PreviewId};
use bytebroom_core::locations::Skipped;
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::SystemLayout;
use bytebroom_core::preview::{self as core_preview, Preview};
use bytebroom_core::red::RedFinding;
use bytebroom_core::scan::Finding;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Where the current scan is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    /// No scan has run yet.
    #[default]
    Idle,
    /// Walking the folders (first step).
    Scanning,
    /// Everything but duplicates is listed; hashing duplicates.
    Hashing,
    /// Finished.
    Done,
    /// Stopped by the owner (what was found so far is still listed).
    Cancelled,
}

impl Phase {
    /// The phase as the page names it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Scanning => "scanning",
            Self::Hashing => "hashing",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
        }
    }

    fn running(self) -> bool {
        matches!(self, Self::Scanning | Self::Hashing)
    }
}

/// Why a finding ID was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// It belongs to an earlier scan (or no scan has run).
    OtherScan,
    /// No finding has that number.
    NoSuchFinding,
}

impl std::fmt::Display for Stale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OtherScan => "that item is from an earlier scan; scan again",
            Self::NoSuchFinding => "that item is not in the scan",
        })
    }
}

#[derive(Debug, Default)]
struct Inner {
    /// The current scan's number (0: none yet).
    scan: u32,
    phase: Phase,
    findings: Arc<Vec<Finding>>,
    red: Option<Vec<RedFinding>>,
    skipped: Vec<Skipped>,
    /// Changes whenever `findings` does, so the page fetches the list only when it changed.
    version: u32,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    took: Option<Duration>,
    /// The folder moves go to, as the owner picked it (kept across scans).
    move_to: Option<WinPath>,
    /// The latest preview of this scan; `clean` takes it, once.
    preview: Option<(PreviewId, Arc<Preview>)>,
    /// How many previews this scan has made.
    previews_made: u32,
    /// A clean is running (see `CleanGuard`).
    cleaning: bool,
    /// This scan was cleaned once; its findings no longer describe the disk.
    used_up: bool,
}

/// A preview ready for confirming: its ID, what it does, and the findings it refers to.
#[derive(Debug, Clone)]
pub struct Ready {
    /// What the page sends back to confirm it.
    pub id: PreviewId,
    /// What it does.
    pub preview: Arc<Preview>,
    /// The scan's findings (the preview refers to them by index).
    pub findings: Arc<Vec<Finding>>,
}

/// What the page is shown about the current scan.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The scan's number.
    pub scan: u32,
    /// Where it is.
    pub phase: Phase,
    /// The findings' version.
    pub version: u32,
    /// The findings so far.
    pub findings: Arc<Vec<Finding>>,
    /// Red-tier sizes, once measured.
    pub red: Option<Vec<RedFinding>>,
    /// Locations that are not scanned, and why.
    pub skipped: Vec<Skipped>,
    /// Time since the scan started (or its total, once finished).
    pub elapsed: Duration,
}

/// The app's one scan session.
#[derive(Debug, Default)]
pub struct Session {
    inner: Mutex<Inner>,
}

/// Handed to a scan job, so it can report to the scan that started it and to no other.
#[derive(Debug, Clone)]
pub struct Reporter {
    session: Arc<Session>,
    scan: u32,
    /// Set when the owner cancels or a newer scan starts.
    pub cancel: Arc<AtomicBool>,
}

impl Reporter {
    /// Run `f` on the session's state if this reporter's scan is still the current one.
    fn update(&self, f: impl FnOnce(&mut Inner)) {
        let mut inner = self.session.lock();
        if inner.scan == self.scan {
            f(&mut inner);
        }
    }

    /// The locations that are not scanned.
    pub fn skipped(&self, skipped: Vec<Skipped>) {
        self.update(|i| i.skipped = skipped);
    }

    /// Everything but duplicates is found.
    pub fn first_step(&self, findings: &[Finding]) {
        self.update(|i| {
            i.findings = Arc::new(findings.to_vec());
            i.version = i.version.wrapping_add(1);
            if i.phase == Phase::Scanning {
                i.phase = Phase::Hashing;
            }
        });
    }

    /// Red-tier sizes are measured.
    pub fn red(&self, red: Vec<RedFinding>) {
        self.update(|i| i.red = Some(red));
    }

    /// The scan ended, with these findings (duplicates included).
    pub fn finished(&self, findings: Vec<Finding>, cancelled: bool) {
        self.update(|i| {
            i.findings = Arc::new(findings);
            i.version = i.version.wrapping_add(1);
            i.phase = if cancelled {
                Phase::Cancelled
            } else {
                Phase::Done
            };
            i.took = i.started.map(|s| s.elapsed());
        });
    }
}

impl Session {
    /// The state, even if a thread panicked while holding the lock (the data is replaced as a
    /// whole on every update, so it is never half-written).
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Start a new scan running `job` on its own thread. Any running scan is cancelled, and its
    /// IDs stop being accepted at once. Returns the new scan's number and the thread.
    pub fn start(
        self: &Arc<Self>,
        job: impl FnOnce(Reporter) + Send + 'static,
    ) -> (u32, std::io::Result<JoinHandle<()>>) {
        let reporter = {
            let mut i = self.lock();
            if i.cleaning {
                return (
                    i.scan,
                    Err(std::io::Error::other(
                        "a clean is running; scan again when it ends",
                    )),
                );
            }
            i.cancel.store(true, Ordering::Relaxed);
            let cancel = Arc::new(AtomicBool::new(false));
            *i = Inner {
                scan: i.scan.wrapping_add(1).max(1),
                phase: Phase::Scanning,
                version: i.version.wrapping_add(1),
                cancel: cancel.clone(),
                started: Some(Instant::now()),
                move_to: i.move_to.take(),
                ..Inner::default()
            };
            Reporter {
                session: self.clone(),
                scan: i.scan,
                cancel,
            }
        };
        let scan = reporter.scan;
        let thread = std::thread::Builder::new()
            .name(format!("scan {scan}"))
            .spawn(move || job(reporter));
        if thread.is_err() {
            let mut i = self.lock();
            if i.scan == scan {
                i.phase = Phase::Cancelled;
            }
        }
        (scan, thread)
    }

    /// Ask the running scan to stop. What it found so far stays listed.
    pub fn cancel(&self) {
        let i = self.lock();
        if i.phase.running() {
            i.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// The current scan as the page sees it.
    pub fn snapshot(&self) -> Snapshot {
        let i = self.lock();
        Snapshot {
            scan: i.scan,
            phase: i.phase,
            version: i.version,
            findings: i.findings.clone(),
            red: i.red.clone(),
            skipped: i.skipped.clone(),
            elapsed: i
                .took
                .or_else(|| i.started.map(|s| s.elapsed()))
                .unwrap_or_default(),
        }
    }

    /// Check that `id` names a finding of the current scan, and return its index.
    pub fn check(&self, id: FindingId) -> Result<usize, Stale> {
        let i = self.lock();
        check_id(i.scan, &i.findings, id)
    }

    /// Remember the folder moves go to (already checked by the caller).
    pub fn set_move_to(&self, dest: WinPath) {
        let mut i = self.lock();
        i.move_to = Some(dest);
        // A preview made for another destination must not be confirmed.
        i.preview = None;
    }

    /// The folder moves go to, if one was picked.
    pub fn move_to(&self) -> Option<WinPath> {
        self.lock().move_to.clone()
    }

    /// Build a preview of `choices` over the current scan and keep it for `take_preview`. Only a
    /// finished (or stopped) scan can be previewed, and every ID must be from it. Each preview
    /// replaces the one before, so only the latest can be confirmed.
    pub fn make_preview(&self, choices: &[Choice], layout: &SystemLayout) -> Result<Ready, String> {
        let mut i = self.lock();
        if i.phase.running() {
            return Err("wait for the scan to finish, or stop it".into());
        }
        if i.cleaning {
            return Err("a clean is running; wait for it to finish".into());
        }
        if i.used_up {
            return Err("this scan was already cleaned; scan again to see what is left".into());
        }
        // Each finding can be chosen once; more choices than findings can only be a bad request
        // (and would make the preview's checks slow while holding the lock).
        if choices.len() > i.findings.len() {
            return Err("more items were chosen than the scan found".into());
        }
        let mut core_choices = Vec::with_capacity(choices.len());
        for c in choices {
            let index = check_id(i.scan, &i.findings, c.finding).map_err(|e| e.to_string())?;
            core_choices.push(core_preview::Choice {
                index,
                action: match c.action {
                    Action::Recycle => core_preview::Action::Recycle,
                    Action::Delete => core_preview::Action::Delete,
                    Action::Move => core_preview::Action::Move,
                },
            });
        }
        let preview = core_preview::preview(&i.findings, &core_choices, i.move_to.as_ref(), layout)
            .map_err(|e| e.to_string())?;
        i.previews_made = i.previews_made.wrapping_add(1);
        let id = PreviewId {
            scan: i.scan,
            number: i.previews_made,
        };
        let preview = Arc::new(preview);
        i.preview = Some((id, preview.clone()));
        Ok(Ready {
            id,
            preview,
            findings: i.findings.clone(),
        })
    }

    /// Take the preview `id` for cleaning. It must be the latest preview of the current scan,
    /// and it can be taken once: a second `clean` of the same preview is refused. While the
    /// returned guard lives, a clean is running: no scan, preview or other clean can start
    /// (security review: two cleans at once could each keep "the other" copy of a duplicate).
    /// Afterwards the scan is used up, so the next clean needs a new scan.
    pub fn take_preview(self: &Arc<Self>, id: PreviewId) -> Result<(Ready, CleanGuard), String> {
        let mut i = self.lock();
        if i.phase.running() {
            return Err("a scan is running; preview again when it ends".into());
        }
        if i.cleaning {
            return Err("a clean is running; wait for it to finish".into());
        }
        match i.preview.take() {
            Some((kept, preview)) if kept == id && id.scan == i.scan => {
                i.cleaning = true;
                i.used_up = true;
                Ok((
                    Ready {
                        id,
                        preview,
                        findings: i.findings.clone(),
                    },
                    CleanGuard {
                        session: self.clone(),
                    },
                ))
            }
            other => {
                // Not this one: the latest preview stays for its own confirm.
                i.preview = other;
                Err("that preview is out of date; preview again".into())
            }
        }
    }
}

/// Marks a clean as running; dropping it (when the clean ends, or if it panics) ends that.
#[derive(Debug)]
pub struct CleanGuard {
    session: Arc<Session>,
}

impl CleanGuard {
    /// The owner declined at the last step and nothing was done: the scan stays usable.
    pub fn nothing_done(self) {
        self.session.lock().used_up = false;
    }
}

impl Drop for CleanGuard {
    fn drop(&mut self) {
        self.session.lock().cleaning = false;
    }
}

/// `id` names one of `findings`, which belong to scan `scan`. Pure.
pub fn check_id(scan: u32, findings: &[Finding], id: FindingId) -> Result<usize, Stale> {
    if scan == 0 || id.scan != scan {
        return Err(Stale::OtherScan);
    }
    let index = usize::try_from(id.index).map_err(|_| Stale::NoSuchFinding)?;
    if index < findings.len() {
        Ok(index)
    } else {
        Err(Stale::NoSuchFinding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytebroom_core::paths::WinPath;
    use bytebroom_core::rules::RULES;
    use std::sync::mpsc;
    use std::time::UNIX_EPOCH;

    fn finding(name: &str) -> Finding {
        let rule = &RULES[0];
        Finding {
            rule,
            tier: rule.tier,
            root: WinPath::parse("C:\\T").unwrap(),
            path: WinPath::parse(&format!("C:\\T\\{name}")).unwrap(),
            is_folder: false,
            bytes: 1,
            files: 1,
            newest: UNIX_EPOCH,
            cloud: false,
            pre_ticked: true,
            duplicate_of: None,
            identity: None,
        }
    }

    fn id(scan: u32, index: u32) -> FindingId {
        FindingId { scan, index }
    }

    #[test]
    fn ids_from_an_earlier_scan_are_refused() {
        let s = Arc::new(Session::default());
        assert_eq!(s.check(id(0, 0)), Err(Stale::OtherScan));
        let (first, t) = s.start(|r| r.finished(vec![finding("a"), finding("b")], false));
        t.unwrap().join().unwrap();
        assert_eq!(s.check(id(first, 1)), Ok(1));
        assert_eq!(s.check(id(first, 2)), Err(Stale::NoSuchFinding));
        assert_eq!(s.check(id(first, u32::MAX)), Err(Stale::NoSuchFinding));

        let (second, t) = s.start(|r| r.finished(vec![finding("a"), finding("b")], false));
        t.unwrap().join().unwrap();
        assert_ne!(first, second);
        // Same index, same file even: still refused, because it came from the earlier scan.
        assert_eq!(s.check(id(first, 1)), Err(Stale::OtherScan));
        assert_eq!(s.check(id(second, 1)), Ok(1));
        assert_eq!(s.check(id(second + 1, 0)), Err(Stale::OtherScan));
    }

    #[test]
    fn a_newer_scan_cancels_the_old_one_and_ignores_its_reports() {
        let s = Arc::new(Session::default());
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (seen_tx, seen_rx) = mpsc::channel::<bool>();
        let (old, t_old) = s.start(move |r| {
            go_rx.recv().unwrap();
            seen_tx.send(r.cancel.load(Ordering::Relaxed)).unwrap();
            r.finished(
                vec![finding("old1"), finding("old2"), finding("old3")],
                false,
            );
        });
        let (new, t_new) = s.start(|r| r.finished(vec![finding("new")], false));
        t_new.unwrap().join().unwrap();
        go_tx.send(()).unwrap();
        assert!(seen_rx.recv().unwrap(), "the old scan was told to stop");
        t_old.unwrap().join().unwrap();
        let snap = s.snapshot();
        assert_eq!(snap.scan, new);
        assert_ne!(old, new);
        assert_eq!(
            snap.findings.len(),
            1,
            "the old scan's late report was ignored"
        );
        assert_eq!(snap.phase, Phase::Done);
    }

    #[test]
    fn the_first_step_is_listed_while_duplicates_hash_and_its_ids_stay_valid() {
        let s = Arc::new(Session::default());
        let (step_tx, step_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (scan, t) = s.start(move |r| {
            r.first_step(&[finding("a")]);
            step_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            r.finished(vec![finding("a"), finding("dup")], false);
        });
        step_rx.recv().unwrap();
        let mid = s.snapshot();
        assert_eq!(mid.phase, Phase::Hashing);
        assert_eq!(mid.findings.len(), 1);
        assert_eq!(s.check(id(scan, 0)), Ok(0));
        go_tx.send(()).unwrap();
        t.unwrap().join().unwrap();
        let end = s.snapshot();
        assert_eq!(end.phase, Phase::Done);
        assert_ne!(end.version, mid.version);
        assert_eq!(end.findings[0].path, mid.findings[0].path);
        assert_eq!(s.check(id(scan, 1)), Ok(1));
    }

    fn layout() -> SystemLayout {
        let p = |s: &str| WinPath::parse(s).unwrap();
        SystemLayout {
            system_root: p("C:\\Windows"),
            program_files: vec![p("C:\\Program Files")],
            program_data: p("C:\\ProgramData"),
            profiles_dir: p("C:\\Users"),
            profile_roots: vec![p("C:\\Users\\Ann")],
            extra_denied: Vec::new(),
        }
    }

    fn choose(scan: u32, index: u32) -> Choice {
        Choice {
            finding: id(scan, index),
            action: Action::Delete,
        }
    }

    fn finished_session() -> (Arc<Session>, u32) {
        let s = Arc::new(Session::default());
        let (scan, t) = s.start(|r| r.finished(vec![finding("a"), finding("b")], false));
        t.unwrap().join().unwrap();
        (s, scan)
    }

    #[test]
    fn a_preview_can_be_cleaned_once_and_only_the_latest() {
        let (s, scan) = finished_session();
        let first = s.make_preview(&[choose(scan, 0)], &layout()).unwrap();
        let second = s.make_preview(&[choose(scan, 1)], &layout()).unwrap();
        assert_ne!(first.id, second.id);
        // The older preview is out of date; the latest is still there afterwards.
        assert!(s.take_preview(first.id).is_err());
        let (taken, guard) = s.take_preview(second.id).unwrap();
        assert_eq!(taken.preview.actions[0].items, vec![1]);
        // Once only.
        assert!(s.take_preview(second.id).is_err());
        drop(guard);
    }

    /// Security review: while a clean runs nothing else may start, and a cleaned scan can't be
    /// previewed again (two cleans could each keep "the other" copy of a duplicate).
    #[test]
    fn nothing_else_runs_during_a_clean_and_a_cleaned_scan_is_used_up() {
        let (s, scan) = finished_session();
        let ready = s.make_preview(&[choose(scan, 0)], &layout()).unwrap();
        let (_, guard) = s.take_preview(ready.id).unwrap();
        assert!(s.make_preview(&[choose(scan, 1)], &layout()).is_err());
        let (still, thread) = s.start(|r| r.finished(Vec::new(), false));
        assert_eq!(still, scan);
        assert!(thread.is_err(), "no scan starts during a clean");
        drop(guard);
        // Used up: a new preview needs a new scan.
        let err = s.make_preview(&[choose(scan, 1)], &layout()).unwrap_err();
        assert!(err.contains("scan again"), "{err}");
        let (scan2, t) = s.start(|r| r.finished(vec![finding("a")], false));
        t.unwrap().join().unwrap();
        assert!(s.make_preview(&[choose(scan2, 0)], &layout()).is_ok());
    }

    #[test]
    fn more_choices_than_findings_are_refused() {
        let (s, scan) = finished_session();
        let many: Vec<Choice> = (0..3).map(|_| choose(scan, 0)).collect();
        assert!(s.make_preview(&many, &layout()).is_err());
        assert!(s.make_preview(&many[..2], &layout()).is_ok());
    }

    #[test]
    fn previews_refuse_stale_ids_and_die_with_their_scan() {
        let (s, scan) = finished_session();
        let ready = s.make_preview(&[choose(scan, 0)], &layout()).unwrap();
        assert!(s.make_preview(&[choose(scan + 1, 0)], &layout()).is_err());
        assert!(s.make_preview(&[choose(scan, 7)], &layout()).is_err());
        let (_, t) = s.start(|r| r.finished(vec![finding("a")], false));
        t.unwrap().join().unwrap();
        assert!(
            s.take_preview(ready.id).is_err(),
            "a new scan ends old previews"
        );
        assert!(s.make_preview(&[choose(scan, 0)], &layout()).is_err());
    }

    #[test]
    fn no_preview_or_clean_while_a_scan_runs_and_a_new_destination_ends_the_preview() {
        let (s, scan) = finished_session();
        let ready = s.make_preview(&[choose(scan, 0)], &layout()).unwrap();
        s.set_move_to(WinPath::parse("D:\\Keep").unwrap());
        assert!(s.take_preview(ready.id).is_err());

        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (scan2, t) = s.start(move |r| {
            r.first_step(&[finding("a")]);
            go_rx.recv().unwrap();
            r.finished(vec![finding("a")], false);
        });
        assert!(s.make_preview(&[choose(scan2, 0)], &layout()).is_err());
        go_tx.send(()).unwrap();
        t.unwrap().join().unwrap();
        assert!(s.make_preview(&[choose(scan2, 0)], &layout()).is_ok());
        // The destination is kept across scans.
        assert_eq!(s.move_to(), Some(WinPath::parse("D:\\Keep").unwrap()));
    }

    #[test]
    fn cancel_reaches_the_running_job_and_is_reported() {
        let s = Arc::new(Session::default());
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (_, t) = s.start(move |r| {
            go_rx.recv().unwrap();
            let stopped = r.cancel.load(Ordering::Relaxed);
            r.finished(vec![finding("partial")], stopped);
        });
        s.cancel();
        go_tx.send(()).unwrap();
        t.unwrap().join().unwrap();
        let snap = s.snapshot();
        assert_eq!(snap.phase, Phase::Cancelled);
        assert_eq!(snap.findings.len(), 1, "what was found so far stays listed");
        // Cancelling when nothing runs changes nothing.
        s.cancel();
        assert_eq!(s.snapshot().phase, Phase::Cancelled);
    }
}
