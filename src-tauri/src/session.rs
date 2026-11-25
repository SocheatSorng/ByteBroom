//! The scan session: one scan at a time on a background thread, its findings kept here in Rust.
//!
//! Each scan gets a new number, and the page refers to a finding by `(scan, index)`. A finding is
//! looked up only if its scan is the current one, so an ID from an earlier scan is refused even
//! when its index still exists. Duplicates arrive as a second step and are added after the other
//! findings (see `bytebroom_core::scan::scan_in_steps`), so indexes handed out by the first step
//! keep naming the same findings.

use crate::boundary::FindingId;
use bytebroom_core::locations::Skipped;
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
            i.cancel.store(true, Ordering::Relaxed);
            let cancel = Arc::new(AtomicBool::new(false));
            *i = Inner {
                scan: i.scan.wrapping_add(1).max(1),
                phase: Phase::Scanning,
                version: i.version.wrapping_add(1),
                cancel: cancel.clone(),
                started: Some(Instant::now()),
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

    /// The current scan's number and findings, for building a preview.
    pub fn findings(&self) -> (u32, Arc<Vec<Finding>>) {
        let i = self.lock();
        (i.scan, i.findings.clone())
    }

    /// Check that `id` names a finding of the current scan, and return its index.
    pub fn check(&self, id: FindingId) -> Result<usize, Stale> {
        let i = self.lock();
        check_id(i.scan, &i.findings, id)
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
