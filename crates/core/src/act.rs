//! Carry out a confirmed [`Preview`]: per action, re-open the roots ([`prepare`]), check every
//! target right before acting (security review F1), then hand what passed to the phase 1 engine,
//! which checks each item again at the moment of action.
//!
//! The check right before acting refuses a target when:
//!
//! - **a file is not the one the scan saw:** another file in its place (a different Windows file
//!   number), or new contents (a different length or change date);
//! - **a duplicate no longer matches** its kept copy (both hashed again), or the kept copy is gone;
//! - **the 24-hour rule** would no longer offer it: something in it changed within the rule's
//!   hours, or part of it can't be read.
//!
//! Anything refused is reported with the reason and left in place; the rest goes ahead.

use crate::clean::prepare;
use crate::engine::{Outcome, SkipReason, Skipped, Target, delete_targets, not_as_expected};
use crate::paths::WinPath;
use crate::policy::{Policy, SystemLayout};
use crate::preview::{Action, Preview};
use crate::relocate::{Journal, move_targets};
use crate::scan::{Finding, hash_whole_file, too_fresh_now};
use crate::win::{Access, open_no_follow};
use std::collections::{BTreeSet, HashMap};
use std::time::SystemTime;

/// What one action did.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// The action.
    pub action: Action,
    /// The engine's report, plus everything the checks left in place.
    pub outcome: Outcome,
}

/// Everything the engine needs from outside: the time the 24-hour rule is measured from, where
/// moves are journalled, and how to recycle (the real Recycle Bin in the app; tests pass a
/// stand-in, so they never touch the owner's bin).
pub struct Context<'a> {
    /// Windows' layout (the hard floor).
    pub layout: &'a SystemLayout,
    /// Now, for the 24-hour rule.
    pub now: SystemTime,
    /// The move journal, held open (in the owner's local app data, never in the repo).
    pub journal: &'a Journal,
    /// Sends targets to the Recycle Bin within a policy.
    pub recycle: &'a dyn Fn(&Policy, &[Target]) -> Outcome,
}

/// Why `f`'s item must not be acted on now, or `None` if it may. Only reads.
pub fn changed_since_scan(f: &Finding) -> Option<&'static str> {
    if !f.is_folder {
        let Ok(opened) = open_no_follow(&f.path, Access::Inspect) else {
            return Some("it can no longer be opened");
        };
        if opened.resolved.is_reparse_point || opened.is_directory {
            return Some("it is no longer a plain file");
        }
        if let Some(seen) = &f.identity {
            if let Some(what) = not_as_expected(&opened, seen) {
                return Some(what);
            }
        } else if opened.size != f.bytes {
            return Some("its size changed");
        }
    }
    if let Some(kept) = &f.duplicate_of {
        let Some(len) = f.identity.map(|i| i.len) else {
            return Some("its identity was not recorded");
        };
        match (hash_whole_file(&f.path, len), hash_whole_file(kept, len)) {
            (Some(a), Some(b)) if a == b => {}
            (_, None) => return Some("the kept copy is gone or changed"),
            _ => return Some("it no longer matches the kept copy"),
        }
    }
    None
}

/// Run the checks for the targets of one action. Returns the targets that passed and the
/// skipped ones with their reasons.
fn check_targets(
    targets: &[WinPath],
    by_path: &HashMap<&WinPath, &Finding>,
    ctx: &Context,
) -> (Vec<WinPath>, Vec<Skipped>) {
    // The 24-hour rule: one walk per root, whatever the number of items in it.
    let mut fresh: HashMap<(WinPath, u64), Option<BTreeSet<String>>> = HashMap::new();
    let mut ok = Vec::new();
    let mut skipped = Vec::new();
    for target in targets {
        let Some(f) = by_path.get(target) else {
            skipped.push(Skipped {
                path: target.clone(),
                reason: SkipReason::ChangedSinceScan("it is not in the scan"),
            });
            continue;
        };
        let mut why = changed_since_scan(f);
        if why.is_none() && f.rule.fresh_hours > 0 {
            let key = (f.root.clone(), f.rule.fresh_hours);
            let names = fresh
                .entry(key)
                .or_insert_with(|| too_fresh_now(&f.root, ctx.layout, ctx.now, f.rule.fresh_hours));
            // The 24-hour rule judges items directly inside the rule's folder; anything deeper
            // (never produced by the scanner) can't be judged, so it fails safe (security review).
            let name = (f.path.parts().len() == f.root.parts().len() + 1)
                .then(|| f.path.parts().last())
                .flatten();
            why = match (names, name) {
                (Some(names), Some(name)) if !names.contains(name) => None,
                (Some(_), Some(_)) => Some("it was used in the last day, or can't all be read"),
                _ => Some("its folder can no longer be checked"),
            };
        }
        match why {
            None => ok.push(target.clone()),
            Some(what) => skipped.push(Skipped {
                path: target.clone(),
                reason: SkipReason::ChangedSinceScan(what),
            }),
        }
    }
    (ok, skipped)
}

/// Carry out `preview` over the scan's `findings`. Each action runs on its own; a refusal in one
/// leaves the others to go ahead.
pub fn carry_out(findings: &[Finding], preview: &Preview, ctx: &Context) -> Vec<ActionResult> {
    let by_path: HashMap<&WinPath, &Finding> = findings.iter().map(|f| (&f.path, f)).collect();
    let mut results = Vec::new();
    for plan in &preview.actions {
        let mut outcome = Outcome::default();
        let prepared = prepare(&plan.plan, ctx.layout);
        for refused in &prepared.refused {
            for t in &refused.targets {
                outcome.skipped.push(Skipped {
                    path: t.clone(),
                    reason: SkipReason::Unsupported(refused.why.clone()),
                });
            }
        }
        if let Some(policy) = &prepared.policy {
            let (ok, mut skipped) = check_targets(&prepared.targets, &by_path, ctx);
            outcome.skipped.append(&mut skipped);
            // Each file's identity goes with it, to be compared again on the handle that acts.
            let ok: Vec<Target> = ok
                .iter()
                .map(|path| Target {
                    path: path.clone(),
                    expect: by_path.get(path).and_then(|f| f.identity),
                })
                .collect();
            if !ok.is_empty() {
                let done = match plan.action {
                    Action::Delete => delete_targets(policy, &ok),
                    Action::Recycle => (ctx.recycle)(policy, &ok),
                    Action::Move => match &preview.move_to {
                        Some(dest) => move_targets(policy, &ok, dest, ctx.journal),
                        None => {
                            let mut o = Outcome::default();
                            for t in &ok {
                                o.skipped.push(Skipped {
                                    path: t.path.clone(),
                                    reason: SkipReason::Unsupported("no destination".into()),
                                });
                            }
                            o
                        }
                    },
                };
                merge(&mut outcome, done);
            }
        }
        results.push(ActionResult {
            action: plan.action,
            outcome,
        });
    }
    results
}

fn merge(into: &mut Outcome, from: Outcome) {
    into.removed.extend(from.removed);
    into.skipped.extend(from.skipped);
    into.warnings.extend(from.warnings);
    into.bytes_freed += from.bytes_freed;
    into.bytes_recycled += from.bytes_recycled;
    into.bytes_moved += from.bytes_moved;
}
