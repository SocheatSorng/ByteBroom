//! From the owner's confirmed selection to what the phase 1 engine acts on.
//!
//! [`plan_clean`] (pure) turns chosen findings into targets and the rules' own folders as roots:
//! red-tier findings are refused, a path chosen twice is acted on once, and an item inside another
//! chosen item is left to that item, so nothing is counted or handled twice.
//!
//! [`prepare`] then re-opens every root without following it. Each must still be the same real
//! folder the scan saw (same spelling, not a link) and pass [`Policy::new`] on its own, which
//! refuses the hard floor and the key, credential and Startup folders. A refused root takes only
//! its own items out of the clean; the rest go ahead. The engine then checks every item again at
//! the moment of action.

use crate::paths::WinPath;
use crate::policy::{Policy, Refusal, SystemLayout};
use crate::rules::Tier;
use crate::scan::Finding;
use crate::win::{Access, open_no_follow};
use std::fmt;

/// Why a selection can't be planned at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// A chosen number is not a finding.
    Unknown(usize),
    /// A red-tier item was chosen; those are freed only through Windows' own tools.
    RedTier(WinPath),
    /// A finding's item is not strictly inside its own root (never produced by the scanner).
    NotInsideRoot(WinPath),
}

impl fmt::Display for SelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "item {n} is not in the scan"),
            Self::RedTier(p) => write!(f, "{p} is a Windows area ByteBroom does not clean"),
            Self::NotInsideRoot(p) => write!(f, "{p} is not inside its rule's folder"),
        }
    }
}

impl std::error::Error for SelectError {}

/// What a confirmed selection asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanPlan {
    /// The rules' folders the clean may act inside, each once.
    pub roots: Vec<WinPath>,
    /// The items to act on, each strictly inside one of `roots`, none inside another.
    pub targets: Vec<WinPath>,
    /// Bytes the scan counted for the targets.
    pub bytes: u64,
    /// Files the scan counted for the targets.
    pub files: u64,
}

/// Turn the chosen findings (by their index in `findings`) into a plan. Pure.
pub fn plan_clean(findings: &[Finding], chosen: &[usize]) -> Result<CleanPlan, SelectError> {
    let mut picked: Vec<&Finding> = Vec::new();
    for &n in chosen {
        let f = findings.get(n).ok_or(SelectError::Unknown(n))?;
        if f.tier == Tier::Red {
            return Err(SelectError::RedTier(f.path.clone()));
        }
        if !f.path.is_strictly_inside(&f.root) {
            return Err(SelectError::NotInsideRoot(f.path.clone()));
        }
        if !picked.iter().any(|p| p.path.eq_ignore_case(&f.path)) {
            picked.push(f);
        }
    }
    // An item inside another chosen item is handled (and counted) by the outer one.
    let outer: Vec<&Finding> = picked
        .iter()
        .copied()
        .filter(|f| {
            !picked.iter().any(|o| {
                !o.path.eq_ignore_case(&f.path) && f.path.is_at_or_inside_ignore_case(&o.path)
            })
        })
        .collect();
    let mut plan = CleanPlan::default();
    for f in outer {
        if !plan.roots.iter().any(|r| r.eq_ignore_case(&f.root)) {
            plan.roots.push(f.root.clone());
        }
        plan.targets.push(f.path.clone());
        plan.bytes += f.bytes;
        plan.files += f.files;
    }
    Ok(plan)
}

/// A plan checked on disk: the policy for the engine and the targets it may act on.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The policy over every root that passed, or `None` when none did.
    pub policy: Option<Policy>,
    /// The targets inside roots that passed.
    pub targets: Vec<WinPath>,
    /// Roots that were refused, why, and the targets left out with them.
    pub refused: Vec<RefusedRoot>,
}

/// A root that can't be cleaned, and what that leaves out.
#[derive(Debug, Clone)]
pub struct RefusedRoot {
    /// The rule's folder.
    pub root: WinPath,
    /// Why.
    pub why: String,
    /// The chosen items inside it, which stay.
    pub targets: Vec<WinPath>,
}

fn check_root(
    root: &WinPath,
    layout: &SystemLayout,
) -> Result<crate::policy::ResolvedPath, String> {
    let opened = open_no_follow(root, Access::Inspect).map_err(|e| e.to_string())?;
    if opened.resolved.is_reparse_point {
        return Err(Refusal::ReparsePoint.to_string());
    }
    if !opened.is_directory || opened.resolved.final_path != *root {
        return Err("it changed since the scan".into());
    }
    Policy::new(vec![opened.resolved.clone()], layout.clone()).map_err(|e| e.to_string())?;
    Ok(opened.resolved)
}

/// Check every root of `plan` on disk and build the engine's policy. Only reads.
pub fn prepare(plan: &CleanPlan, layout: &SystemLayout) -> Prepared {
    let mut ok = Vec::new();
    let mut refused = Vec::new();
    for root in &plan.roots {
        match check_root(root, layout) {
            Ok(resolved) => ok.push(resolved),
            Err(why) => refused.push(RefusedRoot {
                root: root.clone(),
                why,
                targets: plan
                    .targets
                    .iter()
                    .filter(|t| t.is_strictly_inside(root))
                    .cloned()
                    .collect(),
            }),
        }
    }
    let targets: Vec<WinPath> = plan
        .targets
        .iter()
        .filter(|t| ok.iter().any(|r| t.is_strictly_inside(&r.final_path)))
        .cloned()
        .collect();
    let policy = if ok.is_empty() {
        None
    } else {
        // Each root already passed on its own, so this only fails if the floor changed between
        // the two calls; then nothing is cleaned.
        Policy::new(ok, layout.clone()).ok()
    };
    let targets = if policy.is_some() {
        targets
    } else {
        Vec::new()
    };
    Prepared {
        policy,
        targets,
        refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RULES;
    use std::time::UNIX_EPOCH;

    fn p(s: &str) -> WinPath {
        WinPath::parse(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }

    fn finding(rule: &str, root: &str, path: &str, bytes: u64) -> Finding {
        let rule = RULES
            .iter()
            .find(|r| r.id == rule)
            .unwrap_or_else(|| unreachable!("{rule}"));
        Finding {
            rule,
            tier: rule.tier,
            root: p(root),
            path: p(path),
            is_folder: false,
            bytes,
            files: 1,
            newest: UNIX_EPOCH,
            cloud: false,
            pre_ticked: rule.pre_ticked(),
            duplicate_of: None,
        }
    }

    const TEMP: &str = "C:\\Users\\Ann\\AppData\\Local\\Temp";

    fn sample() -> Vec<Finding> {
        vec![
            finding(
                "user-temp",
                TEMP,
                "C:\\Users\\Ann\\AppData\\Local\\Temp\\a",
                10,
            ),
            finding(
                "user-temp",
                TEMP,
                "C:\\Users\\Ann\\AppData\\Local\\Temp\\big",
                1000,
            ),
            // The same file as a large file, and a large file inside the chosen temp folder.
            finding(
                "large-files",
                "C:\\Users\\Ann\\AppData\\Local\\Temp\\big",
                "C:\\Users\\Ann\\AppData\\Local\\Temp\\big\\x.iso",
                900,
            ),
            finding(
                "old-installers",
                "C:\\Users\\Ann\\Downloads",
                "C:\\Users\\Ann\\Downloads\\s.exe",
                5,
            ),
            finding(
                "large-files",
                "C:\\Users\\Ann\\Downloads",
                "C:\\Users\\Ann\\Downloads\\s.exe",
                5,
            ),
        ]
    }

    #[test]
    fn roots_are_the_rules_folders_each_once() {
        let plan = plan_clean(&sample(), &[0, 1, 3]).unwrap_or_default();
        assert_eq!(plan.roots, vec![p(TEMP), p("C:\\Users\\Ann\\Downloads")]);
        assert_eq!(plan.targets.len(), 3);
        assert_eq!(plan.bytes, 1015);
        for t in &plan.targets {
            assert!(plan.roots.iter().any(|r| t.is_strictly_inside(r)));
        }
    }

    #[test]
    fn a_file_found_twice_or_inside_a_chosen_folder_is_handled_once() {
        let plan = plan_clean(&sample(), &[1, 2, 3, 4, 3]).unwrap_or_default();
        assert_eq!(
            plan.targets,
            vec![
                p("C:\\Users\\Ann\\AppData\\Local\\Temp\\big"),
                p("C:\\Users\\Ann\\Downloads\\s.exe")
            ]
        );
        assert_eq!(plan.bytes, 1005);
        // The inner large file's own root is not needed.
        assert_eq!(plan.roots.len(), 2);
    }

    #[test]
    fn red_unknown_and_malformed_choices_are_refused() {
        let mut f = sample();
        assert_eq!(plan_clean(&f, &[9]), Err(SelectError::Unknown(9)));
        f[0].tier = Tier::Red;
        assert!(matches!(plan_clean(&f, &[0]), Err(SelectError::RedTier(_))));
        let mut f = sample();
        f[0].path = p(TEMP);
        assert!(matches!(
            plan_clean(&f, &[0]),
            Err(SelectError::NotInsideRoot(_))
        ));
        let mut f = sample();
        f[0].path = p("C:\\Users\\Ann\\Documents\\x");
        assert!(matches!(
            plan_clean(&f, &[0]),
            Err(SelectError::NotInsideRoot(_))
        ));
    }

    #[test]
    fn an_empty_selection_plans_nothing() {
        assert_eq!(plan_clean(&sample(), &[]), Ok(CleanPlan::default()));
    }
}
