//! Totals for a scan, with every file counted once.
//!
//! Findings can overlap: a large file inside a temp folder that is also a finding, or one file
//! found by two rules. Per-category totals show what each rule found; tier totals, the pre-ticked
//! total and the largest items count each piece of disk once, under the outermost finding (on a
//! tie, the earlier rule, so green before amber).

use crate::rules::{RULES, Rule, Tier};
use crate::scan::Finding;
use std::cmp::Ordering;

/// What one rule found (overlaps with other rules included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CategoryTotal {
    /// The rule.
    pub rule: &'static Rule,
    /// Items found.
    pub items: usize,
    /// Their bytes.
    pub bytes: u64,
}

/// One tier's total, each file counted once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierTotal {
    /// The tier.
    pub tier: Tier,
    /// Items, not counting those inside another finding.
    pub items: usize,
    /// Their bytes.
    pub bytes: u64,
}

/// The totals of a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Every green and amber rule in order, including those that found nothing.
    pub categories: Vec<CategoryTotal>,
    /// Green, then amber; each file once.
    pub tiers: Vec<TierTotal>,
    /// Bytes of the pre-ticked (green) items, each file once.
    pub pre_ticked_bytes: u64,
    /// Indices into the findings of the largest items (not inside another finding), largest first.
    pub largest: Vec<usize>,
}

/// A path as case-folded parts, so sorting puts every folder right before what is inside it.
fn key(f: &Finding) -> Vec<String> {
    f.path.parts().iter().map(|p| p.to_lowercase()).collect()
}

fn rule_order(f: &Finding) -> usize {
    RULES
        .iter()
        .position(|r| std::ptr::eq(r, f.rule))
        .unwrap_or(usize::MAX)
}

/// Which findings are not inside (or the same as) another finding: the ones that count.
fn outermost(findings: &[Finding]) -> Vec<bool> {
    let mut order: Vec<(Vec<String>, char, usize, usize)> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| (key(f), f.path.drive(), rule_order(f), i))
        .collect();
    order.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
    });
    let mut counts = vec![false; findings.len()];
    let mut open: Vec<(char, Vec<String>)> = Vec::new();
    for (parts, drive, _, i) in order {
        while let Some((d, top)) = open.last() {
            let inside = *d == drive && parts.len() >= top.len() && parts[..top.len()] == top[..];
            if inside {
                break;
            }
            open.pop();
        }
        if open.is_empty() {
            counts[i] = true;
            open.push((drive, parts));
        }
    }
    counts
}

/// Add up `findings`, keeping the `top` largest items.
pub fn summarize(findings: &[Finding], top: usize) -> Summary {
    let categories = RULES
        .iter()
        .filter(|r| r.tier != Tier::Red)
        .map(|rule| {
            let mine = findings.iter().filter(|f| std::ptr::eq(f.rule, rule));
            CategoryTotal {
                rule,
                items: mine.clone().count(),
                bytes: mine.map(|f| f.bytes).sum(),
            }
        })
        .collect();
    let counts = outermost(findings);
    let counted = || findings.iter().enumerate().filter(|(i, _)| counts[*i]);
    let tiers = [Tier::Green, Tier::Amber]
        .into_iter()
        .map(|tier| {
            let mine = counted().filter(|(_, f)| f.tier == tier);
            TierTotal {
                tier,
                items: mine.clone().count(),
                bytes: mine.map(|(_, f)| f.bytes).sum(),
            }
        })
        .collect();
    let pre_ticked_bytes = counted()
        .filter(|(_, f)| f.pre_ticked)
        .map(|(_, f)| f.bytes)
        .sum();
    let mut largest: Vec<usize> = counted().map(|(i, _)| i).collect();
    largest.sort_by(|&a, &b| match findings[b].bytes.cmp(&findings[a].bytes) {
        Ordering::Equal => a.cmp(&b),
        other => other,
    });
    largest.truncate(top);
    Summary {
        categories,
        tiers,
        pre_ticked_bytes,
        largest,
    }
}

/// Bytes in plain English, as Explorer counts them: "512 bytes", "3.4 KB", "1.2 GB".
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::WinPath;
    use std::time::UNIX_EPOCH;

    fn finding(rule: &str, root: &str, path: &str, bytes: u64) -> Finding {
        let rule = RULES
            .iter()
            .find(|r| r.id == rule)
            .unwrap_or_else(|| unreachable!("{rule}"));
        let p = |s: &str| WinPath::parse(s).unwrap_or_else(|e| unreachable!("{s}: {e}"));
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

    const T: &str = "C:\\U\\AppData\\Local\\Temp";

    fn sample() -> Vec<Finding> {
        vec![
            finding("user-temp", T, "C:\\U\\AppData\\Local\\Temp\\big", 1000),
            // Inside the temp folder above: counted there, not again.
            finding(
                "large-files",
                "C:\\U\\AppData\\Local\\Temp\\big",
                "C:\\U\\AppData\\Local\\Temp\\big\\x.iso",
                900,
            ),
            // A sibling whose name sorts between "big" and "big\x.iso" as plain text.
            finding("user-temp", T, "C:\\U\\AppData\\Local\\Temp\\big c", 10),
            // One file found by two amber rules.
            finding(
                "old-installers",
                "C:\\U\\Downloads",
                "C:\\U\\Downloads\\s.exe",
                600,
            ),
            finding(
                "large-files",
                "C:\\U\\Downloads",
                "C:\\U\\Downloads\\S.EXE",
                600,
            ),
            finding("duplicates", "D:\\x", "D:\\x\\copy.bin", 50),
        ]
    }

    #[test]
    fn each_file_counts_once_in_tier_totals() {
        let s = summarize(&sample(), 20);
        assert_eq!(
            s.tiers,
            vec![
                TierTotal {
                    tier: Tier::Green,
                    items: 2,
                    bytes: 1010
                },
                TierTotal {
                    tier: Tier::Amber,
                    items: 2,
                    bytes: 650
                },
            ]
        );
        assert_eq!(s.pre_ticked_bytes, 1010);
    }

    #[test]
    fn categories_show_what_each_rule_found_including_overlaps_and_empty_ones() {
        let s = summarize(&sample(), 20);
        let get = |id: &str| {
            s.categories
                .iter()
                .find(|c| c.rule.id == id)
                .copied()
                .unwrap_or_else(|| unreachable!("{id}"))
        };
        assert_eq!(
            (get("large-files").items, get("large-files").bytes),
            (2, 1500)
        );
        assert_eq!((get("user-temp").items, get("user-temp").bytes), (2, 1010));
        assert_eq!(get("crash-dumps").items, 0);
        assert_eq!(s.categories.len(), 12);
        assert!(s.categories.iter().all(|c| c.rule.tier != Tier::Red));
    }

    #[test]
    fn the_largest_list_skips_covered_items_and_is_cut_to_size() {
        let f = sample();
        let s = summarize(&f, 3);
        let paths: Vec<String> = s.largest.iter().map(|&i| f[i].path.to_string()).collect();
        assert_eq!(
            paths,
            vec![
                "C:\\U\\AppData\\Local\\Temp\\big",
                // Same file (case aside) under two rules: "Large files" comes first in RULES.
                "C:\\U\\Downloads\\S.EXE",
                "D:\\x\\copy.bin"
            ]
        );
    }

    #[test]
    fn nothing_found_adds_up_to_zero() {
        let s = summarize(&[], 20);
        assert!(s.tiers.iter().all(|t| t.items == 0 && t.bytes == 0));
        assert!(s.largest.is_empty());
    }

    #[test]
    fn bytes_read_like_explorer() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(1023), "1023 bytes");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(500 * 1024 * 1024), "500.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
        assert_eq!(human_bytes(u64::MAX), "16777216.0 TB");
    }
}
