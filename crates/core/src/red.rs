//! Red-tier sizes: what Windows' own areas take, reported and never acted on.
//!
//! Phase 2 only measures. Nothing here (or in `win::red`) can delete, move, recycle or empty
//! anything; a test reads both sources to prove it. Freeing red-tier space waits for phase 4,
//! through Windows' own tools.

use crate::rules::{Look, RULES, RedItem, Rule, Tier};

/// What ByteBroom could find out about one red-tier item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedSize {
    /// Its size. `complete` is false when part of it could not be read, so the real size is
    /// larger.
    Bytes {
        /// The bytes counted.
        bytes: u64,
        /// Every part was counted.
        complete: bool,
    },
    /// It is not on this PC.
    Absent,
    /// Its size can't be read without administrator rights.
    NeedsAdmin,
}

impl RedSize {
    /// Plain English for the owner, e.g. "3.2 GB", "not present", "needs admin".
    pub fn describe(&self) -> String {
        match self {
            Self::Bytes { bytes, complete } => {
                let gb = *bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                let text = if gb >= 1.0 {
                    format!("{gb:.1} GB")
                } else {
                    format!("{:.0} MB", *bytes as f64 / (1024.0 * 1024.0))
                };
                if *complete {
                    text
                } else {
                    format!("at least {text}")
                }
            }
            Self::Absent => "not present".into(),
            Self::NeedsAdmin => "needs admin".into(),
        }
    }
}

/// One red-tier item and its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedFinding {
    /// The rule (for its label).
    pub rule: &'static Rule,
    /// What was found.
    pub size: RedSize,
}

/// Every red-tier rule with the item it reports, in the owner's order.
pub fn red_rules() -> impl Iterator<Item = (&'static Rule, RedItem)> {
    RULES.iter().filter_map(|r| match r.look {
        Look::SizeOnly(item) if r.tier == Tier::Red => Some((r, item)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_red_rule_has_an_item() {
        assert_eq!(red_rules().count(), 7);
        assert!(red_rules().all(|(r, _)| r.tier == Tier::Red && !r.pre_ticked()));
    }

    #[test]
    fn sizes_read_plainly() {
        let gb = 1024 * 1024 * 1024;
        let full = |bytes| RedSize::Bytes {
            bytes,
            complete: true,
        };
        assert_eq!(full(3 * gb + gb / 5).describe(), "3.2 GB");
        assert_eq!(full(5 * 1024 * 1024).describe(), "5 MB");
        assert_eq!(
            RedSize::Bytes {
                bytes: 2 * gb,
                complete: false
            }
            .describe(),
            "at least 2.0 GB"
        );
        assert_eq!(RedSize::Absent.describe(), "not present");
        assert_eq!(RedSize::NeedsAdmin.describe(), "needs admin");
    }
}
