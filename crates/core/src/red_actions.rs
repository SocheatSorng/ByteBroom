//! The red tier's actions (phase 4, owner's decision 3): what each frees, whether it can be
//! undone, the word the owner types to confirm (decision 7), and whether it needs the elevated
//! helper. Pure; the window shows these texts as they are.

#![forbid(unsafe_code)]

use crate::admin::AdminAction;

/// One red-tier action the window offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedAction {
    /// Empty the Recycle Bin: in the unelevated window, no helper (decision 8).
    RecycleBin,
    /// Clear the Delivery Optimization cache, through the helper.
    DeliveryOptimization,
    /// Turn hibernation off, through the helper (decision 4).
    Hibernation,
}

impl RedAction {
    /// Every action, in the window's order.
    pub const ALL: [RedAction; 3] = [
        RedAction::RecycleBin,
        RedAction::DeliveryOptimization,
        RedAction::Hibernation,
    ];

    /// The fixed name the page sends (never built from input).
    pub fn id(self) -> &'static str {
        match self {
            Self::RecycleBin => "recycle-bin",
            Self::DeliveryOptimization => "delivery-optimization",
            Self::Hibernation => "hibernation",
        }
    }

    /// Look an action up by the name the page sent; anything else is refused.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.id() == id)
    }

    /// The word the owner types to confirm (decision 7).
    pub fn confirm_word(self) -> &'static str {
        match self {
            Self::RecycleBin => "recycle bin",
            Self::DeliveryOptimization => "delivery optimization",
            Self::Hibernation => "hibernation",
        }
    }

    /// Whether what the owner typed confirms this action: the word, ignoring case and the
    /// spaces around it.
    pub fn confirmed_by(self, typed: &str) -> bool {
        typed.trim().eq_ignore_ascii_case(self.confirm_word())
    }

    /// The button's text.
    pub fn title(self) -> &'static str {
        match self {
            Self::RecycleBin => "Empty the Recycle Bin",
            Self::DeliveryOptimization => "Clear the Delivery Optimization cache",
            Self::Hibernation => "Turn hibernation off",
        }
    }

    /// What it frees.
    pub fn frees(self) -> &'static str {
        match self {
            Self::RecycleBin => "Frees the space the Recycle Bin uses on every drive.",
            Self::DeliveryOptimization => {
                "Frees Windows' cache of update downloads shared with other PCs; pinned files are kept."
            }
            Self::Hibernation => {
                "Frees hiberfil.sys. Hibernate and Hybrid Sleep stop working until you turn it back on."
            }
        }
    }

    /// Whether, and how, it can be undone.
    pub fn undo(self) -> &'static str {
        match self {
            Self::RecycleBin => "Can't be undone: the files are gone for good.",
            Self::DeliveryOptimization => "Can't be undone; Windows downloads again what it needs.",
            Self::Hibernation => "Undo: run powercfg /hibernate on in an administrator PowerShell.",
        }
    }

    /// The helper action it needs, or `None` when the window does it itself (decision 8).
    pub fn admin_action(self) -> Option<AdminAction> {
        match self {
            Self::RecycleBin => None,
            Self::DeliveryOptimization => Some(AdminAction::DeliveryOptimizationCache),
            Self::Hibernation => Some(AdminAction::HibernationOff),
        }
    }

    /// Before a helper action, said every time: a restore point comes first (decision 5).
    pub fn restore_note(self) -> Option<&'static str> {
        self.admin_action().map(|_| {
            "A restore point is made first (or one from the last 24 hours is used); without one, nothing is changed."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_words_match_decision_7_ignoring_case() {
        assert!(RedAction::RecycleBin.confirmed_by("Recycle Bin"));
        assert!(RedAction::DeliveryOptimization.confirmed_by("  DELIVERY OPTIMIZATION "));
        assert!(RedAction::Hibernation.confirmed_by("hibernation"));
        for wrong in ["", "yes", "hibernate", "recycle", "recyclebin", "delivery"] {
            for a in RedAction::ALL {
                assert!(!a.confirmed_by(wrong), "{a:?} {wrong:?}");
            }
        }
        // One action's word never confirms another.
        for a in RedAction::ALL {
            for b in RedAction::ALL {
                assert_eq!(a.confirmed_by(b.confirm_word()), a == b);
            }
        }
    }

    #[test]
    fn ids_round_trip_and_nothing_else_is_accepted() {
        for a in RedAction::ALL {
            assert_eq!(RedAction::from_id(a.id()), Some(a));
        }
        for bad in [
            "",
            "noop",
            "restore-point",
            "hibernation-off",
            "Hibernation",
            "recycle-bin ",
        ] {
            assert_eq!(RedAction::from_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn every_action_says_what_it_frees_and_whether_it_can_be_undone() {
        for a in RedAction::ALL {
            assert!(!a.title().is_empty() && a.frees().starts_with("Frees"));
            assert!(a.undo().starts_with("Can't be undone") || a.undo().starts_with("Undo:"));
        }
        // Only hibernation can be undone, with the command from decision 4.
        assert!(
            RedAction::Hibernation
                .undo()
                .contains("powercfg /hibernate on")
        );
    }

    #[test]
    fn the_recycle_bin_needs_no_helper_and_the_others_do() {
        assert_eq!(RedAction::RecycleBin.admin_action(), None);
        assert_eq!(RedAction::RecycleBin.restore_note(), None);
        for a in [RedAction::DeliveryOptimization, RedAction::Hibernation] {
            let action = a.admin_action().unwrap();
            assert_ne!(action, AdminAction::Noop);
            assert_ne!(action, AdminAction::RestorePoint);
            assert!(a.restore_note().is_some());
        }
    }
}
