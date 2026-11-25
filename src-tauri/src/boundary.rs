//! Everything the page can send to Rust. Only numbers and fixed choices: no text, no paths, so a
//! page can only pick among findings the scan already offered. `tests/boundary.rs` checks this file
//! never gains a text or path type.

use serde::{Deserialize, Serialize};

/// A finding, as the scan that produced it numbered it. Dies with its scan: a later scan has a
/// different `scan` number, so old IDs are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingId {
    /// Which scan handed this ID out.
    pub scan: u32,
    /// The finding's place in that scan's list.
    pub index: u32,
}

/// What to do with one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
pub enum Action {
    /// Send to the Recycle Bin.
    Recycle,
    /// Delete for good.
    Delete,
    /// Move to the folder chosen with `pick_move_destination`.
    Move,
}

/// A red-tier action the owner asked for (phase 4): a fixed choice, never text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum RedActionId {
    /// Empty the Recycle Bin (in the window, no helper).
    RecycleBin,
    /// Clear the Delivery Optimization cache (helper).
    DeliveryOptimization,
    /// Turn hibernation off (helper).
    Hibernation,
}

impl RedActionId {
    /// Every choice, in the window's order (matches `RedAction::ALL`).
    pub const ALL: [RedActionId; 3] = [
        RedActionId::RecycleBin,
        RedActionId::DeliveryOptimization,
        RedActionId::Hibernation,
    ];

    /// The core action it names.
    pub fn action(self) -> bytebroom_core::red_actions::RedAction {
        use bytebroom_core::red_actions::RedAction;
        match self {
            Self::RecycleBin => RedAction::RecycleBin,
            Self::DeliveryOptimization => RedAction::DeliveryOptimization,
            Self::Hibernation => RedAction::Hibernation,
        }
    }
}

/// One line of the owner's choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    /// The finding.
    pub finding: FindingId,
    /// The action chosen for it.
    pub action: Action,
}

/// A preview the owner has seen. `clean` acts on exactly this preview, once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewId {
    /// Which scan the preview was built from.
    pub scan: u32,
    /// Which preview of that scan.
    pub number: u32,
}

/// Moves to put back (phase 5): one clean's moves, or one of them, as the history list numbered
/// them. Dies with its list: a later list has a different `list` number, so old IDs are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PutBackId {
    /// Which history list handed this ID out.
    pub list: u32,
    /// The clean's place in that list.
    pub group: u32,
    /// One move in that clean, or `None` for every move of it still moved.
    pub item: Option<u32>,
}
