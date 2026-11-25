//! Everything the page can send to Rust. Only numbers and fixed choices: no text, no paths, so a
//! page can only pick among findings the scan already offered. `tests/boundary.rs` checks this file
//! never gains a text or path type.

use serde::Deserialize;

/// A finding, as the scan that produced it numbered it. Dies with its scan: a later scan has a
/// different `scan` number, so old IDs are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewId {
    /// Which scan the preview was built from.
    pub scan: u32,
    /// Which preview of that scan.
    pub number: u32,
}
