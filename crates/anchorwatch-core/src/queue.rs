//! The re-verification queue.
//!
//! The queue is the pass's main human-facing output. It lives in the
//! bundle as a Markdown file with a JSON twin under the bundle's
//! `.recension` directory, the engine's own state home, where
//! bundle validators and the concept inventory do not read. Items
//! carry a reason from a fixed
//! vocabulary, the evidence values behind the item, the runs that
//! first raised and last confirmed it, and a state. The engine moves
//! an item to done only on observed evidence; a human or agent moves
//! it to waived, with the waiver recorded in the queue file itself.

/// Reason code for a passed `stale_after`.
pub const STALE: &str = "STALE";
/// Reason code for a verification that predates the last change.
pub const LAPSED_VERIFICATION: &str = "LAPSED VERIFICATION";
/// Reason code for a recomputed tier lower than the last recorded tier.
pub const TIER_DROP: &str = "TIER DROP";
/// Reason code for a supersession chain problem or proposal.
pub const SUPERSESSION_DEFECT: &str = "SUPERSESSION DEFECT";
/// Reason code for a missing or unresolvable source.
pub const PROVENANCE_GAP: &str = "PROVENANCE GAP";
/// Reason code for a concept with no `stale_after` at all.
pub const NO_REVIEW_DATE: &str = "NO REVIEW DATE";
/// Reason code for a concept that lost its `type` key.
pub const TYPE_MISSING: &str = "TYPE MISSING";
/// Reason code for an index that no longer matches its directory.
pub const INDEX_DRIFT: &str = "INDEX DRIFT";
/// Reason code for a semantic-layer definition that references a
/// column the live schema no longer carries, or carries changed.
/// The name is the working vocabulary of the cross-ecosystem
/// grading programme, settled jointly with the trust auditor's
/// design record; it changes by amendment, never silently.
pub const DEFINITION_DRIFT: &str = "DEFINITION DRIFT";

/// The state of one queue item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueState {
    /// Raised and not yet worked.
    Open,
    /// Claimed by a human or agent.
    Claimed,
    /// Closed on evidence observed by a pass.
    Done,
    /// Waived by a human or agent, recorded in the queue file.
    Waived,
}

impl QueueState {
    /// The state name as stored in the queue file.
    pub fn as_str(&self) -> &'static str {
        match self {
            QueueState::Open => "open",
            QueueState::Claimed => "claimed",
            QueueState::Done => "done",
            QueueState::Waived => "waived",
        }
    }

    /// Parses a stored state name.
    pub fn from_name(name: &str) -> Option<QueueState> {
        match name {
            "open" => Some(QueueState::Open),
            "claimed" => Some(QueueState::Claimed),
            "done" => Some(QueueState::Done),
            "waived" => Some(QueueState::Waived),
            _ => None,
        }
    }
}

/// One re-verification queue item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueItem {
    /// The concept the item is about, as a bundle-relative path.
    pub concept: String,
    /// A reason code from the fixed vocabulary above.
    pub reason: String,
    /// Evidence values from the bundle, as name and value pairs.
    pub evidence: Vec<(String, String)>,
    /// The run that first raised the item.
    pub first_raised: String,
    /// The run that most recently confirmed the item still holds.
    pub last_confirmed: String,
    /// The item's state.
    pub state: QueueState,
    /// Priority class from the pass's deterministic ordering.
    /// Zero is worked first.
    pub priority: u8,
}

impl QueueItem {
    /// Creates an open item raised by `run_id`.
    pub fn new(
        concept: String,
        reason: &str,
        evidence: Vec<(String, String)>,
        run_id: &str,
    ) -> QueueItem {
        QueueItem {
            concept,
            reason: reason.to_string(),
            evidence,
            first_raised: run_id.to_string(),
            last_confirmed: run_id.to_string(),
            state: QueueState::Open,
            priority: 2,
        }
    }
}

/// Sorts items into the pass's deterministic work order: priority
/// class first, then concept path, then reason code.
pub fn sort_queue(items: &mut [QueueItem]) {
    items.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.concept.cmp(&b.concept))
            .then_with(|| a.reason.cmp(&b.reason))
    });
}
