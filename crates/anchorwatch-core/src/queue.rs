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

use std::path::{Path, PathBuf};

/// Writes one of the engine's own state files durably: the
/// content lands in a sibling temporary first and is renamed
/// over the target, so a reader, including the next pass after
/// a crash, sees the old file whole or the new file whole and
/// never a torn one. The state files are the engine's memory
/// across passes, and a torn queue would forget what a human
/// did to it, a waiver above all. Bundle content files are not
/// written this way; they are the user's, and the queue is what
/// records their state.
pub(crate) fn write_durably(path: &Path, content: &str) -> std::io::Result<()> {
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    std::fs::write(&tmp, content)?;
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

/// Reason code for a passed `stale_after`.
pub const STALE: &str = "STALE";
/// Reason code for a verification that predates the last change.
pub const LAPSED_VERIFICATION: &str = "LAPSED VERIFICATION";
/// Reason code for a recomputed tier lower than the last recorded tier.
pub const TIER_DROP: &str = "TIER DROP";
/// Reason code for a verification event that cannot be judged,
/// lacking an actor or a parseable timestamp, so the concept's
/// recorded verification misstates its state. The name mirrors the
/// auditor's own finding label, adopted by amendment in the
/// convergence round on the same precedent as DEFINITION DRIFT.
pub const MALFORMED_VERIFICATION: &str = "MALFORMED VERIFICATION";
/// Reason code for an attested computation whose claimed result
/// does not recompute, or whose claim no computation can support.
/// The name mirrors the auditor's own finding family, adopted by
/// amendment alongside MALFORMED VERIFICATION, and it gained its
/// producer in the attestation follow-on round.
pub const ATTESTATION_DEFECT: &str = "ATTESTATION DEFECT";
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

/// A generated claim registry has drifted from the bundle it
/// indexes: an entry names a concept the bundle no longer carries,
/// an entry's supersession edge names a claim the registry does
/// not hold, or a claim id appears twice. The registry is the
/// product seat's artefact; the engine checks it as found and
/// does not adopt its convention as a general format rule.
pub const REGISTRY_DRIFT: &str = "REGISTRY DRIFT";

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

#[cfg(test)]
mod tests {
    use super::write_durably;

    #[test]
    fn a_durable_write_lands_exactly_and_leaves_no_temporary() {
        let dir = std::env::temp_dir().join(format!("anchorwatch-durable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("queue.json");
        write_durably(&path, "{\"items\": []}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"items\": []}");
        // A second write replaces the first whole.
        write_durably(&path, "{\"items\": [1]}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"items\": [1]}");
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["queue.json".to_string()]);
    }

    #[test]
    fn a_durable_write_into_a_missing_directory_fails_by_name() {
        let path = std::env::temp_dir()
            .join(format!(
                "anchorwatch-durable-missing-{}",
                std::process::id()
            ))
            .join("nope")
            .join("queue.json");
        assert!(write_durably(&path, "x").is_err());
        assert!(!path.exists());
    }
}
