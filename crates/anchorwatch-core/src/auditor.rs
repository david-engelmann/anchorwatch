//! The trust auditor interface.
//!
//! The dependency direction is one way. The engine consumes the
//! auditor's checks and implements no trust judgment of its own. The
//! contract is a versioned JSON-shaped report with four calls:
//! verification currency, supersession integrity, freshness, and
//! provenance. Findings carry stable rule identifiers, because the
//! engine queues and reports by rule identifier. The auditor never
//! mutates the bundle, and its output is deterministic for the same
//! bundle and the same pinned as-of instant.
//!
//! The real auditor is the perishables core library, consumed
//! through the adapter in [`crate::perishables`], which translates
//! its tier reports and findings into this contract's shapes and
//! adopts its stable finding labels as the rule identifiers. The
//! mechanical stub that stood in for it until the convergence was
//! removed in the convergence round, as the design record always
//! provided.

use crate::bundle::Bundle;

/// The version of the auditor report schema this build consumes.
pub const AUDITOR_SCHEMA_VERSION: &str = "2";

/// A trust tier, calculated from current verification events only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// No current verification event.
    Unverified = 0,
    /// A current event from a process or team actor.
    MachineConfirmed = 1,
    /// A current event from a human actor.
    HumanReviewed = 2,
}

impl Tier {
    /// The tier's name in the spec's vocabulary.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Unverified => "unverified",
            Tier::MachineConfirmed => "machine-confirmed",
            Tier::HumanReviewed => "human-reviewed",
        }
    }

    /// Parses a tier name recorded by an earlier pass.
    pub fn from_name(name: &str) -> Option<Tier> {
        match name {
            "unverified" => Some(Tier::Unverified),
            "machine-confirmed" => Some(Tier::MachineConfirmed),
            "human-reviewed" => Some(Tier::HumanReviewed),
            _ => None,
        }
    }
}

/// Finding severity, in the contract's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A defect the queue must carry.
    Error,
    /// A proposal or observation for a decider.
    Warning,
}

impl Severity {
    /// The severity name as emitted in reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// One auditor finding, keyed by its stable rule identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The stable rule identifier, part of the contract.
    pub rule_id: String,
    /// The finding severity.
    pub severity: Severity,
    /// The concept the finding is about, as a bundle-relative path.
    pub concept: String,
    /// The evidence values behind the finding, as name and value pairs.
    pub evidence: Vec<(String, String)>,
}

/// The currency call's per-concept result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyEntry {
    /// The concept path.
    pub concept: String,
    /// Verification events current at the as-of instant.
    pub current_events: usize,
    /// Verification events that predate the last meaningful change.
    pub lapsed_events: usize,
    /// Verification events that cannot be judged, lacking an actor
    /// or a parseable timestamp. They count in neither of the other
    /// counts and are reported as findings in their own right, so a
    /// concept whose events are all malformed never reads as
    /// event-free.
    pub malformed_events: usize,
    /// The tier recomputed from current events only.
    pub tier: Tier,
}

/// The provenance call's per-concept result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceEntry {
    /// The concept path.
    pub concept: String,
    /// Whether the concept carries a `sources` family at all.
    pub has_sources: bool,
    /// Sources whose resource is a path inside the bundle.
    pub local_sources: usize,
    /// Local sources that do not resolve, or whose recorded content
    /// hash has drifted. Each one also raises a finding.
    pub unresolved: usize,
}

/// The auditor's report for one pass over one bundle.
#[derive(Debug, Clone)]
pub struct AuditorReport {
    /// Who produced the report, for example `stub` or the real auditor.
    pub auditor: String,
    /// The report schema version.
    pub schema_version: String,
    /// The pinned as-of instant the report was computed at.
    pub as_of: String,
    /// Currency results, in concept path order.
    pub currency: Vec<CurrencyEntry>,
    /// Provenance results, in concept path order.
    pub provenance: Vec<ProvenanceEntry>,
    /// All findings, in rule and path order.
    pub findings: Vec<Finding>,
    /// Which of the four calls this auditor actually implements.
    pub coverage: Vec<(String, bool)>,
}

/// The four-call auditor contract.
pub trait Auditor {
    /// The auditor's name, recorded in every pass report.
    fn name(&self) -> &str;
    /// Runs the implemented calls over the bundle at the pinned
    /// as-of instant. Implementations never mutate the bundle.
    fn audit(&self, bundle: &Bundle, as_of: &str) -> AuditorReport;
}
