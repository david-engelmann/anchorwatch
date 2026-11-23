//! The trust auditor interface and its stub.
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
//! Until the real auditor publishes its interface, the engine builds
//! against [`StubAuditor`], which implements the four calls in their
//! mechanical form for the dogfood fixture, exactly as the design
//! record sanctions. The stub is a test instrument for the upkeep
//! contract, never a second auditor, and it is removed when the real
//! interface lands. Rule identifiers are stable across both: AW-CUR
//! for currency data (carried as entries, not findings), AW-SUP for
//! supersession integrity, AW-FRE for freshness, and AW-PRO for
//! provenance.

use std::collections::BTreeMap;

use crate::bundle::Bundle;
use crate::time::parse_timestamp;

/// The version of the auditor report schema this build consumes.
pub const AUDITOR_SCHEMA_VERSION: &str = "1";

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

/// The sanctioned stub auditor. Implements the four calls in their
/// mechanical form. See the module documentation before relying on
/// it for anything beyond the upkeep contract's own tests.
pub struct StubAuditor;

impl Auditor for StubAuditor {
    fn name(&self) -> &str {
        "stub"
    }

    fn audit(&self, bundle: &Bundle, as_of: &str) -> AuditorReport {
        let mut currency = Vec::new();
        let mut provenance = Vec::new();
        let mut findings = Vec::new();
        let as_of_secs = parse_timestamp(as_of);
        let deprecated: Vec<&str> = bundle
            .concepts()
            .filter(|c| c.frontmatter.status.as_deref() == Some("deprecated"))
            .map(|c| c.relpath.as_str())
            .collect();
        for concept in bundle.concepts() {
            let fm = &concept.frontmatter;
            let generated = fm.generated_at.as_deref().and_then(parse_timestamp);
            let mut current = 0usize;
            let mut lapsed = 0usize;
            let mut best = Tier::Unverified;
            for event in &fm.verified {
                let at = parse_timestamp(&event.at);
                let is_current = match (at, generated) {
                    (Some(at), Some(gen)) => at >= gen,
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                if is_current {
                    current += 1;
                    let tier = if event.by.starts_with("human:") {
                        Tier::HumanReviewed
                    } else {
                        Tier::MachineConfirmed
                    };
                    if tier > best {
                        best = tier;
                    }
                } else {
                    lapsed += 1;
                }
            }
            currency.push(CurrencyEntry {
                concept: concept.relpath.clone(),
                current_events: current,
                lapsed_events: lapsed,
                tier: best,
            });
            // Freshness. A malformed review date is a defect, never
            // fresh; a passed date is a lapse signal for the queue.
            if let Some(raw) = fm.stale_after.as_deref() {
                match parse_timestamp(raw) {
                    None => findings.push(Finding {
                        rule_id: "AW-FRE-02".to_string(),
                        severity: Severity::Error,
                        concept: concept.relpath.clone(),
                        evidence: vec![("stale_after".to_string(), raw.to_string())],
                    }),
                    Some(stale_secs) => {
                        if let Some(now) = as_of_secs {
                            if now > stale_secs {
                                findings.push(Finding {
                                    rule_id: "AW-FRE-01".to_string(),
                                    severity: Severity::Warning,
                                    concept: concept.relpath.clone(),
                                    evidence: vec![
                                        ("stale_after".to_string(), raw.to_string()),
                                        ("as_of".to_string(), as_of.to_string()),
                                    ],
                                });
                            }
                        }
                    }
                }
            }
            // Provenance. Absence of the sources family is data, not
            // a finding: a concept that declares no sources has no
            // missing source. A declared local source that does not
            // resolve, or whose recorded hash has drifted, is one.
            let mut local_sources = 0usize;
            let mut unresolved = 0usize;
            for entry in &fm.sources {
                let Some(resource) = entry.resource.as_deref() else {
                    continue;
                };
                if resource.starts_with("http://")
                    || resource.starts_with("https://")
                    || resource.contains(' ')
                {
                    continue;
                }
                local_sources += 1;
                match bundle.file(resource) {
                    None => {
                        unresolved += 1;
                        findings.push(Finding {
                            rule_id: "AW-PRO-01".to_string(),
                            severity: Severity::Error,
                            concept: concept.relpath.clone(),
                            evidence: vec![(
                                "resource".to_string(),
                                resource.to_string(),
                            )],
                        });
                    }
                    Some(target) => {
                        if let Some(recorded) = entry.content_hash.as_deref() {
                            if recorded != target.hash {
                                unresolved += 1;
                                findings.push(Finding {
                                    rule_id: "AW-PRO-02".to_string(),
                                    severity: Severity::Error,
                                    concept: concept.relpath.clone(),
                                    evidence: vec![
                                        ("resource".to_string(), resource.to_string()),
                                        ("recorded_hash".to_string(), recorded.to_string()),
                                        ("actual_hash".to_string(), target.hash.clone()),
                                    ],
                                });
                            }
                        }
                    }
                }
            }
            provenance.push(ProvenanceEntry {
                concept: concept.relpath.clone(),
                has_sources: fm.has_sources,
                local_sources,
                unresolved,
            });
            // Supersession integrity for declared chains.
            if fm.status.as_deref() == Some("deprecated") {
                match fm.superseded_by.as_deref() {
                    Some(target) => {
                        if bundle.file(target).is_none() {
                            findings.push(Finding {
                                rule_id: "AW-SUP-01".to_string(),
                                severity: Severity::Error,
                                concept: concept.relpath.clone(),
                                evidence: vec![(
                                    "superseded_by".to_string(),
                                    target.to_string(),
                                )],
                            });
                        }
                        if chain_cycles(bundle, &concept.relpath) {
                            findings.push(Finding {
                                rule_id: "AW-SUP-02".to_string(),
                                severity: Severity::Error,
                                concept: concept.relpath.clone(),
                                evidence: vec![(
                                    "superseded_by".to_string(),
                                    target.to_string(),
                                )],
                            });
                        }
                    }
                    None => {
                        findings.push(Finding {
                            rule_id: "AW-SUP-01".to_string(),
                            severity: Severity::Error,
                            concept: concept.relpath.clone(),
                            evidence: vec![(
                                "superseded_by".to_string(),
                                "(absent)".to_string(),
                            )],
                        });
                    }
                }
            }
            // A current concept that links to a deprecated concept as
            // its live reference is a proposal for a decider, never
            // an engine conclusion.
            if fm.status.as_deref() != Some("deprecated") && !deprecated.is_empty() {
                if let Ok(text) = std::fs::read_to_string(bundle.root.join(&concept.relpath)) {
                    for target in &deprecated {
                        if text.contains(&format!("]({target})")) {
                            findings.push(Finding {
                                rule_id: "AW-SUP-03".to_string(),
                                severity: Severity::Warning,
                                concept: concept.relpath.clone(),
                                evidence: vec![(
                                    "links_to_deprecated".to_string(),
                                    target.to_string(),
                                )],
                            });
                        }
                    }
                }
            }
        }
        findings.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.concept.cmp(&b.concept))
        });
        AuditorReport {
            auditor: self.name().to_string(),
            schema_version: AUDITOR_SCHEMA_VERSION.to_string(),
            as_of: as_of.to_string(),
            currency,
            provenance,
            findings,
            coverage: vec![
                ("currency".to_string(), true),
                ("supersession".to_string(), true),
                ("freshness".to_string(), true),
                ("provenance".to_string(), true),
            ],
        }
    }
}

fn chain_cycles(bundle: &Bundle, start: &str) -> bool {
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    let mut current = start.to_string();
    loop {
        if seen.insert(current.clone(), ()).is_some() {
            return true;
        }
        let Some(file) = bundle.file(&current) else {
            return false;
        };
        if file.frontmatter.status.as_deref() != Some("deprecated") {
            return false;
        }
        match file.frontmatter.superseded_by.as_deref() {
            Some(target) => current = target.to_string(),
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Auditor, StubAuditor, Tier};
    use crate::bundle::Bundle;
    use std::io::Write;

    fn fixture(name: &str, files: &[(&str, &str)]) -> (std::path::PathBuf, Bundle) {
        let dir = std::env::temp_dir().join(format!(
            "anchorwatch-auditor-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for (rel, content) in files {
            let path = dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
        }
        let bundle = Bundle::load(&dir).unwrap();
        (dir, bundle)
    }

    #[test]
    fn currency_counts_only_events_at_or_after_generation() {
        let (_dir, bundle) = fixture("currency", &[(
            "a.md",
            "---\ntype: Note\ngenerated:\n  at: \"2026-11-10T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-01T00:00:00Z\"\n  - by: \"process:nightly\"\n    at: \"2026-11-12T00:00:00Z\"\n---\nbody\n",
        )]);
        let report = StubAuditor.audit(&bundle, "2026-11-21T00:00:00Z");
        assert_eq!(report.currency.len(), 1);
        assert_eq!(report.currency[0].current_events, 1);
        assert_eq!(report.currency[0].lapsed_events, 1);
        assert_eq!(report.currency[0].tier, Tier::MachineConfirmed);
    }

    #[test]
    fn freshness_flags_passed_and_malformed_review_dates() {
        let (_dir, bundle) = fixture("freshness", &[
            (
                "a.md",
                "---\ntype: Note\nstale_after: 2026-11-01\n---\nbody\n",
            ),
            (
                "b.md",
                "---\ntype: Note\nstale_after: next Tuesday\n---\nbody\n",
            ),
            (
                "c.md",
                "---\ntype: Note\nstale_after: 2027-01-01\n---\nbody\n",
            ),
        ]);
        let report = StubAuditor.audit(&bundle, "2026-11-21T00:00:00Z");
        let ids: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert_eq!(ids, vec!["AW-FRE-01", "AW-FRE-02"]);
    }

    #[test]
    fn provenance_flags_only_declared_sources_that_fail() {
        let (_dir, bundle) = fixture("provenance", &[
            (
                "a.md",
                "---\ntype: Note\nsources:\n  - resource: \"refs/missing.md\"\n  - resource: \"https://example.com/spec\"\n  - resource: \"all queries in project X\"\n---\nbody\n",
            ),
            ("b.md", "---\ntype: Note\n---\nbody\n"),
        ]);
        let report = StubAuditor.audit(&bundle, "2026-11-21T00:00:00Z");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "AW-PRO-01");
        assert_eq!(report.provenance.len(), 2);
        assert!(report.provenance[0].has_sources);
        assert!(!report.provenance[1].has_sources);
    }

    #[test]
    fn a_dangling_supersession_target_is_a_finding() {
        let (_dir, bundle) = fixture("dangling", &[(
            "a.md",
            "---\ntype: Note\nstatus: deprecated\nsuperseded_by: gone.md\n---\nbody\n",
        )]);
        let report = StubAuditor.audit(&bundle, "2026-11-21T00:00:00Z");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "AW-SUP-01");
    }
}
