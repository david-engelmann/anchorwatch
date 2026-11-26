//! The adapter to the real trust auditor, the perishables core
//! library.
//!
//! The adapter implements the locked [`Auditor`] contract over
//! `perishables_core`, translating its tier reports and findings
//! into the contract's shapes. Three translation decisions are the
//! adapter's own contract surface, recorded in the design record's
//! convergence sections. Concept identity: the publisher names a
//! concept by its bundle-relative path without the Markdown suffix,
//! and the adapter re-attaches the suffix in both directions.
//! Severity: the publisher's findings carry no severity, so the
//! adapter publishes the code-to-severity table below. Rule
//! identifiers: the publisher's stable finding labels are adopted
//! verbatim, retiring the placeholder series the stub used.
//!
//! Attested computations arrive through the publisher's executor,
//! which the adapter calls only when the operator opts in, the
//! upkeep command's attestation flag being off by default: a
//! scheduled pass that spawns an interpreter by default would
//! change what the tool is trusted to do unattended. With the flag
//! on, the executor re-runs the bundle's declared computations
//! under the publisher's deterministic profile, with the
//! publisher's default limits rather than its environment
//! overrides, so an attesting pass over the same bundle at the
//! same instant still produces the same result.

use perishables_core::{
    AuditClock, Bundle as PerishablesBundle, EventClass, FindingCode, check_currency, check_drift,
    check_freshness, check_provenance, check_supersession, recompute_tier,
};

use crate::auditor::{
    AUDITOR_SCHEMA_VERSION, Auditor, AuditorReport, CurrencyEntry, Finding, ProvenanceEntry,
    Severity, Tier,
};
use crate::bundle::Bundle;

/// The trust auditor as the upkeep engine consumes it: the
/// perishables core library behind the locked contract.
#[derive(Default)]
pub struct PerishablesAuditor {
    /// Whether the audit re-executes the bundle's declared
    /// computations and reports their verdicts. Off by default;
    /// the upkeep command's attestation flag turns it on.
    pub execute_attestations: bool,
}

/// The adapter's published code-to-severity table. Nine codes are
/// defects the queue must carry at error severity; the three
/// remaining codes are observations for a decider.
fn severity(code: FindingCode) -> Severity {
    match code {
        FindingCode::DanglingSupersededBy
        | FindingCode::SupersessionCycle
        | FindingCode::UnparseableStaleAfter
        | FindingCode::MalformedVerification
        | FindingCode::UnresolvedCitation
        | FindingCode::MissingSource
        | FindingCode::SourceDrift
        | FindingCode::AttestedResultMismatch
        | FindingCode::UnattestedClaim => Severity::Error,
        FindingCode::LapsedVerification
        | FindingCode::SupersededWithoutDeprecated
        | FindingCode::StaleButStable => Severity::Warning,
    }
}

fn translate(finding: perishables_core::Finding) -> Finding {
    Finding {
        rule_id: finding.code.label().to_string(),
        severity: severity(finding.code),
        concept: format!("{}.md", finding.concept_id),
        evidence: vec![("detail".to_string(), finding.detail)],
    }
}

fn uncovered_report(as_of: &str) -> AuditorReport {
    AuditorReport {
        auditor: "perishables".to_string(),
        schema_version: AUDITOR_SCHEMA_VERSION.to_string(),
        as_of: as_of.to_string(),
        currency: Vec::new(),
        provenance: Vec::new(),
        findings: Vec::new(),
        coverage: vec![
            ("currency".to_string(), false),
            ("supersession".to_string(), false),
            ("freshness".to_string(), false),
            ("provenance".to_string(), false),
        ],
    }
}

impl Auditor for PerishablesAuditor {
    fn name(&self) -> &str {
        "perishables"
    }

    fn audit(&self, bundle: &Bundle, as_of: &str) -> AuditorReport {
        // A load the publisher's reader refuses is surfaced as a
        // report covering nothing, never as a clean audit: the
        // pass reports the uncovered calls in its notes, as the
        // design record's convergence decisions provide.
        let Some(clock) = AuditClock::parse(as_of) else {
            return uncovered_report(as_of);
        };
        let Ok(p_bundle) = PerishablesBundle::load(&bundle.root) else {
            return uncovered_report(as_of);
        };

        let mut raw_findings = Vec::new();
        raw_findings.extend(check_currency(&p_bundle, &clock));
        raw_findings.extend(check_supersession(&p_bundle));
        raw_findings.extend(check_freshness(&p_bundle, &clock));
        raw_findings.extend(check_provenance(&p_bundle));
        raw_findings.extend(check_drift(&p_bundle));
        if self.execute_attestations {
            let reports = perishables::execute::run_computations(
                &p_bundle,
                &perishables::execute::ExecConfig::default(),
            );
            raw_findings.extend(perishables::execute::findings_from_reports(&reports));
        }

        let mut coverage = vec![
            ("currency".to_string(), true),
            ("supersession".to_string(), true),
            ("freshness".to_string(), true),
            ("provenance".to_string(), true),
        ];
        // Attestation is this adapter's own optional path, not
        // one of the contract's four calls. Where it did not run
        // and the bundle carries a claimed result it would have
        // judged, the coverage says so, so the pass names the
        // unrun derivation instead of letting a clean report
        // imply it ran. Where it ran, or where no claimed result
        // stands to be misread, no entry appears.
        if !self.execute_attestations
            && p_bundle.concepts.iter().any(|c| c.claimed_result.is_some())
        {
            coverage.push(("attestation".to_string(), false));
        }

        let mut currency = Vec::new();
        let mut provenance = Vec::new();
        for concept in &p_bundle.concepts {
            let report = recompute_tier(concept, &clock);
            let count_class =
                |class: EventClass| report.events.iter().filter(|e| e.class == class).count();
            currency.push(CurrencyEntry {
                concept: format!("{}.md", concept.id),
                current_events: count_class(EventClass::Current),
                lapsed_events: count_class(EventClass::Lapsed),
                malformed_events: count_class(EventClass::Malformed),
                tier: Tier::from_name(report.recomputed_tier.name()).unwrap_or(Tier::Unverified),
            });
            let local_sources = concept
                .sources
                .iter()
                .filter(|s| match &s.resource {
                    Some(r) => !r.is_empty() && !r.contains("://") && !r.contains(' '),
                    None => false,
                })
                .count();
            let unresolved = raw_findings
                .iter()
                .filter(|f| {
                    f.concept_id == concept.id
                        && matches!(
                            f.code,
                            FindingCode::MissingSource | FindingCode::SourceDrift
                        )
                })
                .count();
            provenance.push(ProvenanceEntry {
                concept: format!("{}.md", concept.id),
                has_sources: !concept.sources.is_empty(),
                local_sources,
                unresolved,
            });
        }

        let mut findings: Vec<Finding> = raw_findings.into_iter().map(translate).collect();
        findings.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.concept.cmp(&b.concept))
        });
        currency.sort_by(|a, b| a.concept.cmp(&b.concept));
        provenance.sort_by(|a, b| a.concept.cmp(&b.concept));

        AuditorReport {
            auditor: self.name().to_string(),
            schema_version: AUDITOR_SCHEMA_VERSION.to_string(),
            as_of: as_of.to_string(),
            currency,
            provenance,
            findings,
            coverage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PerishablesAuditor;
    use crate::auditor::{Auditor, Severity, Tier};
    use crate::bundle::Bundle;
    use std::path::PathBuf;

    fn fixture(name: &str, files: &[(&str, &str)]) -> (PathBuf, Bundle) {
        let dir = std::env::temp_dir().join(format!(
            "anchorwatch-perishables-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for (rel, text) in files {
            let path = dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
        }
        let bundle = Bundle::load(&dir).unwrap();
        (dir, bundle)
    }

    #[test]
    fn a_dangling_target_surfaces_under_the_publishers_label() {
        let (_dir, bundle) = fixture(
            "dangling",
            &[
                (
                    "a.md",
                    "---\ntype: Note\nstatus: deprecated\nsuperseded_by: gone.md\n---\nbody\n",
                ),
                ("index.md", "# Index\n"),
            ],
        );
        let report = PerishablesAuditor::default().audit(&bundle, "2026-11-25T00:00:00Z");
        assert_eq!(report.auditor, "perishables");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "DANGLING_SUPERSEDED_BY");
        assert_eq!(report.findings[0].severity, Severity::Error);
        assert_eq!(report.findings[0].concept, "a.md");
    }

    #[test]
    fn tiers_and_event_classes_translate() {
        let (_dir, bundle) = fixture(
            "tiers",
            &[
                (
                    "a.md",
                    "---\ntype: Note\ngenerated:\n  at: \"2026-11-01T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-02T00:00:00Z\"\n  - by: \"process:old\"\n    at: \"2026-10-01T00:00:00Z\"\n  - by: \"human:broken\"\n---\nbody\n",
                ),
                ("index.md", "# Index\n"),
            ],
        );
        let report = PerishablesAuditor::default().audit(&bundle, "2026-11-25T00:00:00Z");
        let entry = &report.currency[0];
        assert_eq!(entry.concept, "a.md");
        assert_eq!(entry.current_events, 1);
        assert_eq!(entry.lapsed_events, 1);
        assert_eq!(entry.malformed_events, 1);
        assert_eq!(entry.tier, Tier::HumanReviewed);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "MALFORMED_VERIFICATION")
        );
    }
}
