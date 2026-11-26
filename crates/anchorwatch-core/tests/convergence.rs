//! The convergence round's acceptance tests, from the design
//! record's section 66 table: the real auditor's findings, carried
//! through the adapter and the pass, raise exactly the queue items
//! the table promises, at the promised priorities. Each fixture is
//! a minimal bundle carrying one defect family; engine-rule items
//! (index drift, no review date) are filtered out of the
//! assertions, as the table provides.

use std::path::PathBuf;

use anchorwatch_core::perishables::PerishablesAuditor;
use anchorwatch_core::queue::{
    ATTESTATION_DEFECT, MALFORMED_VERIFICATION, PROVENANCE_GAP, STALE, SUPERSESSION_DEFECT,
};
use anchorwatch_core::upkeep::{Mode, PassReport, run_pass};

const AS_OF: &str = "2026-11-25T00:00:00Z";

fn bundle(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "anchorwatch-convergence-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.md"), "# Fixture\n").unwrap();
    std::fs::write(dir.join("log.md"), "# Bundle Update Log\n").unwrap();
    for (rel, text) in files {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
    }
    dir
}

fn pass(dir: &std::path::Path) -> PassReport {
    run_pass(dir, AS_OF, &PerishablesAuditor::default(), Mode::DryRun).unwrap()
}

fn pass_attesting(dir: &std::path::Path) -> PassReport {
    let auditor = PerishablesAuditor {
        execute_attestations: true,
    };
    run_pass(dir, AS_OF, &auditor, Mode::DryRun).unwrap()
}

/// The priorities of the items one concept drew under one reason.
fn priorities(report: &PassReport, concept: &str, reason: &str) -> Vec<u8> {
    report
        .queue
        .iter()
        .filter(|item| item.concept == concept && item.reason == reason)
        .map(|item| item.priority)
        .collect()
}

/// Whether a concept drew any auditor-driven item at all.
fn any_defect(report: &PassReport, concept: &str) -> bool {
    report.queue.iter().any(|item| {
        item.concept == concept
            && matches!(
                item.reason.as_str(),
                STALE
                    | SUPERSESSION_DEFECT
                    | PROVENANCE_GAP
                    | MALFORMED_VERIFICATION
                    | ATTESTATION_DEFECT
            )
    })
}

fn concept(extra: &str) -> String {
    format!("---\ntype: Note\n{extra}---\nbody\n")
}

// The publisher's discipline, which the convergence adopts: a
// supersession chain is walked once per component, so a cycle
// raises one finding on the component's entry concept, its
// detail naming the whole chain. Section 66's table promised a
// defect per member, from the stub's per-concept behaviour; the
// correction is recorded in section 71.
#[test]
fn a_two_concept_cycle_raises_one_defect_on_the_entry_concept() {
    let dir = bundle(
        "cycle-two",
        &[
            (
                "a.md",
                &concept("status: deprecated\nsuperseded_by: b.md\n"),
            ),
            (
                "b.md",
                &concept("status: deprecated\nsuperseded_by: a.md\n"),
            ),
        ],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", SUPERSESSION_DEFECT), vec![1]);
    assert_eq!(
        priorities(&report, "b.md", SUPERSESSION_DEFECT),
        Vec::<u8>::new()
    );
}

#[test]
fn a_three_concept_cycle_raises_one_defect_on_the_entry_concept() {
    let dir = bundle(
        "cycle-three",
        &[
            (
                "a.md",
                &concept("status: deprecated\nsuperseded_by: b.md\n"),
            ),
            (
                "b.md",
                &concept("status: deprecated\nsuperseded_by: c.md\n"),
            ),
            (
                "c.md",
                &concept("status: deprecated\nsuperseded_by: a.md\n"),
            ),
        ],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", SUPERSESSION_DEFECT), vec![1]);
    for name in ["b.md", "c.md"] {
        assert_eq!(
            priorities(&report, name, SUPERSESSION_DEFECT),
            Vec::<u8>::new()
        );
    }
}

#[test]
fn a_dangling_target_raises_an_error_defect() {
    let dir = bundle(
        "dangling",
        &[(
            "a.md",
            &concept("status: deprecated\nsuperseded_by: gone.md\n"),
        )],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", SUPERSESSION_DEFECT), vec![1]);
}

#[test]
fn a_superseded_concept_still_stable_raises_a_warning_defect() {
    let dir = bundle(
        "without-deprecated",
        &[
            ("a.md", &concept("superseded_by: b.md\n")),
            ("b.md", &concept("")),
        ],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", SUPERSESSION_DEFECT), vec![2]);
}

#[test]
fn a_passed_review_date_on_a_stable_concept_raises_a_warning_stale() {
    let dir = bundle("stale", &[("a.md", &concept("stale_after: 2026-01-01\n"))]);
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", STALE), vec![2]);
}

#[test]
fn an_unparseable_review_date_raises_an_error_stale_marked_malformed() {
    let dir = bundle(
        "malformed-date",
        &[("a.md", &concept("stale_after: not-a-date\n"))],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", STALE), vec![1]);
    let item = report
        .queue
        .iter()
        .find(|item| item.concept == "a.md" && item.reason == STALE)
        .unwrap();
    assert!(
        item.evidence
            .iter()
            .any(|(k, v)| k == "malformed" && v == "true")
    );
}

#[test]
fn a_malformed_verification_event_raises_the_new_reason() {
    let dir = bundle(
        "malformed-event",
        &[("a.md", &concept("verified:\n  - by: \"human:ada\"\n"))],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", MALFORMED_VERIFICATION), vec![1]);
}

#[test]
fn a_missing_source_file_raises_a_provenance_gap() {
    let dir = bundle(
        "missing-source",
        &[(
            "a.md",
            &concept("sources:\n  - id: data\n    resource: data/absent.csv\n"),
        )],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", PROVENANCE_GAP), vec![1]);
}

#[test]
fn a_drifted_source_hash_raises_a_provenance_gap() {
    let dir = bundle(
        "source-drift",
        &[
            (
                "a.md",
                &concept(
                    "sources:\n  - id: data\n    resource: data/present.csv\n    sha256: \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
                ),
            ),
            ("data/present.csv", "real content\n"),
        ],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", PROVENANCE_GAP), vec![1]);
}

#[test]
fn an_unresolved_footnote_citation_raises_a_provenance_gap() {
    let dir = bundle(
        "footnote",
        &[(
            "a.md",
            "---\ntype: Note\n---\nA claim.[^1]\n\n[^1]: data/absent.csv\n",
        )],
    );
    let report = pass(&dir);
    assert_eq!(priorities(&report, "a.md", PROVENANCE_GAP), vec![1]);
}

#[test]
fn a_lapsed_verification_queues_nothing_of_its_own_on_a_first_pass() {
    let dir = bundle(
        "lapsed",
        &[(
            "a.md",
            &concept(
                "generated:\n  at: \"2026-11-01T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-10-01T00:00:00Z\"\n",
            ),
        )],
    );
    let report = pass(&dir);
    assert!(!any_defect(&report, "a.md"));
}

/// An attested computation concept in the publisher's own shape,
/// claiming the given result for a computation giving three.
fn computation_concept(claimed: &str) -> String {
    format!(
        "---\ntype: Attested Computation\ntitle: Row count\nstatus: stable\nruntime: python\n---\n\n# Computation\n\n```python\nresult = len([1, 2, 3])\n```\n\n# Claimed result\n\nThe attested result claimed for this computation is {claimed}.\n"
    )
}

#[test]
fn a_mismatched_attestation_raises_an_attestation_defect_when_asked() {
    let dir = bundle("attest-mismatch", &[("a.md", &computation_concept("4"))]);
    let report = pass_attesting(&dir);
    assert_eq!(priorities(&report, "a.md", ATTESTATION_DEFECT), vec![1]);
}

#[test]
fn a_mismatched_attestation_raises_nothing_by_default() {
    let dir = bundle("attest-off", &[("a.md", &computation_concept("4"))]);
    let report = pass(&dir);
    assert!(!any_defect(&report, "a.md"));
}

#[test]
fn a_matching_attestation_raises_nothing_when_asked() {
    let dir = bundle("attest-match", &[("a.md", &computation_concept("3"))]);
    let report = pass_attesting(&dir);
    assert!(!any_defect(&report, "a.md"));
}

#[test]
fn a_claim_no_computation_supports_raises_an_attestation_defect_when_asked() {
    let dir = bundle(
        "attest-unattested",
        &[(
            "a.md",
            "---\ntype: Attested Computation\ntitle: Row count\nstatus: stable\nruntime: python\n---\n\n# Claimed result\n\nThe attested result claimed for this computation is 3.\n",
        )],
    );
    let report = pass_attesting(&dir);
    assert_eq!(priorities(&report, "a.md", ATTESTATION_DEFECT), vec![1]);
}

#[test]
fn a_healthy_concept_raises_no_defect() {
    let dir = bundle(
        "clean",
        &[(
            "a.md",
            &concept(
                "stale_after: 2027-01-01\ngenerated:\n  at: \"2026-11-01T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-20T00:00:00Z\"\n",
            ),
        )],
    );
    let report = pass(&dir);
    assert!(!any_defect(&report, "a.md"));
}
