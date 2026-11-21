//! Integration tests for the upkeep pass over a fixture bundle.
//!
//! The fixture exercises the queue vocabulary end to end: a stale
//! concept, a concept with no review date, a dangling supersession,
//! a type-stripped concept known to the manifest, and a tier drop
//! observed across two passes. Determinism is asserted by running
//! the same pass twice and comparing the reports byte for byte.

use std::io::Write;
use std::path::{Path, PathBuf};

use anchorwatch_core::auditor::StubAuditor;
use anchorwatch_core::queue::{INDEX_DRIFT, NO_REVIEW_DATE, STALE, SUPERSESSION_DEFECT, TYPE_MISSING};
use anchorwatch_core::upkeep::{run_pass, Mode};

fn write_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
}

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "anchorwatch-pass-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/a.md",
        "---\ntype: Note\ntitle: \"A\"\nstale_after: 2026-11-01\n---\nbody a\n",
    );
    write_file(
        &dir,
        "concepts/b.md",
        "---\ntype: Note\ntitle: \"B\"\ngenerated:\n  at: \"2026-11-10T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-12T00:00:00Z\"\n---\nbody b\n",
    );
    write_file(
        &dir,
        "concepts/broken.md",
        "---\ntype: Note\ntitle: \"Broken\"\nstatus: deprecated\nsuperseded_by: concepts/missing.md\n---\nbody broken\n",
    );
    write_file(
        &dir,
        "concepts/stripped.md",
        "# Stripped\n\nThis file lost its frontmatter.\n",
    );
    write_file(
        &dir,
        ".recension/state.json",
        "{\"migrated_at\": \"2026-11-20T21:45:00Z\", \"concepts\": {\"concepts/a.md\": \"Note\", \"concepts/b.md\": \"Note\", \"concepts/broken.md\": \"Note\", \"concepts/stripped.md\": \"Note\"}}",
    );
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Fixture bundle\"\n---\n\n# Fixture bundle\n\n# concepts\n\n* [A](concepts/a.md)\n* [B](concepts/b.md)\n* [Broken](concepts/broken.md)\n",
    );
    write_file(
        &dir,
        "concepts/index.md",
        "# concepts\n\n* [A](a.md)\n* [B](b.md)\n* [Broken](broken.md)\n",
    );
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    dir
}

fn reasons_for(report: &anchorwatch_core::upkeep::PassReport, concept: &str) -> Vec<String> {
    report
        .queue
        .iter()
        .filter(|item| item.concept == concept)
        .map(|item| item.reason.clone())
        .collect()
}

#[test]
fn the_fixture_raises_the_expected_queue() {
    let dir = fixture("basic");
    let report = run_pass(&dir, "2026-11-21T00:00:00Z", &StubAuditor, Mode::DryRun).unwrap();
    assert!(reasons_for(&report, "concepts/a.md").contains(&STALE.to_string()));
    assert!(reasons_for(&report, "concepts/b.md").contains(&NO_REVIEW_DATE.to_string()));
    assert!(
        reasons_for(&report, "concepts/broken.md").contains(&SUPERSESSION_DEFECT.to_string())
    );
    assert!(
        reasons_for(&report, "concepts/stripped.md").contains(&TYPE_MISSING.to_string())
    );
    // The indexes list every concept they should, so no drift.
    assert!(
        !report
            .queue
            .iter()
            .any(|item| item.reason == INDEX_DRIFT),
        "unexpected index drift: {:?}",
        report.queue
    );
    // A dry run writes nothing.
    assert!(!dir.join("upkeep").join("queue.json").exists());
}

#[test]
fn two_runs_over_the_same_bundle_are_byte_identical() {
    let dir = fixture("determinism");
    let first = run_pass(&dir, "2026-11-21T00:00:00Z", &StubAuditor, Mode::DryRun).unwrap();
    let second = run_pass(&dir, "2026-11-21T00:00:00Z", &StubAuditor, Mode::DryRun).unwrap();
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first.to_markdown(), second.to_markdown());
}

#[test]
fn a_second_pass_observes_a_tier_drop() {
    let dir = fixture("tierdrop");
    let first = run_pass(&dir, "2026-11-21T00:00:00Z", &StubAuditor, Mode::Apply).unwrap();
    assert_eq!(first.concept_count, 3);
    assert!(dir.join("upkeep").join("queue.json").exists());
    assert!(dir.join(".recension").join("pass-state.json").exists());
    // The concept is regenerated after its verification, so the
    // previously current human event lapses.
    write_file(
        &dir,
        "concepts/b.md",
        "---\ntype: Note\ntitle: \"B\"\ngenerated:\n  at: \"2026-11-20T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-12T00:00:00Z\"\n---\nbody b, changed\n",
    );
    let second = run_pass(&dir, "2026-11-22T00:00:00Z", &StubAuditor, Mode::DryRun).unwrap();
    let reasons = reasons_for(&second, "concepts/b.md");
    assert!(reasons.contains(&"TIER DROP".to_string()), "reasons: {reasons:?}");
    assert!(
        reasons.contains(&"LAPSED VERIFICATION".to_string()),
        "reasons: {reasons:?}"
    );
    // Tier drops from a human-reviewed tier sort first.
    assert_eq!(second.queue[0].concept, "concepts/b.md");
    assert_eq!(second.queue[0].reason, "TIER DROP");
}
