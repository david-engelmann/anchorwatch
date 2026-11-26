//! Integration tests for the upkeep pass over a fixture bundle.
//!
//! The fixture exercises the queue vocabulary end to end: a stale
//! concept, a concept with no review date, a dangling supersession,
//! a type-stripped concept known to the manifest, and a tier drop
//! observed across two passes. Determinism is asserted by running
//! the same pass twice and comparing the reports byte for byte.

use std::io::Write;
use std::path::{Path, PathBuf};

use anchorwatch_core::perishables::PerishablesAuditor;
use anchorwatch_core::queue::{
    INDEX_DRIFT, NO_REVIEW_DATE, PROVENANCE_GAP, QueueState, REGISTRY_DRIFT, STALE,
    SUPERSESSION_DEFECT, TYPE_MISSING,
};
use anchorwatch_core::upkeep::{Mode, run_pass};

fn write_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
}

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anchorwatch-pass-{name}-{}", std::process::id()));
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
        "concepts/c.md",
        "---\ntype: Note\ntitle: \"C\"\nsources:\n  - resource: \"refs/missing.md\"\n---\nbody c\n",
    );
    write_file(
        &dir,
        "concepts/stripped.md",
        "# Stripped\n\nThis file lost its frontmatter.\n",
    );
    write_file(
        &dir,
        ".recension/state.json",
        "{\"migrated_at\": \"2026-11-20T21:45:00Z\", \"concepts\": {\"concepts/a.md\": \"Note\", \"concepts/b.md\": \"Note\", \"concepts/broken.md\": \"Note\", \"concepts/c.md\": \"Note\", \"concepts/stripped.md\": \"Note\"}}",
    );
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Fixture bundle\"\n---\n\n# Fixture bundle\n\n# concepts\n\n* [A](concepts/a.md)\n* [B](concepts/b.md)\n* [Broken](concepts/broken.md)\n* [C](concepts/c.md)\n",
    );
    write_file(
        &dir,
        "concepts/index.md",
        "# concepts\n\n* [A](a.md)\n* [B](b.md)\n* [Broken](broken.md)\n* [C](c.md)\n",
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
    let report = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(reasons_for(&report, "concepts/a.md").contains(&STALE.to_string()));
    assert!(reasons_for(&report, "concepts/b.md").contains(&NO_REVIEW_DATE.to_string()));
    assert!(reasons_for(&report, "concepts/broken.md").contains(&SUPERSESSION_DEFECT.to_string()));
    assert!(reasons_for(&report, "concepts/stripped.md").contains(&TYPE_MISSING.to_string()));
    assert!(reasons_for(&report, "concepts/c.md").contains(&PROVENANCE_GAP.to_string()));
    // The fixture carries no claim registry, so the registry check
    // stays silent.
    assert!(
        !report
            .queue
            .iter()
            .any(|item| item.reason == REGISTRY_DRIFT)
    );
    // The indexes list every concept they should, so no drift.
    assert!(
        !report.queue.iter().any(|item| item.reason == INDEX_DRIFT),
        "unexpected index drift: {:?}",
        report.queue
    );
    // A dry run writes nothing.
    assert!(!dir.join(".recension").join("queue.json").exists());
}

#[test]
fn two_runs_over_the_same_bundle_are_byte_identical() {
    let dir = fixture("determinism");
    let first = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    let second = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first.to_markdown(), second.to_markdown());
}

#[test]
fn apply_keeps_the_log_newest_first() {
    let dir = fixture("logorder");
    write_file(
        &dir,
        "log.md",
        "# Bundle Update Log\n\n## 2026-11-19\n* **Creation**: Bundle created.\n",
    );
    run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    let log = std::fs::read_to_string(dir.join("log.md")).unwrap();
    assert!(log.starts_with("# Bundle Update Log"));
    let new_group = log.find("## 2026-11-21").unwrap();
    let old_group = log.find("## 2026-11-19").unwrap();
    assert!(new_group < old_group, "log not newest first:\n{log}");
    // A second pass on the same date joins the existing group
    // instead of opening a new one or landing in the older group.
    run_pass(
        &dir,
        "2026-11-21T12:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    let log = std::fs::read_to_string(dir.join("log.md")).unwrap();
    assert_eq!(log.matches("## 2026-11-21").count(), 1);
    let first_entry = log.find("Pass ").unwrap();
    let second_entry = log.rfind("Pass ").unwrap();
    assert!(first_entry < second_entry);
    assert!(second_entry < log.find("## 2026-11-19").unwrap());
    // A backfilled date lands between the newer and older groups.
    run_pass(
        &dir,
        "2026-11-20T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    let log = std::fs::read_to_string(dir.join("log.md")).unwrap();
    let d21 = log.find("## 2026-11-21").unwrap();
    let d20 = log.find("## 2026-11-20").unwrap();
    let d19 = log.find("## 2026-11-19").unwrap();
    assert!(d21 < d20 && d20 < d19, "log groups out of order:\n{log}");
}

fn repair_fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anchorwatch-pass-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/keyless.md",
        "---\ntitle: \"Keyless\"\n---\nbody keyless\n",
    );
    write_file(
        &dir,
        "concepts/blockless.md",
        "# Blockless\n\nThis file lost its whole frontmatter block.\n",
    );
    write_file(
        &dir,
        ".recension/state.json",
        "{\"concepts\": {\"concepts/keyless.md\": \"Note\", \"concepts/blockless.md\": \"Note\"}}",
    );
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Repair fixture\"\n---\n\n# Repair fixture\n",
    );
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    dir
}

#[test]
fn apply_restores_a_stripped_type_key_and_leaves_the_blockless_file() {
    let dir = repair_fixture("typerepair");
    let dry = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(reasons_for(&dry, "concepts/keyless.md").contains(&TYPE_MISSING.to_string()));
    assert!(reasons_for(&dry, "concepts/blockless.md").contains(&TYPE_MISSING.to_string()));
    let blockless_before = std::fs::read_to_string(dir.join("concepts/blockless.md")).unwrap();

    let applied = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    assert!(
        applied
            .actions
            .iter()
            .any(|a| a == "type restored from the manifest: concepts/keyless.md (Note)"),
        "actions: {:?}",
        applied.actions
    );
    // The item was raised by this pass; it closes on the next one.
    assert!(reasons_for(&applied, "concepts/keyless.md").contains(&TYPE_MISSING.to_string()));
    let repaired = std::fs::read_to_string(dir.join("concepts/keyless.md")).unwrap();
    assert_eq!(
        repaired,
        "---\ntype: Note\ntitle: \"Keyless\"\n---\nbody keyless\n"
    );
    // A file that lost the whole block is left exactly as found.
    assert_eq!(
        std::fs::read_to_string(dir.join("concepts/blockless.md")).unwrap(),
        blockless_before
    );

    let second = run_pass(
        &dir,
        "2026-11-22T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(!reasons_for(&second, "concepts/keyless.md").contains(&TYPE_MISSING.to_string()));
    assert!(reasons_for(&second, "concepts/blockless.md").contains(&TYPE_MISSING.to_string()));
}

#[test]
fn a_legacy_queue_migrates_to_the_dot_directory() {
    let dir = fixture("migration");
    // A queue written by an older pass, in the legacy home, with a
    // first-raised run the merge must preserve across the move.
    write_file(
        &dir,
        "upkeep/queue.json",
        "{\"as_of\": \"2026-11-20T00:00:00Z\", \"items\": [{\"concept\": \"concepts/b.md\", \"evidence\": {}, \"first_raised\": \"run-legacy00000\", \"last_confirmed\": \"run-legacy00000\", \"priority\": 2, \"reason\": \"NO REVIEW DATE\", \"state\": \"open\"}], \"run_id\": \"run-legacy00000\"}",
    );
    write_file(&dir, "upkeep/queue.md", "# Re-verification queue\n");
    let report = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    let item = report
        .queue
        .iter()
        .find(|item| item.concept == "concepts/b.md" && item.reason == NO_REVIEW_DATE)
        .unwrap();
    assert_eq!(item.first_raised, "run-legacy00000");
    assert!(dir.join(".recension").join("queue.json").exists());
    assert!(dir.join(".recension").join("queue.md").exists());
    assert!(!dir.join("upkeep").join("queue.json").exists());
    assert!(!dir.join("upkeep").join("queue.md").exists());
    assert!(
        report
            .actions
            .iter()
            .any(|a| a == "legacy queue files under upkeep/ removed after the move to .recension/"),
        "actions: {:?}",
        report.actions
    );
    // The migrated file itself carries the preserved first run.
    let written = std::fs::read_to_string(dir.join(".recension").join("queue.json")).unwrap();
    assert!(written.contains("run-legacy00000"));
}

#[test]
fn a_claim_registry_is_checked_against_the_bundle() {
    let dir = fixture("registry");
    // Discovered by shape at an unremarkable address, never by name.
    write_file(
        &dir,
        "claims.json",
        "{\"claims\": [{\"id\": \"claim-1\", \"concept\": \"concepts/a.md\"}, {\"id\": \"claim-2\", \"concept\": \"concepts/gone.md\"}, {\"id\": \"claim-3\", \"concept\": \"concepts/b.md\", \"supersedes\": [\"claim-1\", \"claim-9\"]}, {\"id\": \"claim-3\", \"concept\": \"concepts/b.md\"}]}",
    );
    let report = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n == "claim registry checked: claims.json (4 claims)"),
        "notes: {:?}",
        report.notes
    );
    let drift: Vec<&anchorwatch_core::queue::QueueItem> = report
        .queue
        .iter()
        .filter(|item| item.reason == REGISTRY_DRIFT)
        .collect();
    assert_eq!(drift.len(), 2, "drift items: {drift:?}");
    let dangling = drift.iter().find(|item| item.concept == "claim-2").unwrap();
    assert_eq!(dangling.priority, 1);
    assert!(
        dangling
            .evidence
            .contains(&("kind".to_string(), "dangling_concept".to_string()))
    );
    assert!(
        dangling
            .evidence
            .contains(&("concept".to_string(), "concepts/gone.md".to_string()))
    );
    let tangled = drift.iter().find(|item| item.concept == "claim-3").unwrap();
    assert!(
        tangled
            .evidence
            .contains(&("kind".to_string(), "dangling_edge".to_string()))
    );
    assert!(
        tangled
            .evidence
            .contains(&("kind".to_string(), "duplicate_id".to_string()))
    );
    assert!(
        tangled
            .evidence
            .contains(&("supersedes".to_string(), "claim-9".to_string()))
    );
}

#[test]
fn a_near_miss_registry_is_named_not_passed_over() {
    // Register R1-04. A file whose claims entries fail the entry
    // shape was silently no candidate at all, so the pass said
    // nothing and the silence read as a clean result. The pass now
    // names the file in a note and still does not check it.
    let dir = fixture("registry-near-miss");
    write_file(
        &dir,
        "claims.json",
        "{\"claims\": [{\"id\": \"claim-1\", \"concept\": \"concepts/a.md\"}, {\"id\": \"claim-2\"}]}",
    );
    let report = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("was not checked as a registry: claims.json")),
        "notes: {:?}",
        report.notes
    );
    assert!(
        !report
            .notes
            .iter()
            .any(|n| n.starts_with("claim registry checked")),
        "notes: {:?}",
        report.notes
    );
    assert!(
        !report
            .queue
            .iter()
            .any(|item| item.reason == REGISTRY_DRIFT),
        "a near miss is reported, never checked"
    );
}

#[test]
fn two_claim_registries_are_reported_not_guessed() {
    let dir = fixture("registry-ambiguous");
    let registry = "{\"claims\": [{\"id\": \"claim-1\", \"concept\": \"concepts/a.md\"}]}";
    write_file(&dir, "claims.json", registry);
    write_file(&dir, ".recension/claims-copy.json", registry);
    let report = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.starts_with("multiple claim registry candidates found, none checked")),
        "notes: {:?}",
        report.notes
    );
    assert!(
        !report
            .queue
            .iter()
            .any(|item| item.reason == REGISTRY_DRIFT)
    );
}

#[test]
fn a_dash_bullet_index_is_a_link_list_not_prose() {
    // Register R1-01. An index written with dash bullets is the
    // same furniture as the engine's own star form, and the
    // migrator's prose test has always exempted both. Before the
    // fix the pass read this index as hand-written prose, left it
    // untouched in apply mode, and its drift item could never
    // close.
    let dir = std::env::temp_dir().join(format!("anchorwatch-pass-dash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/a.md",
        "---\ntype: Note\ntitle: \"A\"\nstale_after: 2027-01-01\n---\nbody a\n",
    );
    write_file(
        &dir,
        "concepts/b.md",
        "---\ntype: Note\ntitle: \"B\"\nstale_after: 2027-01-01\n---\nbody b\n",
    );
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Fixture bundle\"\n---\n\n# Fixture bundle\n\n# concepts\n\n* [A](concepts/a.md)\n* [B](concepts/b.md)\n",
    );
    write_file(&dir, "concepts/index.md", "# concepts\n\n- [A](a.md)\n");
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    let report = run_pass(
        &dir,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    let item = report
        .queue
        .iter()
        .find(|item| item.concept == "concepts/index.md" && item.reason == INDEX_DRIFT)
        .expect("the dash index drifts from its directory");
    assert!(
        item.evidence
            .iter()
            .any(|(k, v)| k == "hand_written_prose" && v == "false"),
        "evidence: {:?}",
        item.evidence
    );
    assert!(
        report
            .actions
            .iter()
            .any(|a| a == "index regenerated: concepts/index.md"),
        "actions: {:?}",
        report.actions
    );
    let regenerated = std::fs::read_to_string(dir.join("concepts/index.md")).unwrap();
    assert!(regenerated.contains("* [B](b.md)"));
    let second = run_pass(
        &dir,
        "2026-11-24T01:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(
        !second
            .queue
            .iter()
            .any(|item| item.concept == "concepts/index.md" && item.reason == INDEX_DRIFT),
        "the regenerated index no longer drifts"
    );
}

#[test]
fn state_files_carry_paths_with_commas() {
    // Register R1-02. Two of the narrow text scans the state
    // readers used before the unification split entries on commas,
    // so a concept path carrying one silently fell out of the
    // manifest and the pass state, and the queue reader is unified
    // with them on the one parser. This fixture runs such a path
    // through all three readers: the type guard reads it in the
    // manifest, the tier baseline reads it in the pass state, and
    // a hand-set waiver on it survives the queue round trip.
    let dir = std::env::temp_dir().join(format!("anchorwatch-pass-comma-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/a,b.md",
        "---\ntype: Note\ntitle: \"A B\"\ngenerated:\n  at: \"2026-11-10T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-12T00:00:00Z\"\n---\nbody\n",
    );
    write_file(
        &dir,
        "concepts/stripped,x.md",
        "# Stripped\n\nNo frontmatter.\n",
    );
    write_file(
        &dir,
        ".recension/state.json",
        "{\"concepts\": {\"concepts/a,b.md\": \"Note\", \"concepts/stripped,x.md\": \"Note\"}}",
    );
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Fixture bundle\"\n---\n\n# Fixture bundle\n\n# concepts\n\n* [A B](concepts/a,b.md)\n* [Stripped](concepts/stripped,x.md)\n",
    );
    write_file(
        &dir,
        "concepts/index.md",
        "# concepts\n\n* [A B](a,b.md)\n* [Stripped](stripped,x.md)\n",
    );
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    let first = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    assert!(
        reasons_for(&first, "concepts/stripped,x.md").contains(&TYPE_MISSING.to_string()),
        "the manifest reader carried the comma path"
    );
    // A human waives the comma concept's review-date item.
    let queue_path = dir.join(".recension").join("queue.json");
    let queue_text = std::fs::read_to_string(&queue_path).unwrap();
    let at = queue_text.find("\"concepts/a,b.md\"").unwrap();
    let state_at = queue_text[at..].find("\"state\": \"open\"").unwrap() + at;
    let mut queue_text = queue_text;
    queue_text.replace_range(
        state_at..state_at + "\"state\": \"open\"".len(),
        "\"state\": \"waived\"",
    );
    std::fs::write(&queue_path, queue_text).unwrap();
    // The concept is regenerated after its verification.
    write_file(
        &dir,
        "concepts/a,b.md",
        "---\ntype: Note\ntitle: \"A B\"\ngenerated:\n  at: \"2026-11-20T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-12T00:00:00Z\"\n---\nbody, changed\n",
    );
    let second = run_pass(
        &dir,
        "2026-11-22T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    let waived = second
        .queue
        .iter()
        .find(|item| item.concept == "concepts/a,b.md" && item.reason == NO_REVIEW_DATE)
        .expect("the comma concept's item survives the queue round trip");
    assert_eq!(waived.state, QueueState::Waived);
    assert_eq!(waived.first_raised, first.run_id);
    assert!(
        reasons_for(&second, "concepts/a,b.md").contains(&"TIER DROP".to_string()),
        "the pass state reader carried the comma path"
    );
}

#[test]
fn the_markdown_report_names_its_auditor_and_lists_its_actions() {
    // The thirteenth register's repair. The human form of the
    // report listed findings without naming the auditor that
    // produced them and omitted the pass's own actions entirely,
    // so an applying pass's writes were invisible in the form a
    // human reviews. Both now stand in the Markdown as they
    // stand in the JSON.
    let dir = fixture("markdown-report");
    let dry = run_pass(
        &dir,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    let markdown = dry.to_markdown();
    assert!(
        markdown.contains("Auditor perishables (schema 2)"),
        "markdown: {markdown}"
    );
    assert!(
        markdown.contains("- dry-run: no files written"),
        "markdown: {markdown}"
    );
    let applied = run_pass(
        &dir,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    let markdown = applied.to_markdown();
    assert!(
        markdown.contains("- pass state recorded at .recension/pass-state.json"),
        "markdown: {markdown}"
    );
}

#[test]
fn an_unclosed_frontmatter_block_is_named_in_the_notes() {
    // Register R2-06, in the narrowed form the convergence left:
    // a block that never closes is read as written, its type and
    // review date standing, and the pass names the defect in its
    // notes rather than absorbing it silently.
    let dir =
        std::env::temp_dir().join(format!("anchorwatch-pass-unclosed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/a.md",
        "---\ntype: Note\ntitle: \"A\"\nstale_after: 2027-01-01\nbody without a closing marker\n",
    );
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Fixture bundle\"\n---\n\n# Fixture bundle\n\n# concepts\n\n* [A](concepts/a.md)\n",
    );
    write_file(&dir, "concepts/index.md", "# concepts\n\n* [A](a.md)\n");
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    let report = run_pass(
        &dir,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("concepts/a.md") && note.contains("never closes")),
        "notes: {:?}",
        report.notes
    );
    // The readings stand: the type was read, so no TYPE MISSING,
    // and the review date was read, so no NO REVIEW DATE.
    assert!(
        !report
            .queue
            .iter()
            .any(|item| item.concept == "concepts/a.md"
                && (item.reason == TYPE_MISSING || item.reason == NO_REVIEW_DATE)),
        "queue: {:?}",
        report.queue
    );
}

#[test]
fn a_review_date_that_does_not_exist_is_malformed_not_stale() {
    // Register R1-03. Before the calendar check, the thirty first
    // of February parsed as a March instant, so the freshness
    // finding was an ordinary passed date. A date that does not
    // exist is malformed, and the queue item must say so.
    let dir = std::env::temp_dir().join(format!("anchorwatch-pass-feb31-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/a.md",
        "---\ntype: Note\ntitle: \"A\"\nstale_after: 2026-02-31\n---\nbody a\n",
    );
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Fixture bundle\"\n---\n\n# Fixture bundle\n\n# concepts\n\n* [A](concepts/a.md)\n",
    );
    write_file(&dir, "concepts/index.md", "# concepts\n\n* [A](a.md)\n");
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    let report = run_pass(
        &dir,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    let item = report
        .queue
        .iter()
        .find(|item| item.concept == "concepts/a.md" && item.reason == STALE)
        .expect("the impossible date raises a stale item");
    assert!(
        item.evidence
            .iter()
            .any(|(k, v)| k == "malformed" && v == "true"),
        "evidence: {:?}",
        item.evidence
    );
    assert!(
        item.evidence
            .iter()
            .any(|(k, v)| k == "rule_id" && v == "UNPARSEABLE_STALE_AFTER"),
        "evidence: {:?}",
        item.evidence
    );
}

#[test]
fn a_crlf_root_index_keeps_its_frontmatter_when_regenerated() {
    // Register R2-01. The root index's frontmatter preservation
    // sliced on line-feed delimiters only, so regenerating a
    // carriage-return bundle's drifted root index replaced its
    // declared frontmatter with the fallback block.
    let dir = std::env::temp_dir().join(format!("anchorwatch-pass-crlf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/a.md",
        "---\ntype: Note\ntitle: \"A\"\nstale_after: 2027-01-01\n---\nbody a\n",
    );
    write_file(
        &dir,
        "index.md",
        "---\r\nokf_version: \"0.3\"\r\ntitle: \"CRLF bundle\"\r\nlicense: \"MIT\"\r\n---\r\n\r\n# CRLF bundle\r\n",
    );
    write_file(&dir, "concepts/index.md", "# concepts\n\n* [A](a.md)\n");
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    let report = run_pass(
        &dir,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    assert!(
        report
            .actions
            .iter()
            .any(|a| a == "index regenerated: index.md"),
        "actions: {:?}",
        report.actions
    );
    let regenerated = std::fs::read_to_string(dir.join("index.md")).unwrap();
    assert!(
        regenerated.contains("license: \"MIT\""),
        "declared frontmatter preserved: {regenerated}"
    );
    assert!(regenerated.contains("title: \"CRLF bundle\""));
    assert!(!regenerated.contains("title: \"Bundle index\""));
    assert!(regenerated.contains("* [A](concepts/a.md)"));
}

#[test]
fn an_index_over_no_concepts_is_reported_and_never_rewritten() {
    // Register R1-05. A directory holding no concepts can still
    // carry an index, over assets or anything else the engine has
    // no model of. Its drift is reported, but apply mode must not
    // regenerate it into an empty concept listing.
    let dir = std::env::temp_dir().join(format!("anchorwatch-pass-assets-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "concepts/a.md",
        "---\ntype: Note\ntitle: \"A\"\nstale_after: 2027-01-01\n---\nbody a\n",
    );
    write_file(&dir, "assets/data.txt", "the asset bytes\n");
    write_file(&dir, "assets/index.md", "# assets\n\n* [Data](data.txt)\n");
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: \"Fixture bundle\"\n---\n\n# Fixture bundle\n\n# concepts\n\n* [A](concepts/a.md)\n",
    );
    write_file(&dir, "concepts/index.md", "# concepts\n\n* [A](a.md)\n");
    write_file(&dir, "log.md", "# Bundle Update Log\n");
    let report = run_pass(
        &dir,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    let item = report
        .queue
        .iter()
        .find(|item| item.concept == "assets/index.md" && item.reason == INDEX_DRIFT)
        .expect("the asset index drift is reported");
    assert!(
        item.evidence
            .iter()
            .any(|(k, v)| k == "expected_links" && v == "0"),
        "evidence: {:?}",
        item.evidence
    );
    assert!(
        report.actions.iter().any(|a| {
            a == "index left untouched, its directory holds no concepts: assets/index.md"
        }),
        "actions: {:?}",
        report.actions
    );
    let untouched = std::fs::read_to_string(dir.join("assets/index.md")).unwrap();
    assert_eq!(untouched, "# assets\n\n* [Data](data.txt)\n");
}

#[test]
fn a_second_pass_observes_a_tier_drop() {
    let dir = fixture("tierdrop");
    let first = run_pass(
        &dir,
        "2026-11-21T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::Apply,
    )
    .unwrap();
    assert_eq!(first.concept_count, 4);
    assert!(dir.join(".recension").join("queue.json").exists());
    assert!(dir.join(".recension").join("pass-state.json").exists());
    // The concept is regenerated after its verification, so the
    // previously current human event lapses.
    write_file(
        &dir,
        "concepts/b.md",
        "---\ntype: Note\ntitle: \"B\"\ngenerated:\n  at: \"2026-11-20T00:00:00Z\"\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-12T00:00:00Z\"\n---\nbody b, changed\n",
    );
    let second = run_pass(
        &dir,
        "2026-11-22T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    let reasons = reasons_for(&second, "concepts/b.md");
    assert!(
        reasons.contains(&"TIER DROP".to_string()),
        "reasons: {reasons:?}"
    );
    assert!(
        reasons.contains(&"LAPSED VERIFICATION".to_string()),
        "reasons: {reasons:?}"
    );
    // Tier drops from a human-reviewed tier sort first.
    assert_eq!(second.queue[0].concept, "concepts/b.md");
    assert_eq!(second.queue[0].reason, "TIER DROP");
}
