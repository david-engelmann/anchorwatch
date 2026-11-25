//! Integration tests for the migrator over a fixture Muse
//! memory tree: the conversion itself, the ledger it ships, the
//! two gates, determinism, and the migrated bundle standing up
//! under the upkeep pass.

use std::io::Write;
use std::path::{Path, PathBuf};

use anchorwatch_core::auditor::StubAuditor;
use anchorwatch_core::migrate::{ClaudeMemoryProfile, Disposition, run_migration};
use anchorwatch_core::queue::NO_REVIEW_DATE;
use anchorwatch_core::upkeep::{Mode, run_pass};

fn write_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
}

fn fixture(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("anchorwatch-migrate-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The fixture encodes the real tree's shape, with the areas
    // nested under memory/ and MEMORY.md at the root, because a
    // fixture in the wrong shape certifies the wrong profile.
    write_file(
        &dir,
        "memory/people/ada.md",
        "---\ndisplay_name: \"Ada Lovelace\"\nsummary: \"First programmer\"\nrank: 1\nfirst_name: \"Ada\"\nlast_name: \"Lovelace\"\nupdated: \"2026-09-01\"\n---\nBody about the analytical engine. This supersedes the earlier note.\n- [ ] ask about the engine\nSee MEMORY.md#L38 for the ruling.\n",
    );
    write_file(
        &dir,
        "memory/people/INDEX.md",
        "# People\n\nClosest first.\n",
    );
    write_file(
        &dir,
        "memory/groups/team.md",
        "---\ndisplay_name: \"Team\"\nsummary: \"The group\"\n---\nGroup body.\n",
    );
    write_file(
        &dir,
        "MEMORY.md",
        "# Curated Memory\n\n## Rulings\n\nA ruling stands here.\n",
    );
    write_file(
        &dir,
        "memory/2026-09-16.md",
        "# 2026-09-16\n\nAn entry. It was superseded by a later entry.\n\n## Evening\n\nA later entry.\n",
    );
    write_file(&dir, "memory/bank/bank.md", "- a distilled bullet\n");
    write_file(&dir, "notes/random.md", "# Random Notes\n\nLoose text.\n");
    dir
}

fn tree_bytes(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn the_fixture_tree_converts_with_an_honest_ledger() {
    let source = fixture("basic");
    let out = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-basic-out-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    let report =
        run_migration(&ClaudeMemoryProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 7);
    assert!(report.reconciliation_ok);
    // The ledger is honest and the load-bearing gate fails
    // visibly: prose supersession and freshness are lost.
    assert!(!report.honesty_gate_failed);
    assert!(report.load_bearing_gate_failed);
    assert!(report.gate_failed);
    assert_eq!(report.entries.len(), 11);
    let supersession = report
        .entries
        .iter()
        .find(|e| e.construct == "prose supersession markers")
        .unwrap();
    assert_eq!(supersession.count, 2);
    assert_eq!(supersession.disposition, Disposition::Lost);
    assert!(supersession.load_bearing);
    let freshness = report
        .entries
        .iter()
        .find(|e| e.construct == "freshness expectations")
        .unwrap();
    assert_eq!(freshness.count, 7);
    // Splitting is built, so both split files now map.
    for construct in ["curated memory file", "daily log files"] {
        let split = report
            .entries
            .iter()
            .find(|e| e.construct == construct)
            .unwrap();
        assert_eq!(split.disposition, Disposition::Mapped);
    }
    // The curated file split at its own heading, preamble kept.
    let rulings = std::fs::read_to_string(out.join("curated/01-rulings.md")).unwrap();
    assert!(rulings.contains("title: \"Rulings\""));
    assert!(rulings.contains("x-anchorwatch-source: \"MEMORY.md section 1\""));
    assert!(rulings.contains("## Rulings"));
    assert!(rulings.contains("A ruling stands here."));
    assert!(out.join("curated/00-preamble.md").exists());
    // The daily log split at its own heading too.
    let evening = std::fs::read_to_string(out.join("logs/2026-09-16-01-evening.md")).unwrap();
    assert!(evening.contains("## Evening"));
    assert!(out.join("logs/2026-09-16-00-preamble.md").exists());
    // The converted person carries the mapping and the extensions.
    let ada = std::fs::read_to_string(out.join("people/ada.md")).unwrap();
    assert!(ada.contains("type: \"Person\""));
    assert!(ada.contains("title: \"Ada Lovelace\""));
    assert!(ada.contains("x-muse-rank: 1"));
    assert!(ada.contains("x-muse-updated: \"2026-09-01\""));
    assert!(ada.contains("x-anchorwatch-source: \"memory/people/ada.md\""));
    assert!(ada.contains("analytical engine"));
    // The bundle furniture is all present.
    assert!(out.join("index.md").exists());
    assert!(out.join("people/index.md").exists());
    assert!(out.join("log.md").exists());
    assert!(out.join("LOSS-LEDGER.md").exists());
    assert!(out.join("loss-ledger.json").exists());
    let manifest = std::fs::read_to_string(out.join(".recension/state.json")).unwrap();
    assert!(manifest.contains("\"people/ada.md\": \"Person\""));
    assert!(manifest.contains("\"curated/01-rulings.md\": \"Curated Memory\""));
}

#[test]
fn two_runs_write_byte_identical_bundles() {
    let source = fixture("determinism");
    // Outputs live outside the source, so the second run walks the
    // same tree the first one did.
    let first_out =
        std::env::temp_dir().join(format!("anchorwatch-migrate-det1-{}", std::process::id()));
    let second_out =
        std::env::temp_dir().join(format!("anchorwatch-migrate-det2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&first_out);
    let _ = std::fs::remove_dir_all(&second_out);
    let first = run_migration(
        &ClaudeMemoryProfile,
        &source,
        &first_out,
        "2026-11-24T00:00:00Z",
    )
    .unwrap();
    let second = run_migration(
        &ClaudeMemoryProfile,
        &source,
        &second_out,
        "2026-11-24T00:00:00Z",
    )
    .unwrap();
    assert_eq!(first.run_id, second.run_id);
    assert_eq!(tree_bytes(&first_out), tree_bytes(&second_out));
}

#[test]
fn an_empty_tree_fails_the_honesty_gate() {
    let source =
        std::env::temp_dir().join(format!("anchorwatch-migrate-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&source);
    std::fs::create_dir_all(&source).unwrap();
    let out = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-empty-out-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    let report =
        run_migration(&ClaudeMemoryProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 0);
    assert!(report.entries.is_empty());
    assert!(report.honesty_gate_failed);
    assert!(report.gate_failed);
}

#[test]
fn an_output_overlapping_the_source_is_refused() {
    // Register R1-07. A migration writes its bundle at the
    // output, and a later run over the same source would ingest
    // that bundle as source material. The overlap is refused
    // before anything is written, in either direction.
    let dir = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-overlap-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "MEMORY.md",
        "# Curated Memory\n\n## Rulings\n\nBody.\n",
    );
    let inside = dir.join("bundle-out");
    let err = run_migration(&ClaudeMemoryProfile, &dir, &inside, "2026-11-24T00:00:00Z")
        .expect_err("an output inside the source is refused");
    assert!(err.contains("overlap"), "error: {err}");
    assert!(!inside.exists(), "nothing was written");
    write_file(
        &dir,
        "sub/MEMORY.md",
        "# Curated Memory\n\n## Rulings\n\nBody.\n",
    );
    let err = run_migration(
        &ClaudeMemoryProfile,
        &dir.join("sub"),
        &dir,
        "2026-11-24T00:00:00Z",
    )
    .expect_err("a source inside the output is refused");
    assert!(err.contains("overlap"), "error: {err}");
}

#[test]
fn a_non_empty_output_is_refused_and_an_empty_one_accepted() {
    // Register R2-05. A migration writes a complete bundle, so
    // writing into a directory that already holds files would
    // leave ghost concepts standing under a manifest that does
    // not name them. The refusal leaves the directory untouched;
    // an existing empty directory is the ordinary case.
    let dir = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-nonempty-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "MEMORY.md",
        "# Curated Memory\n\n## Rulings\n\nBody.\n",
    );
    let out = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-nonempty-out-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    write_file(&out, "stray.md", "# Stray\n");
    let err = run_migration(&ClaudeMemoryProfile, &dir, &out, "2026-11-24T00:00:00Z")
        .expect_err("a non-empty output is refused");
    assert!(err.contains("not empty"), "error: {err}");
    assert!(
        out.join("stray.md").exists(),
        "nothing was written or removed"
    );
    assert!(!out.join("LOSS-LEDGER.md").exists());
    let empty_out = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-empty-out2-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&empty_out);
    std::fs::create_dir_all(&empty_out).unwrap();
    let report = run_migration(
        &ClaudeMemoryProfile,
        &dir,
        &empty_out,
        "2026-11-24T00:00:00Z",
    )
    .unwrap();
    assert_eq!(report.concepts_written, 2);
}

#[test]
fn a_heading_inside_a_code_fence_does_not_split_a_section() {
    // Register R1-06. Section splitting used to break on any
    // heading-shaped line, including one inside a fenced code
    // sample, which cut the section in two and minted a concept
    // out of the sample's contents.
    let dir =
        std::env::temp_dir().join(format!("anchorwatch-migrate-fence-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "MEMORY.md",
        "# Curated Memory\n\n## Code sample\n\nText.\n\n```\n## Not a heading\nmore code\n```\n\nAfter.\n",
    );
    let out = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-fence-out-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    let report = run_migration(&ClaudeMemoryProfile, &dir, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 2);
    let section = std::fs::read_to_string(out.join("curated/01-code-sample.md")).unwrap();
    assert!(section.contains("## Not a heading"));
    assert!(section.contains("After."));
    assert!(!out.join("curated/02-not-a-heading.md").exists());
}

#[test]
fn area_profile_and_history_files_become_profile_concepts() {
    let dir =
        std::env::temp_dir().join(format!("anchorwatch-migrate-areas-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "memory/shopping/PROFILE.md",
        "# Shopping Profile\n\nSizes and preferences.\n",
    );
    write_file(
        &dir,
        "memory/travel/HISTORY.md",
        "# Travel History\n\nPast trips.\n",
    );
    let out = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-areas-out-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    let report = run_migration(&ClaudeMemoryProfile, &dir, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 2);
    let area = report
        .entries
        .iter()
        .find(|e| e.construct == "area profile and history files")
        .unwrap();
    assert_eq!(area.count, 2);
    let shopping = std::fs::read_to_string(out.join("profile/shopping-profile.md")).unwrap();
    assert!(shopping.contains("type: \"Profile\""));
    assert!(shopping.contains("title: \"Shopping Profile\""));
    assert!(out.join("profile/travel-history.md").exists());
}

#[test]
fn the_migrated_bundle_stands_up_under_an_upkeep_pass() {
    let source = fixture("upkeep");
    let out = std::env::temp_dir().join(format!(
        "anchorwatch-migrate-upkeep-out-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    run_migration(&ClaudeMemoryProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    let report = run_pass(&out, "2026-11-25T00:00:00Z", &StubAuditor, Mode::DryRun).unwrap();
    assert_eq!(report.concept_count, 7);
    // No drift, no defects: only the honest freshness consequence,
    // one NO REVIEW DATE item per concept.
    assert_eq!(report.queue.len(), 7);
    assert!(
        report
            .queue
            .iter()
            .all(|item| item.reason == NO_REVIEW_DATE)
    );
}
