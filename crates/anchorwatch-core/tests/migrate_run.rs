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
    write_file(
        &dir,
        "people/ada.md",
        "---\ndisplay_name: \"Ada Lovelace\"\nsummary: \"First programmer\"\nrank: 1\nfirst_name: \"Ada\"\nlast_name: \"Lovelace\"\nupdated: \"2026-09-01\"\n---\nBody about the analytical engine. This supersedes the earlier note.\n- [ ] ask about the engine\nSee MEMORY.md#L38 for the ruling.\n",
    );
    write_file(&dir, "people/INDEX.md", "# People\n\nClosest first.\n");
    write_file(
        &dir,
        "groups/team.md",
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
        "# 2026-09-16\n\nAn entry. It was superseded by a later entry.\n",
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
    let out = source.join("bundle-out");
    let report =
        run_migration(&ClaudeMemoryProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 5);
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
    assert_eq!(freshness.count, 5);
    // The converted person carries the mapping and the extensions.
    let ada = std::fs::read_to_string(out.join("people/ada.md")).unwrap();
    assert!(ada.contains("type: \"Person\""));
    assert!(ada.contains("title: \"Ada Lovelace\""));
    assert!(ada.contains("x-muse-rank: 1"));
    assert!(ada.contains("x-muse-updated: \"2026-09-01\""));
    assert!(ada.contains("x-anchorwatch-source: \"people/ada.md\""));
    assert!(ada.contains("analytical engine"));
    // The bundle furniture is all present.
    assert!(out.join("index.md").exists());
    assert!(out.join("people/index.md").exists());
    assert!(out.join("log.md").exists());
    assert!(out.join("LOSS-LEDGER.md").exists());
    assert!(out.join("loss-ledger.json").exists());
    let manifest = std::fs::read_to_string(out.join(".recension/state.json")).unwrap();
    assert!(manifest.contains("\"people/ada.md\": \"Person\""));
    assert!(manifest.contains("\"curated/memory.md\": \"Curated Memory\""));
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
    let out = source.join("bundle-out");
    let report =
        run_migration(&ClaudeMemoryProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 0);
    assert!(report.entries.is_empty());
    assert!(report.honesty_gate_failed);
    assert!(report.gate_failed);
}

#[test]
fn the_migrated_bundle_stands_up_under_an_upkeep_pass() {
    let source = fixture("upkeep");
    let out = source.join("bundle-out");
    run_migration(&ClaudeMemoryProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    let report = run_pass(&out, "2026-11-25T00:00:00Z", &StubAuditor, Mode::DryRun).unwrap();
    assert_eq!(report.concept_count, 5);
    // No drift, no defects: only the honest freshness consequence,
    // one NO REVIEW DATE item per concept.
    assert_eq!(report.queue.len(), 5);
    assert!(
        report
            .queue
            .iter()
            .all(|item| item.reason == NO_REVIEW_DATE)
    );
}
