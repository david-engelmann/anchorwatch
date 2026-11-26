//! Integration tests for the OKF native profile: an existing
//! OKF bundle re-emitted as a v0.3 bundle over the migrator
//! engine, with the version step's path rewrites, the furniture
//! carried, and the ledger honest about what regeneration drops.

use std::path::PathBuf;

use anchorwatch_core::migrate::{OkfNativeProfile, run_migration};
use anchorwatch_core::perishables::PerishablesAuditor;
use anchorwatch_core::upkeep::{Mode, run_pass};

fn write_file(root: &std::path::Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn out_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anchorwatch-okf-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A bundle that declares no version, so its bare path fields
/// were written from the bundle root under the pre-0.3 reading.
fn fixture(name: &str) -> PathBuf {
    let dir = out_dir(name);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "index.md",
        "---\ntitle: Field notes\ndescription: Notes from the field.\nlicense: CC-BY-4.0\n---\n\n# Field notes\n\n* [Orders](tables/orders.md)\n",
    );
    write_file(
        &dir,
        "log.md",
        "# Bundle Update Log\n\n## 2026-05-22\n* **Update**: Orders refreshed.\n\n## 2026-05-15\n* **Creation**: Bundle created.\n",
    );
    write_file(
        &dir,
        "tables/orders.md",
        "---\ntype: BigQuery Table\ntitle: Customer Orders\ndescription: One row per completed order.\ntags: [sales, orders]\ngenerated: { by: \"agent:etl\", at: \"2026-05-20T00:00:00Z\" }\nstale_after: \"2027-01-01T00:00:00Z\"\nx-acme-owner: \"team:rates\"\nsources:\n  - id: rates\n    resource: data/rates.csv\n    title: Rates sheet\n---\n\n# Schema\n\nThe orders table.\n",
    );
    write_file(
        &dir,
        "metrics/legacy.md",
        "---\ntype: Metric\ntitle: Legacy Margin\nstatus: deprecated\nsuperseded_by: metrics/gross-margin.md\nverified:\n  - { by: \"human:ada\", at: \"2026-06-25T09:00:00Z\" }\n---\n\nThe old margin.\n",
    );
    write_file(
        &dir,
        "metrics/gross-margin.md",
        "---\ntype: Metric\ntitle: Gross Margin\n---\n\nThe margin.\n",
    );
    write_file(
        &dir,
        "metrics/index.md",
        "# Index\n\nThese metrics are reviewed monthly.\n\n* [Gross Margin](gross-margin.md)\n",
    );
    write_file(
        &dir,
        "notes/scratch.md",
        "Loose notes with no frontmatter.\n",
    );
    write_file(&dir, "data/rates.csv", "a,b\n1,2\n");
    dir
}

fn entry<'a>(
    report: &'a anchorwatch_core::migrate::MigrateReport,
    construct: &str,
) -> Option<&'a anchorwatch_core::migrate::LedgerEntry> {
    report.entries.iter().find(|e| e.construct == construct)
}

#[test]
fn a_crlf_bundle_migrates_with_its_types_read() {
    // Register R1-08. A bundle written with carriage-return line
    // endings used to yield no frontmatter spans at all, so every
    // concept read as typeless and was excluded. The spans are
    // read under either ending; the body rides across with its
    // own endings untouched.
    let dir = out_dir("crlf");
    write_file(
        &dir,
        "index.md",
        "---\r\nokf_version: \"0.3\"\r\ntitle: \"CRLF bundle\"\r\n---\r\n\r\n# CRLF bundle\r\n",
    );
    write_file(
        &dir,
        "notes/kept.md",
        "---\r\ntype: Note\r\ntitle: \"Kept\"\r\n---\r\n\r\nBody line.\r\n",
    );
    write_file(&dir, "log.md", "# Bundle Update Log\r\n");
    let out = out_dir("crlf-out");
    let report = run_migration(&OkfNativeProfile, &dir, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 1);
    assert_eq!(entry(&report, "OKF concepts").unwrap().count, 1);
    assert!(entry(&report, "Markdown files without a type").is_none());
    let kept = std::fs::read_to_string(out.join("notes/kept.md")).unwrap();
    assert!(kept.contains("type: Note"));
    assert!(kept.contains("Body line.\r\n"), "body endings preserved");
}

#[test]
fn a_pre_v03_bundle_migrates_with_its_paths_rewritten() {
    let source = fixture("basic");
    let out = out_dir("basic-out");
    let report = run_migration(&OkfNativeProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 3);
    assert!(report.reconciliation_ok);
    assert!(!report.gate_failed, "entries: {:?}", report.entries);

    // The version step rewrote both bare path fields.
    let paths = entry(&report, "root-relative path fields").expect("path entry");
    assert_eq!(paths.count, 2);
    let legacy = std::fs::read_to_string(out.join("metrics/legacy.md")).unwrap();
    assert!(legacy.contains("superseded_by: /metrics/gross-margin.md"));
    let orders = std::fs::read_to_string(out.join("tables/orders.md")).unwrap();
    assert!(orders.contains("resource: /data/rates.csv"));
    // Everything else in the frontmatter rode across verbatim.
    assert!(orders.contains("tags: [sales, orders]"));
    assert!(orders.contains("x-acme-owner: \"team:rates\""));
    assert!(orders.contains("stale_after: \"2027-01-01T00:00:00Z\""));
    assert!(orders.contains("# Schema"));

    // The ledger's other counts.
    assert_eq!(entry(&report, "OKF concepts").unwrap().count, 3);
    assert_eq!(entry(&report, "extension keys").unwrap().count, 1);
    assert_eq!(entry(&report, "verification events").unwrap().count, 1);
    assert_eq!(entry(&report, "review dates").unwrap().count, 1);
    assert_eq!(
        entry(&report, "Markdown files without a type")
            .unwrap()
            .count,
        1
    );
    assert_eq!(entry(&report, "source index files").unwrap().count, 2);
    assert_eq!(entry(&report, "index prose").unwrap().count, 1);
    assert_eq!(entry(&report, "bundle log history").unwrap().count, 2);
    assert_eq!(entry(&report, "asset files").unwrap().count, 1);
    assert_eq!(entry(&report, "bundle metadata").unwrap().count, 3);
    assert!(entry(&report, "unrecognised frontmatter keys").is_none());

    // The typeless file stayed behind; the asset is byte-identical.
    assert!(!out.join("notes/scratch.md").exists());
    assert_eq!(
        std::fs::read(out.join("data/rates.csv")).unwrap(),
        b"a,b\n1,2\n"
    );

    // The carried furniture: log history under the creation
    // group, bundle metadata in the regenerated root index.
    let log = std::fs::read_to_string(out.join("log.md")).unwrap();
    let creation = log.find("## 2026-11-24").unwrap();
    let older = log.find("## 2026-05-22").unwrap();
    assert!(creation < older);
    assert!(log.contains("## 2026-05-15"));
    let root_index = std::fs::read_to_string(out.join("index.md")).unwrap();
    assert!(root_index.contains("okf_version: \"0.3\""));
    assert!(root_index.contains("title: \"Field notes\""));
    assert!(root_index.contains("license: \"CC-BY-4.0\""));
    let manifest = std::fs::read_to_string(out.join(".recension/state.json")).unwrap();
    assert!(manifest.contains("\"tables/orders.md\": \"BigQuery Table\""));
}

#[test]
fn a_v03_bundle_needs_no_path_rewrite() {
    let dir = out_dir("v03");
    std::fs::create_dir_all(&dir).unwrap();
    write_file(
        &dir,
        "index.md",
        "---\nokf_version: \"0.3\"\ntitle: Current bundle\n---\n\n# Current\n",
    );
    write_file(
        &dir,
        "metrics/legacy.md",
        "---\ntype: Metric\ntitle: Legacy Margin\nstatus: deprecated\nsuperseded_by: metrics/gross-margin.md\n---\n\nThe old margin.\n",
    );
    write_file(
        &dir,
        "metrics/gross-margin.md",
        "---\ntype: Metric\ntitle: Gross Margin\n---\n\nThe margin.\n",
    );
    let out = out_dir("v03-out");
    let report = run_migration(&OkfNativeProfile, &dir, &out, "2026-11-24T00:00:00Z").unwrap();
    assert_eq!(report.concepts_written, 2);
    // Under 0.3 the bare value already resolves from the file's
    // own directory, so it is carried verbatim and no path entry
    // is written.
    assert!(entry(&report, "root-relative path fields").is_none());
    let legacy = std::fs::read_to_string(out.join("metrics/legacy.md")).unwrap();
    assert!(legacy.contains("superseded_by: metrics/gross-margin.md"));
    assert!(!legacy.contains("superseded_by: /metrics/gross-margin.md"));
}

#[test]
fn two_runs_write_byte_identical_bundles() {
    let source = fixture("determinism");
    let first_out = out_dir("det1");
    let second_out = out_dir("det2");
    let first = run_migration(
        &OkfNativeProfile,
        &source,
        &first_out,
        "2026-11-24T00:00:00Z",
    )
    .unwrap();
    let second = run_migration(
        &OkfNativeProfile,
        &source,
        &second_out,
        "2026-11-24T00:00:00Z",
    )
    .unwrap();
    assert_eq!(first.run_id, second.run_id);
    assert_eq!(tree_bytes(&first_out), tree_bytes(&second_out));
}

fn tree_bytes(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    collect(root, root, &mut files);
    files.sort();
    files
        .into_iter()
        .map(|rel| {
            let bytes = std::fs::read(root.join(&rel)).unwrap();
            (rel, bytes)
        })
        .collect()
}

fn collect(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(root, &path, out);
        } else {
            out.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

#[test]
fn the_migrated_bundle_stands_up_under_an_upkeep_pass() {
    let source = fixture("interop");
    let out = out_dir("interop-out");
    run_migration(&OkfNativeProfile, &source, &out, "2026-11-24T00:00:00Z").unwrap();
    let report = run_pass(
        &out,
        "2026-11-24T00:00:00Z",
        &PerishablesAuditor::default(),
        Mode::DryRun,
    )
    .unwrap();
    assert_eq!(report.concept_count, 3);
    // Both concepts without a review date queue for one, and the
    // concept carrying a date queues for nothing.
    let no_date: Vec<_> = report
        .queue
        .iter()
        .filter(|item| item.reason == "NO REVIEW DATE")
        .collect();
    assert_eq!(no_date.len(), 2);
    // The convergence closed the disagreement recorded in design
    // record section 33: the stub auditor resolved path fields by
    // exact path match and read the spec's leading-slash form as
    // a dangling target, where the real auditor resolves paths as
    // section 6.2 of the spec provides. The migrated bundle's
    // supersession is sound, and no defect item stands.
    let defect: Vec<_> = report
        .queue
        .iter()
        .filter(|item| item.reason == "SUPERSESSION DEFECT")
        .collect();
    assert_eq!(defect.len(), 0);
}
