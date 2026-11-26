//! Integration tests for the drift check over fixture snapshots.
//!
//! The fixture manifest references one column the live schema
//! dropped outright and one it renamed, so a check raises a defect
//! item and a proposal item side by side. Later checks show the
//! cadence contract: first-raised runs survive re-checks, and items
//! close only when a fixed schema export makes them stop holding.

use std::io::Write;
use std::path::{Path, PathBuf};

use anchorwatch_core::drift::{StubDriftAuditor, run_drift_check};
use anchorwatch_core::queue::DEFINITION_DRIFT;
use anchorwatch_core::upkeep::Mode;

const MANIFEST: &str = r#"{
  "semantic_models": [
    {
      "name": "orders",
      "node_relation": {"relation_name": "analytics.orders"},
      "entities": [{"name": "order_id", "type": "primary", "expr": "order_id"}],
      "dimensions": [
        {"name": "channel", "type": "categorical", "expr": "channel"},
        {"name": "ordered_on", "type": "time", "expr": "order_date"}
      ],
      "measures": [{"name": "revenue", "agg": "sum", "expr": "amount"}]
    }
  ]
}"#;

const LIVE_DRIFTED: &str = r#"{
  "tables": {
    "analytics.orders": {
      "columns": [
        {"name": "order_id", "type": "integer"},
        {"name": "channel", "type": "text"},
        {"name": "orderdate", "type": "date"}
      ]
    }
  }
}"#;

const LIVE_FIXED: &str = r#"{
  "tables": {
    "analytics.orders": {
      "columns": [
        {"name": "order_id", "type": "integer"},
        {"name": "channel", "type": "text"},
        {"name": "order_date", "type": "date"},
        {"name": "amount", "type": "numeric"}
      ]
    }
  }
}"#;

fn write_file(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
}

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anchorwatch-drift-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "definitions.json", MANIFEST);
    write_file(&dir, "live.json", LIVE_DRIFTED);
    dir
}

fn check(dir: &Path, as_of: &str, mode: Mode) -> anchorwatch_core::drift::DriftReport {
    run_drift_check(
        &dir.join("definitions.json"),
        &dir.join("live.json"),
        &dir.join("state"),
        as_of,
        &StubDriftAuditor,
        mode,
    )
    .unwrap()
}

#[test]
fn a_check_raises_a_defect_and_a_proposal() {
    let dir = fixture("basic");
    let report = check(&dir, "2026-11-24T00:00:00Z", Mode::DryRun);
    assert_eq!(report.models, 1);
    assert_eq!(report.references, 4);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.queue.len(), 2);
    assert_eq!(report.raised, 2);
    assert_eq!(report.closed, 0);
    assert!(
        report
            .queue
            .iter()
            .all(|item| item.reason == DEFINITION_DRIFT)
    );
    // The defect sorts ahead of the proposal.
    assert_eq!(report.queue[0].concept, "orders.measure.revenue");
    assert_eq!(report.queue[0].priority, 1);
    assert_eq!(report.queue[1].concept, "orders.dimension.ordered_on");
    assert_eq!(report.queue[1].priority, 2);
    // A dry run writes nothing.
    assert!(!dir.join("state").join("drift-queue.json").exists());
}

const VIEW: &str = r#"name: sales_view
tables:
  - name: orders
    base_table:
      database: ANALYTICS
      schema: PUBLIC
      table: ORDERS
    dimensions:
      - name: channel
        expr: channel
        data_type: text
    facts:
      - name: amount_fact
        expr: amount
        data_type: number
"#;

const VIEW_LIVE: &str = r#"{
  "tables": {
    "ANALYTICS.PUBLIC.ORDERS": {
      "columns": [
        {"name": "channel", "type": "TEXT"},
        {"name": "amount", "type": "TEXT"}
      ]
    }
  }
}"#;

#[test]
fn a_snowflake_view_check_raises_type_drift() {
    let dir = std::env::temp_dir().join(format!(
        "anchorwatch-drift-snowflake-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "definitions.yaml", VIEW);
    write_file(&dir, "live.json", VIEW_LIVE);
    let report = run_drift_check(
        &dir.join("definitions.yaml"),
        &dir.join("live.json"),
        &dir.join("state"),
        "2026-11-24T00:00:00Z",
        &StubDriftAuditor,
        Mode::DryRun,
    )
    .unwrap();
    assert_eq!(report.definitions_format, "snowflake-semantic-view");
    assert_eq!(report.references, 2);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "AW-DRF-03");
    assert_eq!(report.queue.len(), 1);
    assert_eq!(report.queue[0].concept, "orders.fact.amount_fact");
    assert_eq!(report.queue[0].reason, DEFINITION_DRIFT);
    assert_eq!(report.queue[0].priority, 1);
}

const VIEW_LONG_SPELLINGS: &str = r#"name: sales_view
tables:
  - name: orders
    base_table:
      database: ANALYTICS
      schema: PUBLIC
      table: ORDERS
    dimensions:
      - name: channel
        expr: channel
        data_type: character varying
    facts:
      - name: amount_fact
        expr: amount
        data_type: int8
    time_dimensions:
      - name: ordered_on
        expr: ordered_on
        data_type: timestamp with time zone
"#;

const VIEW_LONG_SPELLINGS_LIVE: &str = r#"{
  "tables": {
    "ANALYTICS.PUBLIC.ORDERS": {
      "columns": [
        {"name": "channel", "type": "TEXT"},
        {"name": "amount", "type": "BIGINT"},
        {"name": "ordered_on", "type": "TIMESTAMP_TZ"}
      ]
    }
  }
}"#;

#[test]
fn long_type_spellings_fold_to_their_families() {
    // Register R1-10. A type spelled long on the definition side
    // and short on the live side is the same type, and the check
    // must not fire its mismatch finding on the spelling alone.
    let dir = std::env::temp_dir().join(format!(
        "anchorwatch-drift-spellings-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "definitions.yaml", VIEW_LONG_SPELLINGS);
    write_file(&dir, "live.json", VIEW_LONG_SPELLINGS_LIVE);
    let report = run_drift_check(
        &dir.join("definitions.yaml"),
        &dir.join("live.json"),
        &dir.join("state"),
        "2026-11-24T00:00:00Z",
        &StubDriftAuditor,
        Mode::DryRun,
    )
    .unwrap();
    assert_eq!(report.references, 3);
    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.queue.len(), 0);
}

const METRIC_VIEW: &str = r#"version: 1.1
source: main.sales.orders
fields:
  - name: channel
    expr: channel
  - name: ordered_on
    expr: order_date
measures:
  - name: revenue
    expr: SUM(amount)
"#;

const METRIC_LIVE: &str = r#"{
  "tables": {
    "main.sales.orders": {
      "columns": [
        {"name": "channel", "type": "text"},
        {"name": "orderdate", "type": "date"}
      ]
    }
  }
}"#;

#[test]
fn a_metric_view_check_raises_the_rename_proposal() {
    let dir = std::env::temp_dir().join(format!(
        "anchorwatch-drift-metricview-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "definitions.yaml", METRIC_VIEW);
    write_file(&dir, "live.json", METRIC_LIVE);
    let report = run_drift_check(
        &dir.join("definitions.yaml"),
        &dir.join("live.json"),
        &dir.join("state"),
        "2026-11-24T00:00:00Z",
        &StubDriftAuditor,
        Mode::DryRun,
    )
    .unwrap();
    assert_eq!(report.definitions_format, "databricks-metric-view");
    assert_eq!(report.references, 2);
    assert_eq!(report.queue.len(), 1);
    assert_eq!(report.queue[0].concept, "orders.field.ordered_on");
    assert_eq!(report.queue[0].reason, DEFINITION_DRIFT);
    assert_eq!(report.queue[0].priority, 2);
}

const GENIE: &str = r#"{
  "version": 2,
  "data_sources": {"tables": [
    {"identifier": "main.sales.orders", "column_configs": [{"name": "order_id"}, {"name": "amount"}]}
  ]},
  "benchmarks": {"questions": []}
}"#;

const GENIE_LIVE: &str = r#"{
  "tables": {
    "main.sales.orders": {
      "columns": [{"name": "order_id", "type": "integer"}]
    }
  }
}"#;

#[test]
fn a_genie_space_check_raises_the_missing_column() {
    let dir = std::env::temp_dir().join(format!("anchorwatch-drift-genie-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "definitions.json", GENIE);
    write_file(&dir, "live.json", GENIE_LIVE);
    let report = run_drift_check(
        &dir.join("definitions.json"),
        &dir.join("live.json"),
        &dir.join("state"),
        "2026-11-24T00:00:00Z",
        &StubDriftAuditor,
        Mode::DryRun,
    )
    .unwrap();
    assert_eq!(report.definitions_format, "databricks-genie-space");
    assert_eq!(report.references, 2);
    assert_eq!(report.queue.len(), 1);
    assert_eq!(report.queue[0].concept, "orders.column.amount");
    assert_eq!(report.queue[0].reason, DEFINITION_DRIFT);
    assert_eq!(report.queue[0].priority, 1);
}

#[test]
fn two_checks_over_the_same_snapshots_are_byte_identical() {
    let dir = fixture("determinism");
    let first = check(&dir, "2026-11-24T00:00:00Z", Mode::DryRun);
    let second = check(&dir, "2026-11-24T00:00:00Z", Mode::DryRun);
    assert_eq!(first.to_json(), second.to_json());
    assert_eq!(first.to_markdown(), second.to_markdown());
}

#[test]
fn rechecks_preserve_first_raised_and_close_on_evidence() {
    let dir = fixture("cadence");
    let first = check(&dir, "2026-11-24T00:00:00Z", Mode::Apply);
    assert!(dir.join("state").join("drift-queue.json").exists());
    assert!(dir.join("state").join("drift-state.json").exists());
    let first_run = first.run_id.clone();
    // The same snapshots at a later instant confirm, never re-raise.
    let second = check(&dir, "2026-11-25T00:00:00Z", Mode::Apply);
    assert_eq!(second.raised, 0);
    assert_eq!(second.closed, 0);
    assert_eq!(second.queue.len(), 2);
    assert!(
        second
            .queue
            .iter()
            .all(|item| item.first_raised == first_run)
    );
    assert!(
        second
            .queue
            .iter()
            .all(|item| item.last_confirmed == second.run_id)
    );
    // A fixed schema export closes both items on observed evidence.
    write_file(&dir, "live.json", LIVE_FIXED);
    let third = check(&dir, "2026-11-26T00:00:00Z", Mode::Apply);
    assert_eq!(third.findings.len(), 0);
    assert_eq!(third.queue.len(), 0);
    assert_eq!(third.closed, 2);
}
