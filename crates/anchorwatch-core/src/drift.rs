//! Definition-versus-live-schema drift upkeep for semantic layers.
//!
//! No vendor semantic layer stores a trusted stamp comparing a
//! definition against the live warehouse schema, so drift, a column
//! renamed or dropped under a metric or view that still references
//! it, is always computed by whoever checks. That computation is
//! the trust auditor's, under the same split as the bundle engine.
//! The auditor computes findings; this module is the upkeep half.
//! It owns the cadence, loading exported definition and schema
//! snapshots, keying each check on their hashes, queueing findings
//! in the shared queue vocabulary, carrying items across checks
//! with their first-raised run intact, and closing an item only
//! when a later check no longer reports it.
//!
//! Both inputs arrive as exported files. The engine never connects
//! to a warehouse and never holds a vendor credential. The first
//! definition shape is the dbt semantic manifest, plain JSON in
//! git, first in the grading programme's gradeability order. The
//! live side is a JSON column listing in the shape this module
//! documents, whatever tool exported it. The Snowflake semantic
//! view YAML shape is the second input and is not yet read.
//!
//! Until the real auditor publishes its drift interface, checks run
//! against [`StubDriftAuditor`], which implements the comparison in
//! mechanical form. The stub is a test instrument for the cadence
//! and queue contract, never a second auditor, and it is removed
//! when the real interface lands. Its rule identifiers are in the
//! AW-DRF series and are expected to be replaced by the auditor's
//! own when the records reconcile.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::auditor::Severity;
use crate::json::{Json, parse};
use crate::queue::{DEFINITION_DRIFT, QueueItem, QueueState, sort_queue};
use crate::sha256::sha256_hex;
use crate::time::parse_timestamp;
use crate::upkeep::{Mode, merge_queue};

/// The drift auditor's report schema version this build emits.
pub const DRIFT_SCHEMA_VERSION: &str = "1";

/// One column reference extracted from a definition snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnRef {
    /// The artifact carrying the reference, model, kind, and name.
    pub artifact: String,
    /// The semantic model the element belongs to.
    pub model: String,
    /// The element kind, entity, dimension, or measure.
    pub kind: String,
    /// The warehouse relation the model reads.
    pub relation: String,
    /// The referenced column name.
    pub column: String,
}

/// A parsed definition snapshot.
#[derive(Debug, Clone)]
pub struct Definitions {
    /// The input format this snapshot was read from.
    pub format: String,
    /// The source label recorded in evidence.
    pub source: String,
    /// The snapshot hash of the source bytes.
    pub hash: String,
    /// Semantic models seen in the snapshot.
    pub models: usize,
    /// Column references, in artifact order.
    pub references: Vec<ColumnRef>,
}

/// A parsed live-schema snapshot.
#[derive(Debug, Clone)]
pub struct LiveSchema {
    /// The source label recorded in evidence.
    pub source: String,
    /// The snapshot hash of the source bytes.
    pub hash: String,
    /// Relation name to its columns, column name to declared type.
    pub tables: BTreeMap<String, BTreeMap<String, String>>,
}

/// One drift finding from the auditor, keyed by its rule identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftFinding {
    /// The stable rule identifier, part of the auditor contract.
    pub rule_id: String,
    /// The finding severity.
    pub severity: Severity,
    /// The definition artifact the finding is about.
    pub artifact: String,
    /// The evidence values behind the finding.
    pub evidence: Vec<(String, String)>,
}

/// The drift auditor contract. Implementations compute findings
/// from two snapshots and never mutate anything.
pub trait DriftAuditor {
    /// The auditor's name, recorded in every check report.
    fn name(&self) -> &str;
    /// Compares the definition snapshot against the live schema.
    fn audit(&self, definitions: &Definitions, live: &LiveSchema) -> Vec<DriftFinding>;
}

/// The sanctioned stub drift auditor. Implements the comparison in
/// mechanical form. See the module documentation before relying on
/// it for anything beyond the cadence contract's own tests.
pub struct StubDriftAuditor;

impl DriftAuditor for StubDriftAuditor {
    fn name(&self) -> &str {
        "stub"
    }

    fn audit(&self, definitions: &Definitions, live: &LiveSchema) -> Vec<DriftFinding> {
        let mut findings = Vec::new();
        let referenced: BTreeMap<&str, BTreeSet<&str>> = {
            let mut map: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
            for reference in &definitions.references {
                map.entry(reference.relation.as_str())
                    .or_default()
                    .insert(reference.column.as_str());
            }
            map
        };
        for reference in &definitions.references {
            let base_evidence = vec![
                ("file".to_string(), definitions.source.clone()),
                ("relation".to_string(), reference.relation.clone()),
                ("column".to_string(), reference.column.clone()),
            ];
            let Some(table) = live.tables.get(&reference.relation) else {
                let mut evidence = base_evidence.clone();
                evidence.push((
                    "observation".to_string(),
                    "relation absent from live schema".to_string(),
                ));
                findings.push(DriftFinding {
                    rule_id: "AW-DRF-01".to_string(),
                    severity: Severity::Error,
                    artifact: reference.artifact.clone(),
                    evidence,
                });
                continue;
            };
            if table.contains_key(&reference.column) {
                continue;
            }
            let wanted = normalize(&reference.column);
            let candidates: Vec<&String> = table
                .keys()
                .filter(|name| {
                    normalize(name) == wanted
                        && !referenced
                            .get(reference.relation.as_str())
                            .is_some_and(|cols| cols.contains(name.as_str()))
                })
                .collect();
            if candidates.len() == 1 {
                let mut evidence = base_evidence;
                evidence.push((
                    "observation".to_string(),
                    "referenced column absent; one rename candidate in live schema".to_string(),
                ));
                evidence.push(("candidate".to_string(), candidates[0].clone()));
                findings.push(DriftFinding {
                    rule_id: "AW-DRF-02".to_string(),
                    severity: Severity::Warning,
                    artifact: reference.artifact.clone(),
                    evidence,
                });
            } else {
                let mut evidence = base_evidence;
                evidence.push((
                    "observation".to_string(),
                    "referenced column absent from live schema".to_string(),
                ));
                findings.push(DriftFinding {
                    rule_id: "AW-DRF-01".to_string(),
                    severity: Severity::Error,
                    artifact: reference.artifact.clone(),
                    evidence,
                });
            }
        }
        findings.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.artifact.cmp(&b.artifact))
        });
        findings
    }
}

/// The name comparison the rename-candidate rule uses, case folded
/// with underscores and hyphens removed.
fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether a definition expression is a plain column identifier.
/// Expressions that compute are not column references the stub can
/// check, and it skips them rather than guessing.
fn is_plain_identifier(expr: &str) -> bool {
    let mut chars = expr.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Relation names compare after quote removal, because exporters
/// disagree about quoting dotted names.
fn normalize_relation(name: &str) -> String {
    name.chars().filter(|c| *c != '"' && *c != '`').collect()
}

/// Loads a dbt semantic manifest as a definition snapshot. The
/// manifest's semantic models carry entities, dimensions, and
/// measures whose expressions name warehouse columns. An element
/// with no expression references the column of its own name.
pub fn load_dbt_manifest(text: &str, source: &str, hash: String) -> Result<Definitions, String> {
    let root = parse(text).ok_or_else(|| format!("definitions do not parse as JSON: {source}"))?;
    let models = root
        .get("semantic_models")
        .and_then(|v| v.as_arr())
        .ok_or_else(|| format!("no semantic_models array in {source}"))?;
    let mut references = Vec::new();
    for model in models {
        let Some(model_name) = model.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let relation = model
            .get("node_relation")
            .and_then(|v| v.get("relation_name"))
            .and_then(|v| v.as_str())
            .map(normalize_relation)
            .unwrap_or_default();
        for (key, kind) in [
            ("entities", "entity"),
            ("dimensions", "dimension"),
            ("measures", "measure"),
        ] {
            let Some(elements) = model.get(key).and_then(|v| v.as_arr()) else {
                continue;
            };
            for element in elements {
                let Some(name) = element.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let column = element.get("expr").and_then(|v| v.as_str()).unwrap_or(name);
                if !is_plain_identifier(column) {
                    continue;
                }
                references.push(ColumnRef {
                    artifact: format!("{model_name}.{kind}.{name}"),
                    model: model_name.to_string(),
                    kind: kind.to_string(),
                    relation: relation.clone(),
                    column: column.to_string(),
                });
            }
        }
    }
    references.sort_by(|a, b| a.artifact.cmp(&b.artifact));
    Ok(Definitions {
        format: "dbt-semantic-manifest".to_string(),
        source: source.to_string(),
        hash,
        models: models.len(),
        references,
    })
}

/// Loads a live-schema snapshot. The shape is a JSON object with a
/// `tables` object mapping each relation name to an object with a
/// `columns` array, each column an object with `name` and an
/// optional `type`. Any exporter that can list a warehouse's
/// columns can produce it.
pub fn load_live_schema(text: &str, source: &str, hash: String) -> Result<LiveSchema, String> {
    let root =
        parse(text).ok_or_else(|| format!("live schema does not parse as JSON: {source}"))?;
    let tables = root
        .get("tables")
        .and_then(|v| v.as_obj())
        .ok_or_else(|| format!("no tables object in {source}"))?;
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (relation, table) in tables {
        let mut columns = BTreeMap::new();
        if let Some(cols) = table.get("columns").and_then(|v| v.as_arr()) {
            for col in cols {
                if let Some(name) = col.get("name").and_then(|v| v.as_str()) {
                    let declared = col
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    columns.insert(name.to_string(), declared);
                }
            }
        }
        out.insert(normalize_relation(relation), columns);
    }
    Ok(LiveSchema {
        source: source.to_string(),
        hash,
        tables: out,
    })
}

/// The report of one drift check.
#[derive(Debug, Clone)]
pub struct DriftReport {
    /// The check's run identifier, derived from both snapshot
    /// hashes, the as-of instant, and the auditor.
    pub run_id: String,
    /// The pinned as-of instant.
    pub as_of: String,
    /// The auditor that computed the findings.
    pub auditor: String,
    /// The definition snapshot's format.
    pub definitions_format: String,
    /// The definition snapshot's hash.
    pub definitions_hash: String,
    /// The live schema snapshot's hash.
    pub live_hash: String,
    /// Semantic models in the definition snapshot.
    pub models: usize,
    /// Column references checked.
    pub references: usize,
    /// The auditor's findings, in rule and artifact order.
    pub findings: Vec<DriftFinding>,
    /// Queue items still holding after the merge, in work order.
    pub queue: Vec<QueueItem>,
    /// Items this check raised for the first time.
    pub raised: usize,
    /// Items this check closed on observed evidence.
    pub closed: usize,
    /// Notes for the report's reader.
    pub notes: Vec<String>,
    /// Writes this check performed, in apply mode.
    pub actions: Vec<String>,
}

impl DriftReport {
    /// Renders the report as deterministic JSON.
    pub fn to_json(&self) -> String {
        Json::obj(vec![
            ("actions", Json::strings(&self.actions)),
            ("as_of", Json::Str(self.as_of.clone())),
            ("auditor", Json::Str(self.auditor.clone())),
            ("closed", Json::Int(self.closed as i64)),
            (
                "definitions",
                Json::obj(vec![
                    ("format", Json::Str(self.definitions_format.clone())),
                    ("hash", Json::Str(self.definitions_hash.clone())),
                    ("models", Json::Int(self.models as i64)),
                    ("references", Json::Int(self.references as i64)),
                ]),
            ),
            (
                "findings",
                Json::Arr(self.findings.iter().map(finding_json).collect()),
            ),
            ("live_hash", Json::Str(self.live_hash.clone())),
            ("notes", Json::strings(&self.notes)),
            (
                "queue",
                Json::Arr(self.queue.iter().map(queue_item_json).collect()),
            ),
            ("raised", Json::Int(self.raised as i64)),
            ("run_id", Json::Str(self.run_id.clone())),
            ("schema", Json::Str(DRIFT_SCHEMA_VERSION.to_string())),
        ])
        .render()
    }

    /// Renders the report as Markdown.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Drift check {}\n\n", self.run_id));
        out.push_str(&format!(
            "As of {}. Auditor {}. Definitions {} ({} models, {} references). Live schema {}.\n\n",
            self.as_of,
            self.auditor,
            self.definitions_hash,
            self.models,
            self.references,
            self.live_hash
        ));
        out.push_str("## Findings\n\n");
        if self.findings.is_empty() {
            out.push_str("None.\n\n");
        }
        for finding in &self.findings {
            out.push_str(&format!(
                "- {} on {} ({})\n",
                finding.rule_id,
                finding.artifact,
                finding.severity.as_str()
            ));
        }
        if !self.findings.is_empty() {
            out.push('\n');
        }
        out.push_str("## Queue\n\n");
        if self.queue.is_empty() {
            out.push_str("No open items.\n\n");
        }
        for item in &self.queue {
            out.push_str(&format!(
                "- {} {} [{}; first raised {}; last confirmed {}]\n",
                item.concept,
                item.reason,
                item.state.as_str(),
                item.first_raised,
                item.last_confirmed
            ));
        }
        if !self.queue.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "Raised {} new items; closed {} items.\n",
            self.raised, self.closed
        ));
        out
    }
}

fn finding_json(finding: &DriftFinding) -> Json {
    Json::obj(vec![
        ("artifact", Json::Str(finding.artifact.clone())),
        (
            "evidence",
            Json::Obj(
                finding
                    .evidence
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::Str(v.clone())))
                    .collect(),
            ),
        ),
        ("rule_id", Json::Str(finding.rule_id.clone())),
        ("severity", Json::Str(finding.severity.as_str().to_string())),
    ])
}

fn queue_item_json(item: &QueueItem) -> Json {
    Json::obj(vec![
        ("concept", Json::Str(item.concept.clone())),
        (
            "evidence",
            Json::Obj(
                item.evidence
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::Str(v.clone())))
                    .collect(),
            ),
        ),
        ("first_raised", Json::Str(item.first_raised.clone())),
        ("last_confirmed", Json::Str(item.last_confirmed.clone())),
        ("priority", Json::Int(item.priority as i64)),
        ("reason", Json::Str(item.reason.clone())),
        ("state", Json::Str(item.state.as_str().to_string())),
    ])
}

/// Runs one drift check over a definition snapshot and a live
/// schema snapshot. The state directory holds the drift queue and
/// check state between runs; a dry run reads them and writes
/// nothing.
pub fn run_drift_check(
    definitions_path: &Path,
    live_path: &Path,
    state_dir: &Path,
    as_of: &str,
    auditor: &dyn DriftAuditor,
    mode: Mode,
) -> Result<DriftReport, String> {
    parse_timestamp(as_of).ok_or_else(|| format!("as-of instant does not parse: {as_of}"))?;
    let definitions_label = definitions_path.to_string_lossy().into_owned();
    let live_label = live_path.to_string_lossy().into_owned();
    let definitions_bytes = std::fs::read(definitions_path)
        .map_err(|e| format!("cannot read definitions at {definitions_label}: {e}"))?;
    let live_bytes = std::fs::read(live_path)
        .map_err(|e| format!("cannot read live schema at {live_label}: {e}"))?;
    let definitions_hash = sha256_hex(&definitions_bytes);
    let live_hash = sha256_hex(&live_bytes);
    let definitions_text = String::from_utf8(definitions_bytes)
        .map_err(|_| format!("definitions are not UTF-8: {definitions_label}"))?;
    let live_text = String::from_utf8(live_bytes)
        .map_err(|_| format!("live schema is not UTF-8: {live_label}"))?;
    let definitions = load_dbt_manifest(&definitions_text, &definitions_label, definitions_hash)?;
    let live = load_live_schema(&live_text, &live_label, live_hash)?;
    let run_id = format!(
        "run-{}",
        &sha256_hex(
            format!(
                "{}|{}|{as_of}|{}",
                definitions.hash,
                live.hash,
                auditor.name()
            )
            .as_bytes()
        )[..12]
    );
    let findings = auditor.audit(&definitions, &live);
    let mut fresh = Vec::new();
    for finding in &findings {
        let mut item = QueueItem::new(
            finding.artifact.clone(),
            DEFINITION_DRIFT,
            finding.evidence.clone(),
            &run_id,
        );
        item.priority = match finding.severity {
            Severity::Error => 1,
            Severity::Warning => 2,
        };
        fresh.push(item);
    }
    let previous = load_drift_queue(state_dir);
    let mut notes = Vec::new();
    if previous.is_empty() {
        notes
            .push("no previous drift queue; this check establishes the drift baseline".to_string());
    }
    let (mut queue, raised, closed) = merge_queue(fresh, previous, &run_id);
    sort_queue(&mut queue);
    let mut report = DriftReport {
        run_id: run_id.clone(),
        as_of: as_of.to_string(),
        auditor: auditor.name().to_string(),
        definitions_format: definitions.format.clone(),
        definitions_hash: definitions.hash.clone(),
        live_hash: live.hash.clone(),
        models: definitions.models,
        references: definitions.references.len(),
        findings,
        queue,
        raised,
        closed,
        notes,
        actions: Vec::new(),
    };
    if matches!(mode, Mode::Apply) {
        write_drift_state(state_dir, &report)?;
        report
            .actions
            .push("drift queue and check state written".to_string());
    }
    Ok(report)
}

/// Loads the drift queue as the previous check left it. Only the
/// fields the merge preserves are read.
fn load_drift_queue(state_dir: &Path) -> Vec<QueueItem> {
    let path = state_dir.join("drift-queue.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Some(root) = parse(&text) else {
        return Vec::new();
    };
    let Some(items) = root.get("items").and_then(|v| v.as_arr()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in items {
        let (Some(concept), Some(reason)) = (
            entry.get("concept").and_then(|v| v.as_str()),
            entry.get("reason").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let mut item = QueueItem::new(concept.to_string(), reason, Vec::new(), "");
        if let Some(first) = entry.get("first_raised").and_then(|v| v.as_str()) {
            item.first_raised = first.to_string();
        }
        if let Some(state) = entry
            .get("state")
            .and_then(|v| v.as_str())
            .and_then(QueueState::from_name)
        {
            item.state = state;
        }
        out.push(item);
    }
    out
}

/// Writes the drift queue and check state in apply mode.
fn write_drift_state(state_dir: &Path, report: &DriftReport) -> Result<(), String> {
    std::fs::create_dir_all(state_dir)
        .map_err(|e| format!("cannot create state directory {}: {e}", state_dir.display()))?;
    let queue_json = Json::obj(vec![
        ("as_of", Json::Str(report.as_of.clone())),
        (
            "items",
            Json::Arr(report.queue.iter().map(queue_item_json).collect()),
        ),
        ("run_id", Json::Str(report.run_id.clone())),
    ])
    .render();
    std::fs::write(state_dir.join("drift-queue.json"), queue_json)
        .map_err(|e| format!("cannot write drift queue: {e}"))?;
    std::fs::write(state_dir.join("drift-queue.md"), report.to_markdown())
        .map_err(|e| format!("cannot write drift queue markdown: {e}"))?;
    let state_json = Json::obj(vec![
        ("as_of", Json::Str(report.as_of.clone())),
        ("auditor", Json::Str(report.auditor.clone())),
        (
            "definitions_hash",
            Json::Str(report.definitions_hash.clone()),
        ),
        ("live_hash", Json::Str(report.live_hash.clone())),
        ("run_id", Json::Str(report.run_id.clone())),
        ("schema", Json::Str(DRIFT_SCHEMA_VERSION.to_string())),
    ])
    .render();
    std::fs::write(state_dir.join("drift-state.json"), state_json)
        .map_err(|e| format!("cannot write drift state: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DriftAuditor, StubDriftAuditor, load_dbt_manifest, load_live_schema};

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

    const LIVE: &str = r#"{
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

    fn fixtures() -> (super::Definitions, super::LiveSchema) {
        let definitions = load_dbt_manifest(MANIFEST, "manifest.json", "d".to_string()).unwrap();
        let live = load_live_schema(LIVE, "live.json", "l".to_string()).unwrap();
        (definitions, live)
    }

    #[test]
    fn the_stub_finds_the_missing_column_and_the_rename_candidate() {
        let (definitions, live) = fixtures();
        assert_eq!(definitions.references.len(), 4);
        let findings = StubDriftAuditor.audit(&definitions, &live);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "AW-DRF-01");
        assert_eq!(findings[0].artifact, "orders.measure.revenue");
        assert_eq!(findings[1].rule_id, "AW-DRF-02");
        assert_eq!(findings[1].artifact, "orders.dimension.ordered_on");
        assert!(
            findings[1]
                .evidence
                .iter()
                .any(|(k, v)| k == "candidate" && v == "orderdate")
        );
    }

    #[test]
    fn a_missing_relation_is_a_defect() {
        let (definitions, _) = fixtures();
        let live = load_live_schema(r#"{"tables": {}}"#, "live.json", "l".to_string()).unwrap();
        let findings = StubDriftAuditor.audit(&definitions, &live);
        assert_eq!(findings.len(), 4);
        assert!(findings.iter().all(|f| f.rule_id == "AW-DRF-01"));
    }

    #[test]
    fn computed_expressions_are_not_column_references() {
        let manifest = r#"{"semantic_models": [{"name": "m", "node_relation": {"relation_name": "t"}, "measures": [{"name": "x", "agg": "sum", "expr": "amount * 2"}]}]}"#;
        let definitions = load_dbt_manifest(manifest, "m.json", "d".to_string()).unwrap();
        assert_eq!(definitions.references.len(), 0);
    }
}
