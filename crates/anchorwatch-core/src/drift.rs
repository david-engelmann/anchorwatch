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
//! to a warehouse and never holds a vendor credential. Definition
//! shapes are read in the grading programme's gradeability order
//! and routed on the document's own keys, never on its file name.
//! First, the dbt semantic manifest, plain JSON in git. Second,
//! the Snowflake semantic view YAML, which also declares a type
//! per element, making type drift checkable where the dbt shape
//! declares none. Third, the Databricks shapes, the metric view
//! YAML and the Genie space's serialized JSON, whose declared
//! column configurations are the space's checkable surface. The
//! live side is a JSON column listing in the shape this module
//! documents, whatever tool exported it.
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
use crate::json::{Json, Parsed, parse};
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
    /// The type the definition declares for the column, when the
    /// definition shape carries one. The dbt manifest does not;
    /// the Snowflake semantic view does.
    pub declared_type: Option<String>,
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
            if let Some(live_type) = table.get(&reference.column) {
                if let Some(declared) = &reference.declared_type
                    && !live_type.is_empty()
                    && type_family(declared) != type_family(live_type)
                {
                    let mut evidence = base_evidence;
                    evidence.push(("declared_type".to_string(), declared.clone()));
                    evidence.push(("live_type".to_string(), live_type.clone()));
                    evidence.push((
                        "observation".to_string(),
                        "declared type family differs from live type family".to_string(),
                    ));
                    findings.push(DriftFinding {
                        rule_id: "AW-DRF-03".to_string(),
                        severity: Severity::Error,
                        artifact: reference.artifact.clone(),
                        evidence,
                    });
                }
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

/// The type family a declared or live type belongs to, for the
/// type-drift comparison. Vendor spellings differ, so known
/// spellings fold into families; an unlisted spelling is its own
/// family and matches only itself. The real auditor's type model
/// replaces this table when its interface lands.
fn type_family(declared: &str) -> String {
    let base = declared
        .split('(')
        .next()
        .unwrap_or(declared)
        .trim()
        .to_lowercase();
    match base.as_str() {
        "text" | "varchar" | "char" | "character" | "string" | "nvarchar" | "nchar" => {
            "text".to_string()
        }
        "number" | "numeric" | "decimal" | "dec" | "int" | "integer" | "bigint" | "smallint"
        | "tinyint" | "float" | "double" | "double precision" | "real" => "number".to_string(),
        "boolean" | "bool" => "boolean".to_string(),
        "date" => "date".to_string(),
        "timestamp" | "timestamp_ntz" | "timestamp_ltz" | "timestamp_tz" | "datetime" => {
            "timestamp".to_string()
        }
        "time" => "time".to_string(),
        "binary" | "varbinary" | "blob" => "binary".to_string(),
        other => other.to_string(),
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
    dbt_from_parsed(&root, source, hash)
}

fn dbt_from_parsed(root: &Parsed, source: &str, hash: String) -> Result<Definitions, String> {
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
                    declared_type: None,
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

/// A node in the narrow YAML reader. Only the block shapes a
/// machine-exported semantic view uses are represented, mappings,
/// lists, and scalar values. Flow collections and block scalars
/// are not read; a file using them fails to parse whole rather
/// than being read approximately.
enum Yaml {
    Scalar(String),
    List(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_scalar(&self) -> Option<&str> {
        match self {
            Yaml::Scalar(value) => Some(value),
            _ => None,
        }
    }

    fn as_list(&self) -> Option<&[Yaml]> {
        match self {
            Yaml::List(items) => Some(items),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct YamlLine {
    indent: usize,
    text: String,
}

/// Splits YAML text into content lines with comments removed and
/// indentation measured. A tab in the indentation makes the file
/// unreadable to this reader, and the empty result says so.
fn yaml_lines(text: &str) -> Vec<YamlLine> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = strip_yaml_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        if line[indent..].starts_with('\t') {
            return Vec::new();
        }
        out.push(YamlLine {
            indent,
            text: line[indent..].trim_end().to_string(),
        });
    }
    out
}

fn strip_yaml_comment(line: &str) -> String {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev = ' ';
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double && prev.is_whitespace() => {
                return line[..i].trim_end().to_string();
            }
            _ => {}
        }
        prev = ch;
    }
    line.to_string()
}

fn yaml_is_map_line(text: &str) -> bool {
    match text.find(':') {
        Some(idx) => idx + 1 == text.len() || text[idx + 1..].starts_with(' '),
        None => false,
    }
}

fn yaml_split_key(text: &str) -> Option<(String, String)> {
    let idx = text.find(':')?;
    if idx + 1 < text.len() && !text[idx + 1..].starts_with(' ') {
        return None;
    }
    let key = unquote_yaml(text[..idx].trim());
    let value = if idx + 1 < text.len() {
        text[idx + 1..].trim().to_string()
    } else {
        String::new()
    };
    Some((key, value))
}

fn unquote_yaml(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        trimmed[1..trimmed.len() - 1].replace("''", "'")
    } else {
        trimmed.to_string()
    }
}

/// Parses the block starting at `start`, whose lines sit at
/// `indent`. Returns the node and the first unconsumed line index.
fn yaml_block(lines: &[YamlLine], start: usize, indent: usize) -> Option<(Yaml, usize)> {
    let first = lines.get(start)?;
    if first.indent != indent {
        return None;
    }
    if first.text == "-" || first.text.starts_with("- ") {
        let mut items = Vec::new();
        let mut i = start;
        while i < lines.len()
            && lines[i].indent == indent
            && (lines[i].text == "-" || lines[i].text.starts_with("- "))
        {
            let rest = lines[i].text[1..].trim_start().to_string();
            if rest.is_empty() {
                let next_indent = lines.get(i + 1).map(|l| l.indent)?;
                if next_indent <= indent {
                    return None;
                }
                let (value, next) = yaml_block(lines, i + 1, next_indent)?;
                items.push(value);
                i = next;
            } else {
                let mut sub = vec![YamlLine {
                    indent: indent + 2,
                    text: rest,
                }];
                let mut j = i + 1;
                while j < lines.len() && lines[j].indent > indent {
                    sub.push(lines[j].clone());
                    j += 1;
                }
                let (value, used) = yaml_block(&sub, 0, indent + 2)?;
                if used != sub.len() {
                    return None;
                }
                items.push(value);
                i = j;
            }
        }
        return Some((Yaml::List(items), i));
    }
    if yaml_is_map_line(&first.text) {
        let mut pairs = Vec::new();
        let mut i = start;
        while i < lines.len() && lines[i].indent == indent && yaml_is_map_line(&lines[i].text) {
            let (key, raw_value) = yaml_split_key(&lines[i].text)?;
            if raw_value.is_empty() {
                match lines.get(i + 1) {
                    Some(next)
                        if next.indent == indent
                            && (next.text == "-" || next.text.starts_with("- ")) =>
                    {
                        let (value, after) = yaml_block(lines, i + 1, indent)?;
                        pairs.push((key, value));
                        i = after;
                    }
                    Some(next) if next.indent > indent => {
                        let (value, after) = yaml_block(lines, i + 1, next.indent)?;
                        pairs.push((key, value));
                        i = after;
                    }
                    _ => {
                        pairs.push((key, Yaml::Scalar(String::new())));
                        i += 1;
                    }
                }
            } else {
                pairs.push((key, Yaml::Scalar(unquote_yaml(&raw_value))));
                i += 1;
            }
        }
        return Some((Yaml::Map(pairs), i));
    }
    Some((Yaml::Scalar(unquote_yaml(&first.text)), start + 1))
}

/// Parses YAML text with the narrow reader. Returns None when the
/// text uses shapes the reader does not cover.
fn parse_yaml(text: &str) -> Option<Yaml> {
    let lines = yaml_lines(text);
    if lines.is_empty() {
        return None;
    }
    let (value, next) = yaml_block(&lines, 0, lines[0].indent)?;
    if next != lines.len() {
        return None;
    }
    Some(value)
}

/// The column an element expression references, the segment after
/// the last dot when it is a plain identifier. A computed
/// expression is not a reference this reader checks.
fn expr_column(expr: &str) -> Option<String> {
    let last = expr.rsplit('.').next()?.trim();
    if is_plain_identifier(last) {
        Some(last.to_string())
    } else {
        None
    }
}

/// Loads a Snowflake semantic view YAML export as a definition
/// snapshot, the shape the platform's own read function for
/// semantic views produces. Each table's facts, dimensions, and
/// time dimensions reference columns of the table's base relation
/// and declare a type. Metrics compose facts rather than naming
/// columns, so they are not references.
pub fn load_snowflake_view(text: &str, source: &str, hash: String) -> Result<Definitions, String> {
    let root = parse_yaml(text)
        .ok_or_else(|| format!("definitions do not parse as semantic view YAML: {source}"))?;
    snowflake_from_yaml(&root, source, hash)
}

fn snowflake_from_yaml(root: &Yaml, source: &str, hash: String) -> Result<Definitions, String> {
    let tables = root
        .get("tables")
        .and_then(|v| v.as_list())
        .ok_or_else(|| format!("no tables list in {source}"))?;
    let mut references = Vec::new();
    for table in tables {
        let Some(table_name) = table.get("name").and_then(|v| v.as_scalar()) else {
            continue;
        };
        let relation = match table.get("base_table") {
            Some(base) => {
                let parts: Vec<&str> = ["database", "schema", "table"]
                    .iter()
                    .filter_map(|key| base.get(key).and_then(|v| v.as_scalar()))
                    .filter(|part| !part.is_empty())
                    .collect();
                if parts.is_empty() {
                    table_name.to_string()
                } else {
                    normalize_relation(&parts.join("."))
                }
            }
            None => table_name.to_string(),
        };
        for (key, kind) in [
            ("facts", "fact"),
            ("dimensions", "dimension"),
            ("time_dimensions", "time_dimension"),
        ] {
            let Some(elements) = table.get(key).and_then(|v| v.as_list()) else {
                continue;
            };
            for element in elements {
                let Some(name) = element.get("name").and_then(|v| v.as_scalar()) else {
                    continue;
                };
                let Some(expr) = element.get("expr").and_then(|v| v.as_scalar()) else {
                    continue;
                };
                let Some(column) = expr_column(expr) else {
                    continue;
                };
                let declared_type = element
                    .get("data_type")
                    .and_then(|v| v.as_scalar())
                    .map(|t| t.to_lowercase());
                references.push(ColumnRef {
                    artifact: format!("{table_name}.{kind}.{name}"),
                    model: table_name.to_string(),
                    kind: kind.to_string(),
                    relation: relation.clone(),
                    column,
                    declared_type,
                });
            }
        }
    }
    references.sort_by(|a, b| a.artifact.cmp(&b.artifact));
    Ok(Definitions {
        format: "snowflake-semantic-view".to_string(),
        source: source.to_string(),
        hash,
        models: tables.len(),
        references,
    })
}

/// Resolves a metric view element expression to the relation and
/// column it references. An unqualified plain identifier reads the
/// view's source. A qualified one reads the join it names, or the
/// source when it names the source itself. Anything computed, or
/// qualified by a name the view does not declare, is not a
/// reference this reader can key honestly, and it is skipped.
fn resolve_metric_ref(
    expr: &str,
    main_relation: &str,
    joins: &BTreeMap<String, String>,
) -> Option<(String, String)> {
    let expr = expr.trim();
    if let Some(dot) = expr.rfind('.') {
        let (qualifier, column) = (&expr[..dot], &expr[dot + 1..]);
        if !is_plain_identifier(column) {
            return None;
        }
        if let Some(relation) = joins.get(qualifier) {
            return Some((relation.clone(), column.to_string()));
        }
        let main_table = main_relation.rsplit('.').next().unwrap_or(main_relation);
        if qualifier == main_table || qualifier == main_relation {
            return Some((main_relation.to_string(), column.to_string()));
        }
        return None;
    }
    if is_plain_identifier(expr) {
        Some((main_relation.to_string(), expr.to_string()))
    } else {
        None
    }
}

/// Loads a Databricks metric view YAML definition. The view body
/// carries no name of its own, so artifacts name the source
/// relation's table segment. Fields, under the fields key in
/// specification 1.1 and the dimensions key before it, and any
/// measure whose expression is a plain reference, name columns of
/// the source or of a declared join.
fn metric_view_from_yaml(root: &Yaml, source: &str, hash: String) -> Result<Definitions, String> {
    let source_relation = root
        .get("source")
        .and_then(|v| v.as_scalar())
        .ok_or_else(|| format!("no source in {source}"))?;
    let main_relation = normalize_relation(source_relation);
    let mut joins: BTreeMap<String, String> = BTreeMap::new();
    if let Some(list) = root.get("joins").and_then(|v| v.as_list()) {
        for join in list {
            if let (Some(name), Some(joined)) = (
                join.get("name").and_then(|v| v.as_scalar()),
                join.get("source").and_then(|v| v.as_scalar()),
            ) {
                joins.insert(name.to_string(), normalize_relation(joined));
            }
        }
    }
    let model = main_relation
        .rsplit('.')
        .next()
        .unwrap_or(&main_relation)
        .to_string();
    let fields = root
        .get("fields")
        .and_then(|v| v.as_list())
        .or_else(|| root.get("dimensions").and_then(|v| v.as_list()));
    let mut references = Vec::new();
    for (elements, kind) in [
        (fields, "field"),
        (root.get("measures").and_then(|v| v.as_list()), "measure"),
    ] {
        let Some(elements) = elements else {
            continue;
        };
        for element in elements {
            let (Some(name), Some(expr)) = (
                element.get("name").and_then(|v| v.as_scalar()),
                element.get("expr").and_then(|v| v.as_scalar()),
            ) else {
                continue;
            };
            let Some((relation, column)) = resolve_metric_ref(expr, &main_relation, &joins) else {
                continue;
            };
            references.push(ColumnRef {
                artifact: format!("{model}.{kind}.{name}"),
                model: model.clone(),
                kind: kind.to_string(),
                relation,
                column,
                declared_type: None,
            });
        }
    }
    references.sort_by(|a, b| a.artifact.cmp(&b.artifact));
    Ok(Definitions {
        format: "databricks-metric-view".to_string(),
        source: source.to_string(),
        hash,
        models: 1,
        references,
    })
}

/// Loads a Databricks Genie space's serialized JSON. The space's
/// declared column configurations, the columns of each data source
/// table the space is configured to use, are its checkable column
/// surface. Its stored questions and benchmark answers are
/// behavioural ground truth for the auditor's grading design, not
/// upkeep references, and its free-form SQL snippets name no single
/// source table, so neither is read here.
fn genie_from_parsed(root: &Parsed, source: &str, hash: String) -> Result<Definitions, String> {
    let tables = root
        .get("data_sources")
        .and_then(|v| v.get("tables"))
        .and_then(|v| v.as_arr())
        .ok_or_else(|| format!("no data_sources tables in {source}"))?;
    let mut references = Vec::new();
    for table in tables {
        let Some(identifier) = table.get("identifier").and_then(|v| v.as_str()) else {
            continue;
        };
        let relation = normalize_relation(identifier);
        let model = relation.rsplit('.').next().unwrap_or(&relation).to_string();
        let Some(configs) = table.get("column_configs").and_then(|v| v.as_arr()) else {
            continue;
        };
        for config in configs {
            let Some(name) = config.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            references.push(ColumnRef {
                artifact: format!("{model}.column.{name}"),
                model: model.clone(),
                kind: "column".to_string(),
                relation: relation.clone(),
                column: name.to_string(),
                declared_type: None,
            });
        }
    }
    references.sort_by(|a, b| a.artifact.cmp(&b.artifact));
    Ok(Definitions {
        format: "databricks-genie-space".to_string(),
        source: source.to_string(),
        hash,
        models: tables.len(),
        references,
    })
}

/// Loads a JSON definition snapshot, routing on the document's own
/// keys. A document with data sources is a Genie space; a document
/// with semantic models is a dbt manifest.
pub fn load_json_definitions(
    text: &str,
    source: &str,
    hash: String,
) -> Result<Definitions, String> {
    let root = parse(text).ok_or_else(|| format!("definitions do not parse as JSON: {source}"))?;
    if root.get("data_sources").is_some() {
        genie_from_parsed(&root, source, hash)
    } else if root.get("semantic_models").is_some() {
        dbt_from_parsed(&root, source, hash)
    } else {
        Err(format!("unrecognized JSON definition shape in {source}"))
    }
}

/// Loads a YAML definition snapshot, routing on the document's own
/// keys. A document with a tables list is a Snowflake semantic
/// view; a document with a source is a Databricks metric view.
pub fn load_yaml_definitions(
    text: &str,
    source: &str,
    hash: String,
) -> Result<Definitions, String> {
    let root =
        parse_yaml(text).ok_or_else(|| format!("definitions do not parse as YAML: {source}"))?;
    if root.get("tables").and_then(|v| v.as_list()).is_some() {
        snowflake_from_yaml(&root, source, hash)
    } else if root.get("source").and_then(|v| v.as_scalar()).is_some() {
        metric_view_from_yaml(&root, source, hash)
    } else {
        Err(format!("unrecognized YAML definition shape in {source}"))
    }
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
    let definitions = match definitions_path.extension().and_then(|e| e.to_str()) {
        Some("yaml") | Some("yml") => {
            load_yaml_definitions(&definitions_text, &definitions_label, definitions_hash)?
        }
        _ => load_json_definitions(&definitions_text, &definitions_label, definitions_hash)?,
    };
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
    use super::{
        DriftAuditor, StubDriftAuditor, load_dbt_manifest, load_json_definitions, load_live_schema,
        load_snowflake_view, load_yaml_definitions,
    };

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
    time_dimensions:
      - name: ordered_on
        expr: order_date
        data_type: date
    facts:
      - name: amount_fact
        expr: amount
        data_type: number
    metrics:
      - name: revenue
        expr: SUM(amount_fact)
"#;

    const VIEW_LIVE: &str = r#"{
      "tables": {
        "ANALYTICS.PUBLIC.ORDERS": {
          "columns": [
            {"name": "channel", "type": "TEXT"},
            {"name": "orderdate", "type": "DATE"},
            {"name": "amount", "type": "TEXT"}
          ]
        }
      }
    }"#;

    #[test]
    fn the_snowflake_view_yields_typed_references_and_type_drift() {
        let definitions = load_snowflake_view(VIEW, "view.yaml", "d".to_string()).unwrap();
        assert_eq!(definitions.format, "snowflake-semantic-view");
        assert_eq!(definitions.models, 1);
        // The metric composes a fact and is not a reference.
        assert_eq!(definitions.references.len(), 3);
        let fact = definitions
            .references
            .iter()
            .find(|r| r.artifact == "orders.fact.amount_fact")
            .unwrap();
        assert_eq!(fact.relation, "ANALYTICS.PUBLIC.ORDERS");
        assert_eq!(fact.declared_type.as_deref(), Some("number"));
        let live = load_live_schema(VIEW_LIVE, "live.json", "l".to_string()).unwrap();
        let findings = StubDriftAuditor.audit(&definitions, &live);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "AW-DRF-02");
        assert_eq!(findings[0].artifact, "orders.time_dimension.ordered_on");
        assert_eq!(findings[1].rule_id, "AW-DRF-03");
        assert_eq!(findings[1].artifact, "orders.fact.amount_fact");
        assert!(
            findings[1]
                .evidence
                .iter()
                .any(|(k, v)| k == "live_type" && v == "TEXT")
        );
    }

    const METRIC_VIEW: &str = r#"version: 1.1
source: main.sales.orders
filter: "order_date >= '2024-01-01'"
fields:
  - name: channel
    expr: channel
  - name: ordered_on
    expr: order_date
  - name: region
    expr: customers.region
joins:
  - name: customers
    source: main.sales.customers
    on: orders.customer_id = customers.id
measures:
  - name: revenue
    expr: SUM(amount)
"#;

    const METRIC_LIVE: &str = r#"{
      "tables": {
        "main.sales.orders": {"columns": [{"name": "channel", "type": "text"}, {"name": "orderdate", "type": "date"}]},
        "main.sales.customers": {"columns": [{"name": "region", "type": "text"}]}
      }
    }"#;

    #[test]
    fn the_metric_view_routes_by_shape_and_resolves_joins() {
        let definitions = load_yaml_definitions(METRIC_VIEW, "view.yaml", "d".to_string()).unwrap();
        assert_eq!(definitions.format, "databricks-metric-view");
        // The aggregate measure is computed and not a reference.
        assert_eq!(definitions.references.len(), 3);
        let region = definitions
            .references
            .iter()
            .find(|r| r.artifact == "orders.field.region")
            .unwrap();
        assert_eq!(region.relation, "main.sales.customers");
        let live = load_live_schema(METRIC_LIVE, "live.json", "l".to_string()).unwrap();
        let findings = StubDriftAuditor.audit(&definitions, &live);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "AW-DRF-02");
        assert_eq!(findings[0].artifact, "orders.field.ordered_on");
    }

    const GENIE: &str = r#"{
      "version": 2,
      "data_sources": {"tables": [
        {"identifier": "main.sales.orders", "column_configs": [{"name": "order_id"}, {"name": "amount"}]},
        {"identifier": "main.sales.customers", "column_configs": [{"name": "region"}]}
      ]},
      "benchmarks": {"questions": []}
    }"#;

    const GENIE_LIVE: &str = r#"{
      "tables": {
        "main.sales.orders": {"columns": [{"name": "order_id", "type": "integer"}]},
        "main.sales.customers": {"columns": [{"name": "region", "type": "text"}]}
      }
    }"#;

    #[test]
    fn the_genie_space_routes_by_shape_and_reads_column_configs() {
        let definitions = load_json_definitions(GENIE, "space.json", "d".to_string()).unwrap();
        assert_eq!(definitions.format, "databricks-genie-space");
        assert_eq!(definitions.models, 2);
        assert_eq!(definitions.references.len(), 3);
        let live = load_live_schema(GENIE_LIVE, "live.json", "l".to_string()).unwrap();
        let findings = StubDriftAuditor.audit(&definitions, &live);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "AW-DRF-01");
        assert_eq!(findings[0].artifact, "orders.column.amount");
    }

    #[test]
    fn tab_indented_yaml_is_refused_whole() {
        let bad = "tables:\n\t- name: orders\n";
        assert!(load_snowflake_view(bad, "view.yaml", "d".to_string()).is_err());
    }

    #[test]
    fn computed_expressions_are_not_column_references() {
        let manifest = r#"{"semantic_models": [{"name": "m", "node_relation": {"relation_name": "t"}, "measures": [{"name": "x", "agg": "sum", "expr": "amount * 2"}]}]}"#;
        let definitions = load_dbt_manifest(manifest, "m.json", "d".to_string()).unwrap();
        assert_eq!(definitions.references.len(), 0);
    }
}
