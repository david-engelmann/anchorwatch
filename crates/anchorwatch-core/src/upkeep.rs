//! The upkeep pass.
//!
//! A pass takes a bundle path, a pinned as-of instant, and a mode.
//! Given the same bundle, the same as-of, and the same auditor, a
//! pass produces a byte-identical report. Traversal order is sorted.
//! Nothing in a pass contacts the network or calls a language model.
//!
//! The steps run in the contract's order: snapshot, audit intake,
//! lapse recompute, supersession audit, index regeneration, log
//! entry, queue maintenance, report. The engine's never list binds
//! every step: it never edits a concept body, never stamps a
//! verification event, never sets or removes a review date, never
//! chooses a supersession target, and never deletes a file. The one
//! frontmatter repair it may apply is restoring a stripped `type`
//! key from the state manifest, always logged; that repair is part
//! of the type guard and is applied only in apply mode.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::CONTRACT_VERSION;
use crate::auditor::{Auditor, AuditorReport, Finding, Tier};
use crate::bundle::{Bundle, StateManifest};
use crate::json::Json;
use crate::queue::{
    INDEX_DRIFT, LAPSED_VERIFICATION, NO_REVIEW_DATE, PROVENANCE_GAP, QueueItem, QueueState, STALE,
    SUPERSESSION_DEFECT, TIER_DROP, TYPE_MISSING, sort_queue,
};
use crate::sha256::sha256_hex;
use crate::time::parse_timestamp;

/// Whether a pass writes its maintenance artefacts or only reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Compute everything, write nothing.
    DryRun,
    /// Compute, then write the queue, the pass state, regenerated
    /// indexes that carry no hand-written prose, and the log entry.
    Apply,
}

impl Mode {
    /// The mode name as emitted in reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::DryRun => "dry-run",
            Mode::Apply => "apply",
        }
    }
}

/// The outcome of one pass. Renders to JSON and Markdown, both
/// deterministic for the same inputs.
#[derive(Debug, Clone)]
pub struct PassReport {
    /// The deterministic run identifier.
    pub run_id: String,
    /// The pinned as-of instant.
    pub as_of: String,
    /// The mode the pass ran in.
    pub mode: Mode,
    /// The bundle snapshot hash recorded at intake.
    pub snapshot_hash: String,
    /// The number of concepts found.
    pub concept_count: usize,
    /// The auditor report the pass consumed.
    pub auditor_report: AuditorReport,
    /// The queue after this pass, in work order.
    pub queue: Vec<QueueItem>,
    /// How many items this pass raised for the first time.
    pub raised: usize,
    /// How many previously open items this pass closed on evidence.
    pub closed: usize,
    /// Actions the pass took or, in dry-run, would take.
    pub actions: Vec<String>,
    /// Notes a reader needs, including every coverage gap.
    pub notes: Vec<String>,
}

impl PassReport {
    /// Renders the report as deterministic JSON.
    pub fn to_json(&self) -> String {
        let findings = self
            .auditor_report
            .findings
            .iter()
            .map(finding_json)
            .collect();
        let queue = self.queue.iter().map(queue_item_json).collect();
        let provenance = self
            .auditor_report
            .provenance
            .iter()
            .map(|entry| {
                Json::obj(vec![
                    ("concept", Json::Str(entry.concept.clone())),
                    ("has_sources", Json::Bool(entry.has_sources)),
                    ("local_sources", Json::Int(entry.local_sources as i64)),
                    ("unresolved", Json::Int(entry.unresolved as i64)),
                ])
            })
            .collect();
        let coverage = Json::Obj(
            self.auditor_report
                .coverage
                .iter()
                .map(|(call, ok)| (call.clone(), Json::Bool(*ok)))
                .collect::<BTreeMap<_, _>>(),
        );
        Json::obj(vec![
            ("actions", Json::strings(&self.actions)),
            ("as_of", Json::Str(self.as_of.clone())),
            ("auditor", Json::Str(self.auditor_report.auditor.clone())),
            (
                "auditor_schema",
                Json::Str(self.auditor_report.schema_version.clone()),
            ),
            ("bundle_snapshot", Json::Str(self.snapshot_hash.clone())),
            ("closed", Json::Int(self.closed as i64)),
            ("concepts", Json::Int(self.concept_count as i64)),
            ("contract", Json::Str(CONTRACT_VERSION.to_string())),
            ("coverage", coverage),
            ("findings", Json::Arr(findings)),
            ("mode", Json::Str(self.mode.as_str().to_string())),
            ("notes", Json::strings(&self.notes)),
            ("provenance", Json::Arr(provenance)),
            ("queue", Json::Arr(queue)),
            ("raised", Json::Int(self.raised as i64)),
            ("run_id", Json::Str(self.run_id.clone())),
        ])
        .render()
    }

    /// Renders the report as Markdown for a human reader.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Upkeep pass {}\n\n", self.run_id));
        out.push_str(&format!(
            "As of {}. Mode {}. Bundle snapshot {}. {} concepts.\n\n",
            self.as_of,
            self.mode.as_str(),
            &self.snapshot_hash[..12],
            self.concept_count
        ));
        out.push_str(&format!(
            "Queue: {} items, {} raised by this pass, {} closed on evidence.\n\n",
            self.queue.len(),
            self.raised,
            self.closed
        ));
        out.push_str("## Queue\n\n");
        if self.queue.is_empty() {
            out.push_str("No open items.\n\n");
        }
        for item in &self.queue {
            let evidence: Vec<String> = item
                .evidence
                .iter()
                .map(|(k, v)| format!("{k} {v}"))
                .collect();
            out.push_str(&format!(
                "- {} on {} ({}): {}\n",
                item.reason,
                item.concept,
                item.state.as_str(),
                evidence.join(", ")
            ));
        }
        out.push_str("\n## Auditor findings\n\n");
        if self.auditor_report.findings.is_empty() {
            out.push_str("None.\n\n");
        }
        for finding in &self.auditor_report.findings {
            out.push_str(&format!(
                "- {} on {} ({})\n",
                finding.rule_id,
                finding.concept,
                finding.severity.as_str()
            ));
        }
        out.push_str("\n## Notes\n\n");
        for note in &self.notes {
            out.push_str(&format!("- {note}\n"));
        }
        out
    }
}

fn finding_json(finding: &Finding) -> Json {
    Json::obj(vec![
        ("concept", Json::Str(finding.concept.clone())),
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

/// Runs one upkeep pass over the bundle at `root`.
pub fn run_pass(
    root: &Path,
    as_of: &str,
    auditor: &dyn Auditor,
    mode: Mode,
) -> Result<PassReport, String> {
    parse_timestamp(as_of).ok_or_else(|| format!("as-of instant does not parse: {as_of}"))?;
    let bundle = Bundle::load(root)?;
    let snapshot_hash = bundle.snapshot_hash();
    let run_id = format!(
        "run-{}",
        &sha256_hex(format!("{snapshot_hash}|{as_of}|{}", auditor.name()).as_bytes())[..12]
    );
    let mut notes = Vec::new();
    let mut actions = Vec::new();

    // Step 2, audit intake. The auditor never mutates the bundle.
    let auditor_report = auditor.audit(&bundle, as_of);
    for (call, covered) in &auditor_report.coverage {
        if !covered {
            notes.push(format!(
                "auditor call not covered by the {} auditor: {call}",
                auditor_report.auditor
            ));
        }
    }

    // Previous state: tiers and current-event counts from the last
    // pass, and the queue as it stood. Absence means a first pass,
    // which establishes the baseline instead of inventing history.
    let prev_state = load_pass_state(root);
    let prev_queue = load_previous_queue(root);
    if prev_state.is_empty() {
        notes.push("no previous pass state; this pass establishes the tier baseline".to_string());
    }

    let mut items: Vec<QueueItem> = Vec::new();
    let currency_by_concept: BTreeMap<&str, &crate::auditor::CurrencyEntry> = auditor_report
        .currency
        .iter()
        .map(|entry| (entry.concept.as_str(), entry))
        .collect();

    // Step 3, lapse recompute. Staleness arrives as auditor
    // freshness findings; the engine derives no dates of its own.
    // The absence rule is the engine's: a concept with no review
    // date is queued for one, never given one.
    for finding in &auditor_report.findings {
        if finding.rule_id == "AW-FRE-01" || finding.rule_id == "AW-FRE-02" {
            let mut evidence = vec![("rule_id".to_string(), finding.rule_id.clone())];
            evidence.extend(finding.evidence.iter().cloned());
            if finding.rule_id == "AW-FRE-02" {
                evidence.push(("malformed".to_string(), "true".to_string()));
            }
            let mut item = QueueItem::new(finding.concept.clone(), STALE, evidence, &run_id);
            item.priority = 1;
            items.push(item);
        }
        if finding.rule_id.starts_with("AW-PRO-") {
            let mut evidence = vec![("rule_id".to_string(), finding.rule_id.clone())];
            evidence.extend(finding.evidence.iter().cloned());
            items.push(QueueItem::new(
                finding.concept.clone(),
                PROVENANCE_GAP,
                evidence,
                &run_id,
            ));
        }
    }
    for concept in bundle.concepts() {
        let fm = &concept.frontmatter;
        if fm.stale_after.is_none() {
            items.push(QueueItem::new(
                concept.relpath.clone(),
                NO_REVIEW_DATE,
                vec![("stale_after".to_string(), "(absent)".to_string())],
                &run_id,
            ));
        }
        if let Some(entry) = currency_by_concept.get(concept.relpath.as_str())
            && let Some(prev) = prev_state.get(&concept.relpath)
            && let Some(prev_tier) = Tier::from_name(&prev.tier)
        {
            if entry.tier < prev_tier {
                let mut item = QueueItem::new(
                    concept.relpath.clone(),
                    TIER_DROP,
                    vec![
                        ("tier_before".to_string(), prev.tier.clone()),
                        ("tier_after".to_string(), entry.tier.as_str().to_string()),
                    ],
                    &run_id,
                );
                if prev_tier == Tier::HumanReviewed {
                    item.priority = 0;
                }
                items.push(item);
            }
            if prev.current_events > 0 && entry.current_events == 0 {
                items.push(QueueItem::new(
                    concept.relpath.clone(),
                    LAPSED_VERIFICATION,
                    vec![
                        (
                            "current_events_before".to_string(),
                            prev.current_events.to_string(),
                        ),
                        ("current_events".to_string(), "0".to_string()),
                    ],
                    &run_id,
                ));
            }
        }
    }
    if auditor_report
        .coverage
        .iter()
        .any(|(call, covered)| call == "freshness" && !covered)
    {
        notes.push(
            "the auditor freshness call is uncovered; no STALE items were derived this pass"
                .to_string(),
        );
    }

    // Step 4, supersession audit. Declared chains are authoritative;
    // defects and proposals arrive as auditor findings.
    for finding in &auditor_report.findings {
        if finding.rule_id.starts_with("AW-SUP-") {
            let mut evidence = vec![("rule_id".to_string(), finding.rule_id.clone())];
            evidence.extend(finding.evidence.iter().cloned());
            items.push(QueueItem::new(
                finding.concept.clone(),
                SUPERSESSION_DEFECT,
                evidence,
                &run_id,
            ));
        }
    }

    // The type-stripping guard, driven by the migrator's manifest.
    let manifest = StateManifest::load(root);
    for (relpath, recorded_type) in &manifest.concepts {
        match bundle.file(relpath) {
            Some(file) => {
                if !file.is_concept() {
                    items.push(QueueItem::new(
                        relpath.clone(),
                        TYPE_MISSING,
                        vec![("recorded_type".to_string(), recorded_type.clone())],
                        &run_id,
                    ));
                }
            }
            None => notes.push(format!(
                "manifest concept absent from the tree, reported rather than guessed: {relpath}"
            )),
        }
    }

    // Step 5, index drift. Regeneration content is computed for
    // every index; a directory whose index carries hand-written
    // prose is flagged and never rewritten by the pass.
    let drift = index_drift(&bundle);
    for (index_relpath, expected, actual, has_prose) in &drift {
        items.push(QueueItem::new(
            index_relpath.clone(),
            INDEX_DRIFT,
            vec![
                ("expected_links".to_string(), expected.to_string()),
                ("actual_links".to_string(), actual.to_string()),
                ("hand_written_prose".to_string(), has_prose.to_string()),
            ],
            &run_id,
        ));
    }

    // Step 7, queue maintenance against the previous queue. An item
    // keeps its first run and its human-set state while its
    // condition holds. An item whose condition no longer holds
    // closes on that observed evidence, never by assertion.
    let (queue, raised, closed) = merge_queue(items, prev_queue, &run_id);
    let mut queue = queue;
    sort_queue(&mut queue);

    if mode == Mode::Apply {
        apply_writes(
            root,
            &bundle,
            &run_id,
            as_of,
            &auditor_report,
            &queue,
            &drift,
            &mut actions,
        )?;
    } else {
        actions.push("dry-run: no files written".to_string());
    }

    Ok(PassReport {
        run_id,
        as_of: as_of.to_string(),
        mode,
        snapshot_hash,
        concept_count: bundle.concepts().count(),
        auditor_report,
        queue,
        raised,
        closed,
        actions,
        notes,
    })
}

/// One concept's recorded state from the previous pass.
struct PrevTier {
    tier: String,
    current_events: usize,
}

/// Loads `.recension/pass-state.json` written by the previous apply
/// pass. The file is this engine's own format: two flat maps from
/// concept path to tier name and to current-event count.
fn load_pass_state(root: &Path) -> BTreeMap<String, PrevTier> {
    let path = root.join(".recension").join("pass-state.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let tiers = extract_string_map(&text, "tiers");
    let counts = extract_string_map(&text, "current_events");
    tiers
        .into_iter()
        .map(|(concept, tier)| {
            let current_events = counts
                .get(&concept)
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            (
                concept,
                PrevTier {
                    tier,
                    current_events,
                },
            )
        })
        .collect()
}

/// Extracts one flat string-to-string object from JSON text by key.
/// The engine reads only its own artefacts and the migrator's
/// manifest, whose shapes are flat by construction; this narrow scan
/// is deliberate, and it never runs on untrusted shapes.
fn extract_string_map(text: &str, wanted: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let needle = format!("\"{wanted}\"");
    let Some(start) = text.find(&needle) else {
        return out;
    };
    let rest = &text[start + needle.len()..];
    let Some(open) = rest.find('{') else {
        return out;
    };
    let body = &rest[open + 1..];
    let mut depth = 1usize;
    let mut current = String::new();
    let mut entries = Vec::new();
    for ch in body.chars() {
        match ch {
            '{' => {
                depth += 1;
                current.push(ch);
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                current.push(ch);
            }
            ',' if depth == 1 => entries.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        entries.push(current);
    }
    for entry in entries {
        if let Some((key, value)) = entry.split_once(':') {
            let key = key.trim().trim_matches('"').to_string();
            let value = value.trim().trim_matches('"').to_string();
            if !key.is_empty() {
                out.insert(key, value);
            }
        }
    }
    out
}

/// Loads the queue as the previous pass left it. Only the fields the
/// merge preserves are read: concept, reason, first run, and state.
/// Evidence keys written by this engine never reuse those field
/// names, which is what makes the sequential scan unambiguous.
/// The queue's home is `.recension/queue.json`; the legacy home
/// under `upkeep/` is read as a fallback so a bundle's queue
/// history survives the move.
fn load_previous_queue(root: &Path) -> Vec<QueueItem> {
    let text = std::fs::read_to_string(root.join(".recension").join("queue.json"))
        .or_else(|_| std::fs::read_to_string(root.join("upkeep").join("queue.json")));
    let Ok(text) = text else {
        return Vec::new();
    };
    let mut items = Vec::new();
    let mut current: Option<QueueItem> = None;
    for (key, value) in scan_string_fields(&text) {
        match key.as_str() {
            "concept" => {
                if let Some(item) = current.take() {
                    items.push(item);
                }
                current = Some(QueueItem::new(value, "", Vec::new(), ""));
            }
            "reason" => {
                if let Some(item) = current.as_mut()
                    && item.reason.is_empty()
                {
                    item.reason = value;
                }
            }
            "first_raised" => {
                if let Some(item) = current.as_mut()
                    && item.first_raised.is_empty()
                {
                    item.first_raised = value;
                }
            }
            "state" => {
                if let Some(item) = current.as_mut()
                    && let Some(state) = QueueState::from_name(&value)
                {
                    item.state = state;
                }
            }
            _ => {}
        }
    }
    if let Some(item) = current.take() {
        items.push(item);
    }
    items
        .into_iter()
        .filter(|item| !item.concept.is_empty() && !item.reason.is_empty())
        .collect()
}

/// Scans JSON text for `"key": "value"` string pairs, in order.
fn scan_string_fields(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let Some((value, next)) = read_json_string(text, i) else {
                break;
            };
            let mut j = next;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b':' {
                j += 1;
                while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                    j += 1;
                }
                if j < bytes.len()
                    && bytes[j] == b'"'
                    && let Some((field_value, after)) = read_json_string(text, j)
                {
                    out.push((value, field_value));
                    i = after;
                    continue;
                }
            }
            i = next;
        } else {
            i += 1;
        }
    }
    out
}

fn read_json_string(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                let esc = bytes.get(i + 1)?;
                match esc {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    _ => out.push(*esc as char),
                }
                i += 2;
            }
            _ => {
                let ch_len = utf8_len(bytes[i]);
                out.push_str(&text[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    None
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// Merges freshly derived items with the previous queue.
pub(crate) fn merge_queue(
    fresh: Vec<QueueItem>,
    previous: Vec<QueueItem>,
    run_id: &str,
) -> (Vec<QueueItem>, usize, usize) {
    let prev_by_key: BTreeMap<(String, String), &QueueItem> = previous
        .iter()
        .map(|item| ((item.concept.clone(), item.reason.clone()), item))
        .collect();
    let mut raised = 0usize;
    let mut merged = Vec::new();
    for mut item in fresh {
        match prev_by_key.get(&(item.concept.clone(), item.reason.clone())) {
            Some(prev) => {
                item.first_raised = prev.first_raised.clone();
                if prev.state == QueueState::Waived || prev.state == QueueState::Claimed {
                    item.state = prev.state;
                }
                item.last_confirmed = run_id.to_string();
            }
            None => raised += 1,
        }
        merged.push(item);
    }
    let fresh_keys: BTreeSet<(String, String)> = merged
        .iter()
        .map(|item| (item.concept.clone(), item.reason.clone()))
        .collect();
    let mut closed = 0usize;
    for prev in previous {
        if prev.state != QueueState::Done
            && prev.state != QueueState::Waived
            && !fresh_keys.contains(&(prev.concept.clone(), prev.reason.clone()))
        {
            closed += 1;
        }
    }
    (merged, raised, closed)
}

/// One index whose link set disagrees with its directory:
/// the index path, expected link count, actual link count, and
/// whether the existing index carries hand-written prose.
type Drift = (String, usize, usize, bool);

fn index_drift(bundle: &Bundle) -> Vec<Drift> {
    let mut drift = Vec::new();
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    dirs.insert(String::new());
    for file in &bundle.files {
        if let Some(slash) = file.relpath.rfind('/') {
            dirs.insert(file.relpath[..slash].to_string());
        }
    }
    for dir in dirs {
        let index_rel = if dir.is_empty() {
            "index.md".to_string()
        } else {
            format!("{dir}/index.md")
        };
        let expected: BTreeSet<String> = if dir.is_empty() {
            bundle.concepts().map(|c| c.relpath.clone()).collect()
        } else {
            bundle
                .concepts()
                .filter(|c| parent_dir(&c.relpath) == dir)
                .map(|c| {
                    c.relpath
                        .rsplit('/')
                        .next()
                        .unwrap_or(&c.relpath)
                        .to_string()
                })
                .collect()
        };
        if expected.is_empty() && bundle.file(&index_rel).is_none() {
            continue;
        }
        let actual: BTreeSet<String> = match bundle.file(&index_rel) {
            Some(file) => {
                let text =
                    std::fs::read_to_string(bundle.root.join(&file.relpath)).unwrap_or_default();
                extract_links(&text)
            }
            None => BTreeSet::new(),
        };
        if expected != actual {
            let has_prose = bundle
                .file(&index_rel)
                .map(|file| {
                    let text = std::fs::read_to_string(bundle.root.join(&file.relpath))
                        .unwrap_or_default();
                    index_has_prose(&text)
                })
                .unwrap_or(false);
            drift.push((index_rel, expected.len(), actual.len(), has_prose));
        }
    }
    drift
}

fn parent_dir(relpath: &str) -> String {
    match relpath.rfind('/') {
        Some(idx) => relpath[..idx].to_string(),
        None => String::new(),
    }
}

fn extract_links(text: &str) -> BTreeSet<String> {
    let mut links = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find("](") {
        let after = &rest[start + 2..];
        if let Some(end) = after.find(')') {
            links.insert(after[..end].to_string());
            rest = &after[end..];
        } else {
            break;
        }
    }
    links
}

fn index_has_prose(text: &str) -> bool {
    let mut in_frontmatter = false;
    for (i, line) in text.lines().enumerate() {
        if i == 0 && line == "---" {
            in_frontmatter = true;
            continue;
        }
        if in_frontmatter {
            if line == "---" {
                in_frontmatter = false;
            }
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("* [") {
            continue;
        }
        return true;
    }
    false
}

/// Renders the generated form of one directory index from concept
/// frontmatter, in the same shape the migrator writes. The bundle
/// root's existing frontmatter is preserved exactly.
fn regenerate_index(bundle: &Bundle, dir: &str) -> String {
    let title_of = |c: &crate::bundle::ConceptFile| {
        c.frontmatter
            .title
            .clone()
            .unwrap_or_else(|| c.relpath.clone())
    };
    if dir.is_empty() {
        let mut out = String::new();
        if let Some(existing) = bundle.file("index.md") {
            if let Ok(text) = std::fs::read_to_string(bundle.root.join("index.md"))
                && let Some(body) = text.strip_prefix("---\n")
                && let Some(end) = body.find("\n---")
            {
                out.push_str(&text[..4 + end + 4]);
                out.push('\n');
            }
            let _ = existing;
        }
        if out.is_empty() {
            out.push_str("---\nokf_version: \"0.3\"\ntitle: \"Bundle index\"\n---\n");
        }
        let root_title = bundle
            .file("index.md")
            .and_then(|f| f.frontmatter.title.clone())
            .unwrap_or_else(|| "Bundle index".to_string());
        out.push_str(&format!("\n# {root_title}\n"));
        let mut dirs: BTreeSet<String> = BTreeSet::new();
        for concept in bundle.concepts() {
            dirs.insert(parent_dir(&concept.relpath));
        }
        for sub in dirs {
            if sub.is_empty() {
                let mut root_concepts: Vec<&crate::bundle::ConceptFile> = bundle
                    .concepts()
                    .filter(|c| parent_dir(&c.relpath).is_empty())
                    .collect();
                root_concepts.sort_by(|a, b| a.relpath.cmp(&b.relpath));
                for concept in root_concepts {
                    out.push_str(&format!("\n* [{}]({})", title_of(concept), concept.relpath));
                }
                out.push('\n');
                continue;
            }
            out.push_str(&format!("\n# {sub}\n"));
            let mut members: Vec<&crate::bundle::ConceptFile> = bundle
                .concepts()
                .filter(|c| parent_dir(&c.relpath) == sub)
                .collect();
            members.sort_by(|a, b| a.relpath.cmp(&b.relpath));
            for concept in members {
                out.push_str(&format!("\n* [{}]({})", title_of(concept), concept.relpath));
            }
            out.push('\n');
        }
        return out;
    }
    let mut out = format!("# {dir}\n");
    let mut members: Vec<&crate::bundle::ConceptFile> = bundle
        .concepts()
        .filter(|c| parent_dir(&c.relpath) == dir)
        .collect();
    members.sort_by(|a, b| a.relpath.cmp(&b.relpath));
    for concept in members {
        let name = concept
            .relpath
            .rsplit('/')
            .next()
            .unwrap_or(&concept.relpath);
        out.push_str(&format!("\n* [{}]({name})", title_of(concept)));
    }
    out.push('\n');
    out
}

/// Inserts a restored `type` line at the head of a document's
/// frontmatter block. Returns None when the document has no
/// frontmatter block, when the block never closes, or when a type
/// key is already present, so the repair never guesses.
fn restore_type_line(text: &str, recorded: &str) -> Option<String> {
    let mut lines = text.lines();
    if lines.next()?.trim_end() != "---" {
        return None;
    }
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" {
            let insert_at = text.find('\n')? + 1;
            let mut out = String::with_capacity(text.len() + recorded.len() + 8);
            out.push_str(&text[..insert_at]);
            out.push_str("type: ");
            out.push_str(recorded);
            out.push('\n');
            out.push_str(&text[insert_at..]);
            return Some(out);
        }
        if trimmed.starts_with("type:") || trimmed.starts_with("type :") {
            return None;
        }
    }
    None
}

/// Apply-mode writes: queue files, pass state, prose-free index
/// regeneration, the logged type restoration, and the log entry.
/// Nothing outside the bundle root is written.
#[allow(clippy::too_many_arguments)]
fn apply_writes(
    root: &Path,
    bundle: &Bundle,
    run_id: &str,
    as_of: &str,
    auditor_report: &AuditorReport,
    queue: &[QueueItem],
    drift: &[Drift],
    actions: &mut Vec<String>,
) -> Result<(), String> {
    // The one autonomous frontmatter repair: restoring a stripped
    // type key from the migrator's manifest, for an open item whose
    // file still carries its frontmatter block. A file that lost
    // the whole block, and any item a human has claimed or waived,
    // is left for a human. Every repair is logged in the actions,
    // and the item itself closes on the next pass, which observes
    // the restored key as evidence.
    for item in queue {
        if item.reason != TYPE_MISSING || item.state != QueueState::Open {
            continue;
        }
        let Some(recorded) = item
            .evidence
            .iter()
            .find(|(key, _)| key == "recorded_type")
            .map(|(_, value)| value.clone())
        else {
            continue;
        };
        let Some(file) = bundle.file(&item.concept) else {
            continue;
        };
        if !file.has_frontmatter {
            continue;
        }
        let path = root.join(&item.concept);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(repaired) = restore_type_line(&text, &recorded) {
            std::fs::write(&path, repaired)
                .map_err(|e| format!("cannot write {}: {e}", item.concept))?;
            actions.push(format!(
                "type restored from the manifest: {} ({recorded})",
                item.concept
            ));
        }
    }
    // Index regeneration for drifted indexes without prose.
    for (index_rel, _, _, has_prose) in drift {
        if *has_prose {
            actions.push(format!(
                "index left untouched, hand-written prose present: {index_rel}"
            ));
            continue;
        }
        let dir = parent_dir(index_rel);
        let content = regenerate_index(bundle, &dir);
        let path = root.join(index_rel);
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if existing != content {
            std::fs::write(&path, content).map_err(|e| format!("cannot write {index_rel}: {e}"))?;
            actions.push(format!("index regenerated: {index_rel}"));
        }
    }
    // Queue files, Markdown with a JSON twin, in the engine's own
    // dot directory beside the pass state.
    let upkeep_dir = root.join(".recension");
    std::fs::create_dir_all(&upkeep_dir)
        .map_err(|e| format!("cannot create state directory: {e}"))?;
    let queue_json = Json::obj(vec![
        ("as_of", Json::Str(as_of.to_string())),
        (
            "items",
            Json::Arr(queue.iter().map(queue_item_json).collect()),
        ),
        ("run_id", Json::Str(run_id.to_string())),
    ])
    .render();
    std::fs::write(upkeep_dir.join("queue.json"), queue_json)
        .map_err(|e| format!("cannot write queue.json: {e}"))?;
    let mut queue_md = format!("# Re-verification queue\n\nPass {run_id}, as of {as_of}.\n");
    for item in queue {
        let evidence: Vec<String> = item
            .evidence
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect();
        queue_md.push_str(&format!(
            "\n- {} on {} ({}): {}",
            item.reason,
            item.concept,
            item.state.as_str(),
            evidence.join(", ")
        ));
    }
    queue_md.push('\n');
    std::fs::write(upkeep_dir.join("queue.md"), queue_md)
        .map_err(|e| format!("cannot write queue.md: {e}"))?;
    actions.push("queue written to .recension/queue.md and .recension/queue.json".to_string());
    // A legacy queue under upkeep/ is removed once its successor
    // is written, but only when it reads as this engine's own
    // queue file, so an unrelated file is never deleted.
    let legacy_json = root.join("upkeep").join("queue.json");
    if legacy_json.exists()
        && std::fs::read_to_string(&legacy_json).is_ok_and(|text| text.contains("\"items\""))
        && std::fs::remove_file(&legacy_json).is_ok()
    {
        let _ = std::fs::remove_file(root.join("upkeep").join("queue.md"));
        actions.push(
            "legacy queue files under upkeep/ removed after the move to .recension/".to_string(),
        );
    }
    // Pass state for the next pass's baseline.
    let state_dir = root.join(".recension");
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| format!("cannot create state directory: {e}"))?;
    let tiers: BTreeMap<String, Json> = auditor_report
        .currency
        .iter()
        .map(|entry| {
            (
                entry.concept.clone(),
                Json::Str(entry.tier.as_str().to_string()),
            )
        })
        .collect();
    let counts: BTreeMap<String, Json> = auditor_report
        .currency
        .iter()
        .map(|entry| {
            (
                entry.concept.clone(),
                Json::Str(entry.current_events.to_string()),
            )
        })
        .collect();
    let state = Json::obj(vec![
        ("as_of", Json::Str(as_of.to_string())),
        ("current_events", Json::Obj(counts)),
        ("run_id", Json::Str(run_id.to_string())),
        ("snapshot", Json::Str(bundle.snapshot_hash())),
        ("tiers", Json::Obj(tiers)),
    ])
    .render();
    std::fs::write(state_dir.join("pass-state.json"), state)
        .map_err(|e| format!("cannot write pass state: {e}"))?;
    actions.push("pass state recorded at .recension/pass-state.json".to_string());
    // Log entry, grouped under the run date. Section 9 of the spec
    // orders log groups newest first, so the entry is inserted in
    // date order rather than appended at the end of the file.
    let date = &as_of[..10.min(as_of.len())];
    let log_path = root.join("log.md");
    let log =
        std::fs::read_to_string(&log_path).unwrap_or_else(|_| "# Bundle Update Log\n".to_string());
    let open = queue.iter().filter(|i| i.state == QueueState::Open).count();
    let entry = format!(
        "* **Upkeep**: Pass {run_id} at {as_of}. Queue holds {open} open items. Auditor {} reported {} findings.",
        auditor_report.auditor,
        auditor_report.findings.len()
    );
    let log = insert_log_entry(&log, date, &entry);
    std::fs::write(&log_path, log).map_err(|e| format!("cannot write log.md: {e}"))?;
    actions.push("log entry recorded in log.md".to_string());
    Ok(())
}

/// Inserts one entry into a bundle log under its date group, keeping
/// the section 9 order of groups, newest date first. An entry for a
/// date that already has a group lands at the end of that group,
/// wherever the group sits. A new group is placed before the first
/// older group, and after the title when every group is newer. The
/// title line, when the log carries one, stays first. Groups already
/// in the file are never reordered; the pass maintains the order in
/// the entries it adds.
fn insert_log_entry(log: &str, date: &str, entry: &str) -> String {
    let heading = format!("## {date}");
    let mut lines: Vec<String> = log.lines().map(str::to_string).collect();
    if let Some(start) = lines
        .iter()
        .position(|line| line.as_str() == heading.as_str())
    {
        let end = lines[start + 1..]
            .iter()
            .position(|line| line.starts_with("## "))
            .map_or(lines.len(), |p| start + 1 + p);
        let mut at = end;
        while at > start + 1 && lines[at - 1].is_empty() {
            at -= 1;
        }
        lines.insert(at, entry.to_string());
        return lines.join("\n") + "\n";
    }
    let mut at = lines.len();
    for (i, line) in lines.iter().enumerate() {
        let Some(group) = line.strip_prefix("## ") else {
            continue;
        };
        let token = group.split_whitespace().next().unwrap_or("");
        let is_date = token.len() == 10 && token.chars().all(|c| c.is_ascii_digit() || c == '-');
        if is_date && token < date {
            at = i;
            break;
        }
    }
    if at == lines.len() {
        if !lines.is_empty() && !lines[lines.len() - 1].is_empty() {
            lines.push(String::new());
        }
        lines.push(heading);
        lines.push(entry.to_string());
    } else {
        lines.insert(at, String::new());
        lines.insert(at, entry.to_string());
        lines.insert(at, heading);
    }
    lines.join("\n") + "\n"
}
