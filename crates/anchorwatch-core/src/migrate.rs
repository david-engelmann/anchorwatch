//! The migrator: profile-based conversion of a memory-shaped tree
//! into an OKF v0.3 bundle, judged by its loss ledger.
//!
//! The migrator is not a generic Markdown converter. A source
//! profile knows how to find the constructs of one tree shape and
//! how each construct converts. Every construct the profile finds
//! must appear in the ledger the run ships with the bundle, under
//! one of five dispositions, and the run report lists construct
//! classes found against entries written so a gap is checkable.
//! Two gates bind every run. A ledger whose entries are all Mapped
//! claims zero loss, which on a real tree is a failed run rather
//! than a good one. And an entry flagged load-bearing with a
//! disposition of Lost fails the migration visibly, though the
//! bundle and ledger are still written, because the finding is
//! the point.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::json::Json;
use crate::sha256::sha256_hex;
use crate::time::parse_timestamp;

/// What happened to one source construct in conversion, in the
/// ledger's five values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The construct has a standard OKF home and arrived intact.
    Mapped,
    /// Something survives in a weaker form.
    Approximated,
    /// The data survives under an x- extension key.
    PreservedAsExtension,
    /// The migrator left the construct out on purpose.
    Excluded,
    /// Nothing machine-readable survives.
    Lost,
}

impl Disposition {
    /// The disposition as written in the ledger.
    pub fn as_str(&self) -> &'static str {
        match self {
            Disposition::Mapped => "Mapped",
            Disposition::Approximated => "Approximated",
            Disposition::PreservedAsExtension => "Preserved as extension",
            Disposition::Excluded => "Excluded",
            Disposition::Lost => "Lost",
        }
    }
}

/// One ledger entry as shipped, with its run-sequential identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Sequential per run, in the form L-001.
    pub id: String,
    /// The source construct, named plainly.
    pub construct: String,
    /// The count measured in the source during the run.
    pub count: usize,
    /// What happened to the construct.
    pub disposition: Disposition,
    /// The OKF field or file that receives it, or the word none.
    pub target: String,
    /// Why, in plain language.
    pub reason: String,
    /// Whether the bundle owner would call the construct part of
    /// the source's value.
    pub load_bearing: bool,
    /// What a future version would need to recover it.
    pub recovery: String,
}

/// One ledger entry as a profile drafts it, before the run assigns
/// identifiers. The construct name doubles as the reconciliation
/// key: the run requires an entry for every class the profile
/// reports finding, and no entry for a class it did not.
#[derive(Debug, Clone)]
pub struct LedgerDraft {
    /// The source construct, named plainly.
    pub construct: String,
    /// The count measured in the source during the run.
    pub count: usize,
    /// What happened to the construct.
    pub disposition: Disposition,
    /// The OKF field or file that receives it, or the word none.
    pub target: String,
    /// Why, in plain language.
    pub reason: String,
    /// Whether the construct is load-bearing.
    pub load_bearing: bool,
    /// What a future version would need to recover it.
    pub recovery: String,
}

/// One construct class a profile found in the source, with the
/// count it measured. The reconciliation surface of the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructClass {
    /// The class name, matching the ledger entries' construct.
    pub name: String,
    /// How much of it the source holds.
    pub count: usize,
}

/// One converted concept file, ready to write.
#[derive(Debug, Clone)]
pub struct ConvertedConcept {
    /// Bundle-relative path of the concept file.
    pub relpath: String,
    /// The concept's type, for the state manifest.
    pub concept_type: String,
    /// The concept's title, for the indexes.
    pub title: String,
    /// The complete file content.
    pub content: String,
}

/// What a profile produces from one source tree: the construct
/// classes it found, the concepts it converted, and the ledger
/// entries it drafts.
#[derive(Debug, Clone)]
pub struct ProfileOutcome {
    /// Every construct class found, counts measured this run.
    pub classes: Vec<ConstructClass>,
    /// The converted concepts, in write order.
    pub concepts: Vec<ConvertedConcept>,
    /// The ledger entries drafted, in ledger order.
    pub drafts: Vec<LedgerDraft>,
}

/// A source profile: the constructs of one tree shape, and how
/// each converts. Profiles measure counts during the same walk
/// that converts, because the tree is live and counts copied from
/// anywhere else would be fiction.
pub trait Profile {
    /// The profile's name, as the command line selects it.
    fn name(&self) -> &str;
    /// Finds the tree's constructs and converts them.
    fn convert_tree(&self, source: &Path, as_of: &str) -> Result<ProfileOutcome, String>;
}

/// The report of one migration run.
#[derive(Debug, Clone)]
pub struct MigrateReport {
    /// The deterministic run identifier.
    pub run_id: String,
    /// The profile that ran.
    pub profile: String,
    /// The source tree path, as given.
    pub source: String,
    /// The bundle path written, as given.
    pub out: String,
    /// The pinned as-of instant.
    pub as_of: String,
    /// How many concepts the run wrote.
    pub concepts_written: usize,
    /// Construct classes found against entries written.
    pub classes: Vec<ConstructClass>,
    /// The ledger as shipped.
    pub entries: Vec<LedgerEntry>,
    /// Whether every class found carries at least one entry and
    /// no entry names a class not found.
    pub reconciliation_ok: bool,
    /// Whether the honesty gate failed (an all-Mapped ledger).
    pub honesty_gate_failed: bool,
    /// Whether the load-bearing gate failed (a load-bearing loss).
    pub load_bearing_gate_failed: bool,
    /// Whether either gate failed.
    pub gate_failed: bool,
}

impl MigrateReport {
    /// The report as deterministic JSON.
    pub fn to_json(&self) -> String {
        Json::obj(vec![
            ("as_of", Json::Str(self.as_of.clone())),
            (
                "classes",
                Json::Arr(
                    self.classes
                        .iter()
                        .map(|class| {
                            Json::obj(vec![
                                ("construct", Json::Str(class.name.clone())),
                                ("count", Json::Int(class.count as i64)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("concepts_written", Json::Int(self.concepts_written as i64)),
            (
                "entries",
                Json::Arr(self.entries.iter().map(ledger_entry_json).collect()),
            ),
            ("gate_failed", Json::Bool(self.gate_failed)),
            ("honesty_gate_failed", Json::Bool(self.honesty_gate_failed)),
            (
                "load_bearing_gate_failed",
                Json::Bool(self.load_bearing_gate_failed),
            ),
            ("out", Json::Str(self.out.clone())),
            ("profile", Json::Str(self.profile.clone())),
            ("reconciliation_ok", Json::Bool(self.reconciliation_ok)),
            ("run_id", Json::Str(self.run_id.clone())),
            ("source", Json::Str(self.source.clone())),
        ])
        .render()
    }

    /// The report as Markdown.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Migration run {}\n\n", self.run_id));
        out.push_str(&format!(
            "Profile {}. Source {}. Bundle {}. As of {}. {} concepts written.\n\n",
            self.profile, self.source, self.out, self.as_of, self.concepts_written
        ));
        out.push_str("## Reconciliation\n\n");
        for class in &self.classes {
            let entries = self
                .entries
                .iter()
                .filter(|entry| entry.construct == class.name)
                .count();
            out.push_str(&format!(
                "- {}: found {}, {} entries\n",
                class.name, class.count, entries
            ));
        }
        out.push_str("\n## Gates\n\n");
        out.push_str(&format!(
            "- honesty gate: {}\n- load-bearing gate: {}\n\n",
            if self.honesty_gate_failed {
                "FAILED, the ledger claims zero loss"
            } else {
                "passed"
            },
            if self.load_bearing_gate_failed {
                "FAILED, a load-bearing construct is lost"
            } else {
                "passed"
            }
        ));
        out.push_str("## Ledger\n\n");
        for entry in &self.entries {
            out.push_str(&format!(
                "- {} {} ({}, {}): {}\n",
                entry.id,
                entry.construct,
                entry.disposition.as_str(),
                entry.count,
                entry.target
            ));
        }
        out
    }
}

/// One ledger entry as JSON, shared by the report and the shipped
/// ledger twin.
fn ledger_entry_json(entry: &LedgerEntry) -> Json {
    Json::obj(vec![
        ("construct", Json::Str(entry.construct.clone())),
        ("count", Json::Int(entry.count as i64)),
        (
            "disposition",
            Json::Str(entry.disposition.as_str().to_string()),
        ),
        ("id", Json::Str(entry.id.clone())),
        ("load_bearing", Json::Bool(entry.load_bearing)),
        ("reason", Json::Str(entry.reason.clone())),
        ("recovery", Json::Str(entry.recovery.clone())),
        ("target", Json::Str(entry.target.clone())),
    ])
}

/// Runs one migration: converts the source tree under the
/// profile, reconciles the ledger against the classes found,
/// computes the gates, and writes the bundle with its ledger.
/// A reconciliation gap is a migrator defect and fails the run
/// before anything is written. A gate failure is not an error:
/// the bundle and ledger are written and the report carries the
/// failure, because the finding is the point.
pub fn run_migration(
    profile: &dyn Profile,
    source: &Path,
    out: &Path,
    as_of: &str,
) -> Result<MigrateReport, String> {
    if parse_timestamp(as_of).is_none() {
        return Err(format!("invalid as-of timestamp: {as_of}"));
    }
    if !source.is_dir() {
        return Err(format!("source is not a directory: {}", source.display()));
    }
    let snapshot = source_snapshot(source)?;
    let run_material = format!("{snapshot}|{as_of}|{}", profile.name());
    let run_id = format!("run-{}", &sha256_hex(run_material.as_bytes())[..12]);
    let outcome = profile.convert_tree(source, as_of)?;

    // Reconciliation: every class found carries at least one
    // entry, and no entry names a class not found.
    let class_names: BTreeSet<&str> = outcome.classes.iter().map(|c| c.name.as_str()).collect();
    let mut entered: BTreeSet<&str> = BTreeSet::new();
    for draft in &outcome.drafts {
        if !class_names.contains(draft.construct.as_str()) {
            return Err(format!(
                "reconciliation gap: ledger entry for a construct the profile did not find: {}",
                draft.construct
            ));
        }
        entered.insert(draft.construct.as_str());
    }
    for class in &outcome.classes {
        if !entered.contains(class.name.as_str()) {
            return Err(format!(
                "reconciliation gap: construct found with no ledger entry: {}",
                class.name
            ));
        }
    }

    let entries: Vec<LedgerEntry> = outcome
        .drafts
        .iter()
        .enumerate()
        .map(|(i, draft)| LedgerEntry {
            id: format!("L-{:03}", i + 1),
            construct: draft.construct.clone(),
            count: draft.count,
            disposition: draft.disposition,
            target: draft.target.clone(),
            reason: draft.reason.clone(),
            load_bearing: draft.load_bearing,
            recovery: draft.recovery.clone(),
        })
        .collect();
    let honesty_gate_failed = entries.iter().all(|e| e.disposition == Disposition::Mapped);
    let load_bearing_gate_failed = entries
        .iter()
        .any(|e| e.load_bearing && e.disposition == Disposition::Lost);
    let gate_failed = honesty_gate_failed || load_bearing_gate_failed;

    write_bundle(
        out,
        profile.name(),
        as_of,
        &run_id,
        &outcome.concepts,
        &entries,
    )?;

    Ok(MigrateReport {
        run_id,
        profile: profile.name().to_string(),
        source: source.display().to_string(),
        out: out.display().to_string(),
        as_of: as_of.to_string(),
        concepts_written: outcome.concepts.len(),
        classes: outcome.classes,
        entries,
        reconciliation_ok: true,
        honesty_gate_failed,
        load_bearing_gate_failed,
        gate_failed,
    })
}

/// Writes the bundle: concept files, per-directory indexes and a
/// root index whose link sets match what the upkeep pass expects,
/// the bundle log, the loss ledger in both forms, and the state
/// manifest the type guard reads.
fn write_bundle(
    out: &Path,
    profile_name: &str,
    as_of: &str,
    run_id: &str,
    concepts: &[ConvertedConcept],
    entries: &[LedgerEntry],
) -> Result<(), String> {
    // The bundle root itself: a tree that converts no concepts
    // still gets its indexes, log, and ledger written into it.
    std::fs::create_dir_all(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    for concept in concepts {
        let path = out.join(&concept.relpath);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, &concept.content)
            .map_err(|e| format!("cannot write {}: {e}", concept.relpath))?;
    }
    // Directory indexes list their own concepts by file name.
    let mut dirs: BTreeMap<String, Vec<&ConvertedConcept>> = BTreeMap::new();
    for concept in concepts {
        dirs.entry(parent_dir(&concept.relpath))
            .or_default()
            .push(concept);
    }
    for (dir, members) in &dirs {
        if dir.is_empty() {
            continue;
        }
        let mut index = String::from("# Index\n");
        for concept in members {
            let name = concept
                .relpath
                .rsplit('/')
                .next()
                .unwrap_or(&concept.relpath);
            index.push_str(&format!("\n* [{}]({name})", concept.title));
        }
        index.push('\n');
        std::fs::write(out.join(dir).join("index.md"), index)
            .map_err(|e| format!("cannot write {dir}/index.md: {e}"))?;
    }
    // The root index carries the bundle frontmatter and lists
    // every concept by its full path, grouped by directory.
    let mut root_index = String::new();
    root_index.push_str("---\nokf_version: \"0.3\"\ntitle: \"Migrated knowledge bundle\"\n");
    root_index.push_str(&format!(
        "description: \"OKF v0.3 bundle migrated by anchorwatch with the {profile_name} profile. See LOSS-LEDGER.md for what did not survive the mapping.\"\n---\n\n# Migrated knowledge bundle\n"
    ));
    for (dir, members) in &dirs {
        if !dir.is_empty() {
            root_index.push_str(&format!("\n# {dir}\n"));
        }
        for concept in members {
            root_index.push_str(&format!("\n* [{}]({})", concept.title, concept.relpath));
        }
        root_index.push('\n');
    }
    std::fs::write(out.join("index.md"), root_index)
        .map_err(|e| format!("cannot write index.md: {e}"))?;
    // The bundle log, one creation group at the as-of date.
    let log = format!(
        "# Bundle Update Log\n\n## {}\n* **Creation**: Bundle created by the anchorwatch migrator with the {profile_name} profile. See LOSS-LEDGER.md for what did not survive the mapping.\n",
        &as_of[..10]
    );
    std::fs::write(out.join("log.md"), log).map_err(|e| format!("cannot write log.md: {e}"))?;
    // The loss ledger, Markdown with a JSON twin.
    let mut ledger = String::new();
    ledger.push_str("# Loss ledger\n\n");
    ledger.push_str(&format!(
        "Migration by the anchorwatch migrator with the {profile_name} profile, as of {as_of}. Run {run_id}.\n"
    ));
    for entry in entries {
        ledger.push_str(&format!(
            "\n## {} {}\n\nSource construct. {}\n\nCount measured. {}\n\nDisposition. {}\n\nTarget shape. {}\n\nReason. {}\n\nLoad bearing. {}\n\nRecovery path. {}\n",
            entry.id,
            entry.construct,
            entry.construct,
            entry.count,
            entry.disposition.as_str(),
            entry.target,
            entry.reason,
            if entry.load_bearing { "Yes" } else { "No" },
            entry.recovery
        ));
    }
    std::fs::write(out.join("LOSS-LEDGER.md"), ledger)
        .map_err(|e| format!("cannot write LOSS-LEDGER.md: {e}"))?;
    let ledger_json = Json::obj(vec![
        ("as_of", Json::Str(as_of.to_string())),
        (
            "entries",
            Json::Arr(entries.iter().map(ledger_entry_json).collect()),
        ),
        ("profile", Json::Str(profile_name.to_string())),
        ("run_id", Json::Str(run_id.to_string())),
    ])
    .render();
    std::fs::write(out.join("loss-ledger.json"), ledger_json)
        .map_err(|e| format!("cannot write loss-ledger.json: {e}"))?;
    // The state manifest, in the shape the type guard reads.
    let state_dir = out.join(".recension");
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| format!("cannot create {}: {e}", state_dir.display()))?;
    let manifest = Json::obj(vec![
        (
            "concepts",
            Json::Obj(
                concepts
                    .iter()
                    .map(|c| (c.relpath.clone(), Json::Str(c.concept_type.clone())))
                    .collect(),
            ),
        ),
        ("migrated_at", Json::Str(as_of.to_string())),
    ])
    .render();
    std::fs::write(state_dir.join("state.json"), manifest)
        .map_err(|e| format!("cannot write state.json: {e}"))?;
    Ok(())
}

/// The parent directory of a bundle-relative path, or the empty
/// string for the bundle root.
fn parent_dir(relpath: &str) -> String {
    match relpath.rfind('/') {
        Some(i) => relpath[..i].to_string(),
        None => String::new(),
    }
}

/// A deterministic snapshot of the source tree: every file's
/// relative path and content hash, in sorted order.
fn source_snapshot(source: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(source, source, &mut files);
    files.sort();
    let mut snapshot = String::new();
    for rel in files {
        let bytes =
            std::fs::read(source.join(&rel)).map_err(|e| format!("cannot read {rel}: {e}"))?;
        snapshot.push_str(&format!("{rel}\0{}\n", sha256_hex(&bytes)));
    }
    Ok(snapshot)
}

/// Collects every file under a directory as relative paths,
/// skipping symlinks.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_files(root, &path, out);
        } else if kind.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Formats epoch seconds as an RFC 3339 UTC timestamp. The civil
/// conversion is the standard days-from-epoch algorithm; the
/// parser in the time module is its oracle in the tests.
pub fn format_timestamp(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60
    )
}

/// The modification instant of a file as an RFC 3339 timestamp,
/// the honest generated.at for a converted concept: the last
/// change the source itself recorded.
fn modified_at(path: &Path) -> String {
    let Ok(metadata) = std::fs::metadata(path) else {
        return "1970-01-01T00:00:00Z".to_string();
    };
    let Ok(modified) = metadata.modified() else {
        return "1970-01-01T00:00:00Z".to_string();
    };
    let secs = modified
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_timestamp(secs)
}

/// The Muse memory profile: the tree shape the runtime memory
/// system writes. People and group pages with their own
/// frontmatter, one curated MEMORY.md, dated daily logs under a
/// memory directory, runtime bank files, and index files whose
/// order carries a closeness signal.
pub struct ClaudeMemoryProfile;

impl Profile for ClaudeMemoryProfile {
    fn name(&self) -> &str {
        "claude-memory"
    }

    fn convert_tree(&self, source: &Path, as_of: &str) -> Result<ProfileOutcome, String> {
        let mut files = Vec::new();
        collect_files(source, source, &mut files);
        files.sort();

        let mut concepts: Vec<ConvertedConcept> = Vec::new();
        let mut pages = 0usize;
        let mut extension_fields = 0usize;
        let mut curated = 0usize;
        let mut logs = 0usize;
        let mut bank = 0usize;
        let mut indexes = 0usize;
        let mut unclassified = 0usize;
        let mut supersede_markers = 0usize;
        let mut checkboxes = 0usize;
        let mut citations = 0usize;

        for rel in &files {
            let path = source.join(rel);
            let parent = parent_dir(rel);
            let base = rel.rsplit('/').next().unwrap_or(rel);
            if rel.starts_with("memory/bank/") {
                bank += 1;
                continue;
            }
            if base == "INDEX.md" {
                indexes += 1;
                continue;
            }
            if !base.ends_with(".md") {
                continue;
            }
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("cannot read {rel}: {e}"))?;
            let lowered = text.to_lowercase();
            supersede_markers += lowered.matches("supersed").count();
            checkboxes += text.matches("- [ ]").count();
            citations += text.matches(".md#L").count();
            if parent == "people" || parent == "groups" {
                pages += 1;
                let concept_type = if parent == "people" {
                    "Person"
                } else {
                    "Group"
                };
                let (concept, fields) = convert_person(&path, rel, &text, concept_type, as_of);
                extension_fields += fields;
                concepts.push(concept);
            } else if rel == "MEMORY.md" {
                curated += 1;
                concepts.push(convert_whole(
                    &path,
                    rel,
                    &text,
                    "Curated Memory",
                    "curated/memory.md",
                    None,
                    as_of,
                ));
            } else if parent == "memory" && is_dated_log(base) {
                logs += 1;
                let stem = base.trim_end_matches(".md");
                concepts.push(convert_whole(
                    &path,
                    rel,
                    &text,
                    "Daily Log",
                    &format!("logs/{base}"),
                    Some(format!("Memory log {stem}")),
                    as_of,
                ));
            } else {
                unclassified += 1;
                concepts.push(convert_whole(&path, rel, &text, "Note", rel, None, as_of));
            }
        }
        concepts.sort_by(|a, b| a.relpath.cmp(&b.relpath));

        let mut classes = Vec::new();
        let mut drafts = Vec::new();
        let mut pair = |count: usize, draft: LedgerDraft| {
            if count > 0 {
                classes.push(ConstructClass {
                    name: draft.construct.clone(),
                    count,
                });
                drafts.push(draft);
            }
        };
        pair(
            pages,
            LedgerDraft {
                construct: "people and group pages".to_string(),
                count: pages,
                disposition: Disposition::Mapped,
                target: "Person and Group concepts".to_string(),
                reason: "display_name becomes title and summary becomes description under the standard fields, and the body carries across whole.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            extension_fields,
            LedgerDraft {
                construct: "people and group frontmatter fields without a standard home".to_string(),
                count: extension_fields,
                disposition: Disposition::PreservedAsExtension,
                target: "x-muse- extension keys on the converted concepts".to_string(),
                reason: "OKF has no rank, name-part, or date-only updated field, so the values survive under the extension keys the spec provides for producer fields.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            curated,
            LedgerDraft {
                construct: "curated memory file".to_string(),
                count: curated,
                disposition: Disposition::Approximated,
                target: "one Curated Memory concept in whole-file mode".to_string(),
                reason: "the file converts whole in this slice, so its sections gain no individual concepts and progressive disclosure over them is deferred, with nothing lost.".to_string(),
                load_bearing: false,
                recovery: "section-level splitting by the file's own headings".to_string(),
            },
        );
        pair(
            logs,
            LedgerDraft {
                construct: "daily log files".to_string(),
                count: logs,
                disposition: Disposition::Approximated,
                target: "Daily Log concepts in whole-file mode".to_string(),
                reason: "a whole log as one concept defeats progressive disclosure, and claim-level splitting is impossible because claim supersession is not machine-readable in the files.".to_string(),
                load_bearing: false,
                recovery: "section-level splitting by the log's own headings".to_string(),
            },
        );
        pair(
            bank,
            LedgerDraft {
                construct: "runtime bank files".to_string(),
                count: bank,
                disposition: Disposition::Excluded,
                target: "none".to_string(),
                reason: "the bank files are runtime-managed derivative distillations whose contents already point back at the curated files and daily logs, so migrating them would double-count the same claims in a second shape.".to_string(),
                load_bearing: false,
                recovery: "a profile of its own if a bank file is ever ruled a source of truth".to_string(),
            },
        );
        pair(
            indexes,
            LedgerDraft {
                construct: "source index files".to_string(),
                count: indexes,
                disposition: Disposition::Approximated,
                target: "regenerated bundle indexes".to_string(),
                reason: "the source indexes list entries closest first and say so in prose, and OKF index files carry no ordering semantics, so the regenerated indexes list in filename order while rank survives on each concept.".to_string(),
                load_bearing: false,
                recovery: "index ordering by x-muse-rank where the key is present".to_string(),
            },
        );
        pair(
            unclassified,
            LedgerDraft {
                construct: "unclassified Markdown files".to_string(),
                count: unclassified,
                disposition: Disposition::Mapped,
                target: "Note concepts at their source-relative paths".to_string(),
                reason: "files outside the profile's known areas convert whole at their own paths under a generic type, with their text intact.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            supersede_markers,
            LedgerDraft {
                construct: "prose supersession markers".to_string(),
                count: supersede_markers,
                disposition: Disposition::Lost,
                target: "none".to_string(),
                reason: "later entries state in words that they supersede earlier ones, naming their targets in prose rather than by identifier, and turning the words into superseded_by edges would need semantic interpretation the migrator must not perform. The words remain in the bodies for a human reader.".to_string(),
                load_bearing: true,
                recovery: "upkeep queue proposals that a decider confirms, after which a declared edge can be written by the authoring side".to_string(),
            },
        );
        pair(
            checkboxes,
            LedgerDraft {
                construct: "open thread checkboxes".to_string(),
                count: checkboxes,
                disposition: Disposition::Approximated,
                target: "body text".to_string(),
                reason: "OKF has no task construct, so the checkboxes survive as body text in the converted concepts, still rendered and editable there.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            citations,
            LedgerDraft {
                construct: "inline citations with line anchors".to_string(),
                count: citations,
                disposition: Disposition::Approximated,
                target: "body text".to_string(),
                reason: "the anchors name source file layouts by path and line, and a mechanical conversion into sources entries would point at the wrong text wherever a source file's shape changes in conversion, so the citations stay verbatim in the bodies.".to_string(),
                load_bearing: false,
                recovery: "a citation rewriter that resolves each anchor to its target concept".to_string(),
            },
        );
        pair(
            concepts.len(),
            LedgerDraft {
                construct: "freshness expectations".to_string(),
                count: concepts.len(),
                disposition: Disposition::Lost,
                target: "none".to_string(),
                reason: "the source tree carries no per-concept review dates, and the spec instructs producers to omit stale_after when no review date is known and never to invent one, so every migrated concept starts with no review date and the upkeep queue carries the consequence.".to_string(),
                load_bearing: true,
                recovery: "a one-time owner triage that sets review dates or waives them per concept or per type".to_string(),
            },
        );

        Ok(ProfileOutcome {
            classes,
            concepts,
            drafts,
        })
    }
}

/// Whether a file name is a dated daily log name, YYYY-MM-DD.md.
fn is_dated_log(name: &str) -> bool {
    let bytes = name.as_bytes();
    name.len() == 13
        && name.ends_with(".md")
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || i >= 10 || b.is_ascii_digit())
}

/// Splits a document into its top-level frontmatter scalar fields
/// and its body. Only unindented key lines are read, and one pair
/// of surrounding double quotes is stripped from values. A
/// document with no frontmatter block yields no fields and its
/// whole text as body.
fn split_frontmatter(text: &str) -> (Vec<(String, String)>, String) {
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        return (Vec::new(), text.to_string());
    }
    let mut fields = Vec::new();
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for line in lines {
        if in_body {
            body_lines.push(line);
            continue;
        }
        if line.trim() == "---" {
            in_body = true;
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            fields.push((key.trim().to_string(), value.to_string()));
        }
    }
    if !in_body {
        return (Vec::new(), text.to_string());
    }
    let mut body = body_lines.join("\n");
    while body.starts_with('\n') {
        body.remove(0);
    }
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    (fields, body)
}

/// Reads one field from a split frontmatter field list.
fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Quotes a value for a frontmatter line, escaping backslashes
/// and double quotes.
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Converts one people or group page: standard fields mapped,
/// fields without a standard home preserved as extensions, the
/// body carried across. Returns the concept and how many
/// extension fields were preserved.
fn convert_person(
    path: &Path,
    rel: &str,
    text: &str,
    concept_type: &str,
    as_of: &str,
) -> (ConvertedConcept, usize) {
    let (fields, body) = split_frontmatter(text);
    let stem = rel
        .rsplit('/')
        .next()
        .unwrap_or(rel)
        .trim_end_matches(".md");
    let title = field(&fields, "display_name").unwrap_or(stem).to_string();
    let mut content = String::new();
    content.push_str("---\n");
    content.push_str(&format!("type: {}\n", quoted(concept_type)));
    content.push_str(&format!("title: {}\n", quoted(&title)));
    if let Some(summary) = field(&fields, "summary")
        && !summary.is_empty()
    {
        content.push_str(&format!("description: {}\n", quoted(summary)));
    }
    content.push_str(&format!(
        "generated: {{ by: \"anchorwatch\", at: {} }}\n",
        quoted(&modified_at(path))
    ));
    let mut preserved = 0usize;
    for (key, xkey) in [
        ("rank", "x-muse-rank"),
        ("first_name", "x-muse-first-name"),
        ("last_name", "x-muse-last-name"),
        ("updated", "x-muse-updated"),
    ] {
        if let Some(value) = field(&fields, key)
            && !value.is_empty()
        {
            preserved += 1;
            if key == "rank" {
                content.push_str(&format!("{xkey}: {value}\n"));
            } else {
                content.push_str(&format!("{xkey}: {}\n", quoted(value)));
            }
        }
    }
    content.push_str(&format!("x-anchorwatch-source: {}\n", quoted(rel)));
    content.push_str(&format!("x-anchorwatch-migrated-at: {}\n", quoted(as_of)));
    content.push_str("---\n\n");
    content.push_str(&body);
    (
        ConvertedConcept {
            relpath: rel.to_string(),
            concept_type: concept_type.to_string(),
            title,
            content,
        },
        preserved,
    )
}

/// Converts one whole file: the source text becomes the body
/// verbatim under a fresh frontmatter block.
fn convert_whole(
    path: &Path,
    rel: &str,
    text: &str,
    concept_type: &str,
    out_rel: &str,
    title_override: Option<String>,
    as_of: &str,
) -> ConvertedConcept {
    let stem = rel
        .rsplit('/')
        .next()
        .unwrap_or(rel)
        .trim_end_matches(".md");
    let title = title_override.unwrap_or_else(|| {
        text.lines()
            .find(|line| line.starts_with("# "))
            .map(|line| line[2..].trim().to_string())
            .unwrap_or_else(|| stem.to_string())
    });
    let mut content = String::new();
    content.push_str("---\n");
    content.push_str(&format!("type: {}\n", quoted(concept_type)));
    content.push_str(&format!("title: {}\n", quoted(&title)));
    content.push_str(&format!(
        "generated: {{ by: \"anchorwatch\", at: {} }}\n",
        quoted(&modified_at(path))
    ));
    content.push_str(&format!("x-anchorwatch-source: {}\n", quoted(rel)));
    content.push_str(&format!("x-anchorwatch-migrated-at: {}\n", quoted(as_of)));
    content.push_str("---\n\n");
    content.push_str(text);
    if !text.ends_with('\n') {
        content.push('\n');
    }
    ConvertedConcept {
        relpath: out_rel.to_string(),
        concept_type: concept_type.to_string(),
        title,
        content,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_round_trip_through_the_parser() {
        for stamp in [
            "1970-01-01T00:00:00Z",
            "2026-11-20T21:45:00Z",
            "2024-02-29T12:00:00Z",
            "2000-01-01T00:00:00Z",
            "2038-01-19T03:14:07Z",
        ] {
            let epoch = parse_timestamp(stamp).unwrap();
            assert_eq!(format_timestamp(epoch), stamp);
        }
    }
}
