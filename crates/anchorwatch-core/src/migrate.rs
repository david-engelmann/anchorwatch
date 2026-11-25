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
use std::path::{Path, PathBuf};

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

/// One non-Markdown file carried across byte for byte.
#[derive(Debug, Clone)]
pub struct AssetFile {
    /// Bundle-relative path of the asset.
    pub relpath: String,
    /// The file's bytes, unchanged.
    pub bytes: Vec<u8>,
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
    /// Non-Markdown files carried across unchanged.
    pub assets: Vec<AssetFile>,
    /// Dated log groups carried from the source bundle's log,
    /// without its title line, oldest material last.
    pub carried_log: Option<String>,
    /// Bundle metadata fields carried from the source root
    /// index (title, description, license), which the spec
    /// requires a regenerating producer to keep.
    pub root_fields: Vec<(String, String)>,
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
    // The output must not sit inside the source tree, nor the
    // source inside the output. A run writes its bundle at the
    // output, and a later run over the same source would ingest
    // the earlier bundle as source material, so the overlap is
    // refused before anything is read or written. The comparison
    // runs on resolved paths, so different spellings of the same
    // directory cannot slip past it.
    let source_real = resolve_path(source);
    let out_real = resolve_path(out);
    if out_real.starts_with(&source_real) || source_real.starts_with(&out_real) {
        return Err(format!(
            "output directory {} and source directory {} overlap; refusing to migrate",
            out.display(),
            source.display()
        ));
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

    write_bundle(out, profile.name(), as_of, &run_id, &outcome, &entries)?;

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
    outcome: &ProfileOutcome,
    entries: &[LedgerEntry],
) -> Result<(), String> {
    let concepts = &outcome.concepts;
    // The bundle root itself: a tree that converts no concepts
    // still gets its indexes, log, and ledger written into it.
    std::fs::create_dir_all(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    for asset in &outcome.assets {
        let path = out.join(&asset.relpath);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, &asset.bytes)
            .map_err(|e| format!("cannot write {}: {e}", asset.relpath))?;
    }
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
    root_index.push_str("---\nokf_version: \"0.3\"\n");
    // Bundle metadata the source root index carried is kept, as
    // the spec requires of a producer that regenerates index.md.
    let carried_field = |key: &str| {
        outcome
            .root_fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    let title = carried_field("title").unwrap_or_else(|| "Migrated knowledge bundle".to_string());
    root_index.push_str(&format!("title: {}\n", quoted(&title)));
    let description = carried_field("description").unwrap_or_else(|| {
        format!(
            "OKF v0.3 bundle migrated by anchorwatch with the {profile_name} profile. See LOSS-LEDGER.md for what did not survive the mapping."
        )
    });
    root_index.push_str(&format!("description: {}\n", quoted(&description)));
    if let Some(license) = carried_field("license") {
        root_index.push_str(&format!("license: {}\n", quoted(&license)));
    }
    root_index.push_str("---\n\n# Migrated knowledge bundle\n");
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
    // The bundle log, one creation group at the as-of date, with
    // any log history the profile carried under it.
    let mut log = format!(
        "# Bundle Update Log\n\n## {}\n* **Creation**: Bundle created by the anchorwatch migrator with the {profile_name} profile. See LOSS-LEDGER.md for what did not survive the mapping.\n",
        &as_of[..10]
    );
    if let Some(carried) = &outcome.carried_log {
        let carried = carried.trim_end();
        if !carried.is_empty() {
            log.push('\n');
            log.push_str(carried);
            log.push('\n');
        }
    }
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

/// Resolves a path for comparison: canonical when the path
/// exists, and when it does not, the canonical form of its
/// nearest existing ancestor with the remaining components
/// re-appended, so a not-yet-created output directory still
/// compares honestly against the source tree.
fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path;
    loop {
        match std::fs::canonicalize(cursor) {
            Ok(mut real) => {
                for part in tail.iter().rev() {
                    real.push(part);
                }
                return real;
            }
            Err(_) => match (cursor.file_name(), cursor.parent()) {
                (Some(name), Some(parent)) => {
                    tail.push(name.to_os_string());
                    cursor = parent;
                }
                _ => return path.to_path_buf(),
            },
        }
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
        let mut area_files = 0usize;
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
            // Classification keys on the immediate directory
            // name, because the real tree nests its areas under
            // memory/ (memory/people, memory/groups), and the
            // prototype conversion placed the converted pages at
            // the bundle's own people and groups directories.
            let area = rel.rsplit('/').nth(1).unwrap_or("");
            if area == "people" || area == "groups" {
                pages += 1;
                let concept_type = if area == "people" { "Person" } else { "Group" };
                let (concept, fields) = convert_person(
                    &path,
                    rel,
                    &format!("{area}/{base}"),
                    &text,
                    concept_type,
                    as_of,
                );
                extension_fields += fields;
                concepts.push(concept);
            } else if rel == "MEMORY.md" {
                curated += 1;
                let sections = split_sections(&text);
                if sections.iter().all(|(heading, _)| heading.is_none()) {
                    concepts.push(convert_whole(
                        &path,
                        rel,
                        &text,
                        "Curated Memory",
                        "curated/memory.md",
                        None,
                        as_of,
                    ));
                } else {
                    let mut number = 0usize;
                    for (heading, body) in &sections {
                        match heading {
                            Some(heading) => {
                                number += 1;
                                concepts.push(convert_section(
                                    &path,
                                    &format!("MEMORY.md section {number}"),
                                    "Curated Memory",
                                    heading,
                                    body,
                                    &format!("curated/{number:02}-{}.md", slugify(heading)),
                                    as_of,
                                ));
                            }
                            None => {
                                concepts.push(convert_section(
                                    &path,
                                    "MEMORY.md preamble",
                                    "Curated Memory",
                                    "Preamble",
                                    body,
                                    "curated/00-preamble.md",
                                    as_of,
                                ));
                            }
                        }
                    }
                }
            } else if parent == "memory" && is_dated_log(base) {
                logs += 1;
                let stem = base.trim_end_matches(".md");
                let sections = split_sections(&text);
                if sections.iter().all(|(heading, _)| heading.is_none()) {
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
                    let mut number = 0usize;
                    for (heading, body) in &sections {
                        match heading {
                            Some(heading) => {
                                number += 1;
                                concepts.push(convert_section(
                                    &path,
                                    &format!("{rel} section {number}"),
                                    "Daily Log",
                                    heading,
                                    body,
                                    &format!("logs/{stem}-{number:02}-{}.md", slugify(heading)),
                                    as_of,
                                ));
                            }
                            None => {
                                concepts.push(convert_section(
                                    &path,
                                    &format!("{rel} preamble"),
                                    "Daily Log",
                                    &format!("Memory log {stem} preamble"),
                                    body,
                                    &format!("logs/{stem}-00-preamble.md"),
                                    as_of,
                                ));
                            }
                        }
                    }
                }
            } else if rel.starts_with("memory/") && (base == "PROFILE.md" || base == "HISTORY.md") {
                area_files += 1;
                let kind = base.trim_end_matches(".md").to_lowercase();
                let titled = |word: &str| {
                    let mut chars = word.chars();
                    match chars.next() {
                        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                        None => String::new(),
                    }
                };
                concepts.push(convert_whole(
                    &path,
                    rel,
                    &text,
                    "Profile",
                    &format!("profile/{area}-{kind}.md"),
                    Some(format!("{} {}", titled(area), titled(&kind))),
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
                disposition: Disposition::Mapped,
                target: "one Curated Memory concept per section, split at the file's own headings".to_string(),
                reason: "the file divides at its level-two headings into numbered section concepts under the prototype builder's slug scheme, any preamble becomes a section of its own rather than being dropped, and a file with no headings converts whole.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            logs,
            LedgerDraft {
                construct: "daily log files".to_string(),
                count: logs,
                disposition: Disposition::Mapped,
                target: "one Daily Log concept per section, split at the log's own headings".to_string(),
                reason: "a log divides at its level-two headings into numbered section concepts, and a log with no headings converts whole, as the prototype's single log did. Claim-level splitting stays deferred until a lineage source exists.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
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
            area_files,
            LedgerDraft {
                construct: "area profile and history files".to_string(),
                count: area_files,
                disposition: Disposition::Mapped,
                target: "Profile concepts in the profile directory".to_string(),
                reason: "the per-area profile and history files the memory system keeps convert whole as Profile concepts, named for their area, as the prototype conversion placed them.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
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
            assets: Vec::new(),
            carried_log: None,
            root_fields: Vec::new(),
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
    out_rel: &str,
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
            relpath: out_rel.to_string(),
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

/// Splits a document at its level-two headings. Each section's
/// body includes its own heading line and runs to the next
/// heading. Content before the first heading comes back as a
/// headingless first section, and only when it has real content.
fn split_sections(text: &str) -> Vec<(Option<String>, String)> {
    let mut sections: Vec<(Option<String>, String)> = Vec::new();
    let mut current: Option<(Option<String>, String)> = None;
    // A heading-shaped line inside a fenced code block is code,
    // not a heading. The splitter tracks the fence it is inside
    // by the character that opened it, so a section's code samples
    // keep their own heading-shaped lines instead of splitting
    // the section at them.
    let mut fence: Option<char> = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let marker = if trimmed.starts_with("```") {
            Some('`')
        } else if trimmed.starts_with("~~~") {
            Some('~')
        } else {
            None
        };
        if let Some(marker) = marker {
            match fence {
                None => fence = Some(marker),
                Some(open) if open == marker => fence = None,
                _ => {}
            }
        }
        if fence.is_none()
            && let Some(heading) = line.strip_prefix("## ")
        {
            if let Some(done) = current.take() {
                sections.push(done);
            }
            current = Some((Some(heading.trim().to_string()), line.to_string()));
        } else {
            match &mut current {
                Some((_, body)) => body.push_str(line),
                None => current = Some((None, line.to_string())),
            }
        }
    }
    if let Some(done) = current.take() {
        sections.push(done);
    }
    if sections
        .first()
        .is_some_and(|(heading, body)| heading.is_none() && body.trim().is_empty())
    {
        sections.remove(0);
    }
    sections
}

/// The prototype builder's slug scheme: lowercase, runs of
/// characters outside a-z and 0-9 become one hyphen, hyphens
/// trimmed from both ends, cut at sixty characters.
fn slugify(heading: &str) -> String {
    let mut slug = String::new();
    let mut last_was_hyphen = true;
    for c in heading.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            slug.push('-');
            last_was_hyphen = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug.chars().take(60).collect()
}

/// Converts one section of a split file under the migrator's
/// own frontmatter, with the source key naming the section it
/// came from, following the prototype builder's convention.
fn convert_section(
    path: &Path,
    source_label: &str,
    concept_type: &str,
    title: &str,
    body: &str,
    out_rel: &str,
    as_of: &str,
) -> ConvertedConcept {
    let mut content = String::new();
    content.push_str("---\n");
    content.push_str(&format!("type: {}\n", quoted(concept_type)));
    content.push_str(&format!("title: {}\n", quoted(title)));
    content.push_str(&format!(
        "generated: {{ by: \"anchorwatch\", at: {} }}\n",
        quoted(&modified_at(path))
    ));
    content.push_str(&format!("x-anchorwatch-source: {}\n", quoted(source_label)));
    content.push_str(&format!("x-anchorwatch-migrated-at: {}\n", quoted(as_of)));
    content.push_str("---\n\n");
    content.push_str(body);
    if !body.ends_with('\n') {
        content.push('\n');
    }
    ConvertedConcept {
        relpath: out_rel.to_string(),
        concept_type: concept_type.to_string(),
        title: title.to_string(),
        content,
    }
}

/// The OKF native profile: a source that is already an OKF
/// bundle, at any declared version, re-emitted as a v0.3 bundle
/// over the same engine. Concepts keep their paths, bodies, and
/// frontmatter spans; the migration's real work is the version
/// step. A bundle that declares 0.2 or earlier, or declares no
/// version, wrote its bare path fields from the bundle root,
/// while v0.3 resolves them from the file's own directory, so
/// carrying such a value across unchanged would silently move
/// its target. The profile rewrites bare in-bundle path values
/// to the leading-slash form, which names the same target under
/// both readings. A bundle that already declares 0.3 needs no
/// rewrite and gets none.
pub struct OkfNativeProfile;

/// One top-level frontmatter key and its raw lines, continuations
/// included, so an unmodified span re-emits byte for byte.
struct FmSpan {
    key: String,
    lines: Vec<String>,
}

/// The frontmatter keys the v0.3 specification defines.
const STANDARD_KEYS: &[&str] = &[
    "type",
    "title",
    "description",
    "resource",
    "tags",
    "sources",
    "usage_window",
    "generated",
    "verified",
    "status",
    "superseded_by",
    "stale_after",
    "okf_version",
    "license",
];

/// Splits a document into its frontmatter spans and its body.
/// A document with no block, or a block that never closes, has
/// no spans and its whole text is the body.
fn split_spans(text: &str) -> (Vec<FmSpan>, &str) {
    let Some(rest) = text.strip_prefix("---\n") else {
        return (Vec::new(), text);
    };
    let mut pos = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim_end_matches(['\n', '\r']) == "---" {
            let block = &rest[..pos];
            let body = &rest[pos + line.len()..];
            return (parse_spans(block), body);
        }
        pos += line.len();
    }
    (Vec::new(), text)
}

fn parse_spans(block: &str) -> Vec<FmSpan> {
    let mut raw: Vec<&str> = block.split('\n').collect();
    if raw.last() == Some(&"") {
        raw.pop();
    }
    let mut spans: Vec<FmSpan> = Vec::new();
    for line in raw {
        let is_key = !line.is_empty()
            && !line.starts_with(char::is_whitespace)
            && !line.starts_with('#')
            && !line.starts_with("- ")
            && line.split(':').next().is_some_and(|head| {
                !head.is_empty()
                    && head
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            })
            && (line.ends_with(':') || line.contains(": "));
        if is_key {
            let key = line.split(':').next().unwrap_or("").to_string();
            spans.push(FmSpan {
                key,
                lines: vec![line.to_string()],
            });
        } else if let Some(current) = spans.last_mut() {
            current.lines.push(line.to_string());
        } else {
            spans.push(FmSpan {
                key: String::new(),
                lines: vec![line.to_string()],
            });
        }
    }
    spans
}

/// Strips one pair of surrounding quotes from a scalar value.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if value.len() >= 2
        && ((bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\''))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// The scalar value a span's key line carries, if it carries one.
fn span_scalar(span: &FmSpan) -> Option<String> {
    let first = span.lines.first()?;
    let (_, value) = first.split_once(':')?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(unquote(value))
}

/// Whether a value reads as a bare in-bundle path: relative,
/// unspaced, schemeless, and carrying a directory component.
fn is_bare_bundle_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(' ')
        && !value.contains("://")
        && !value.starts_with('/')
        && !value.starts_with('.')
        && !value.starts_with('#')
        && value.contains('/')
}

/// Rewrites a top-level path field line to the leading-slash
/// form, preserving its quoting. None when the value is not a
/// bare in-bundle path.
fn rewrite_path_line(line: &str) -> Option<String> {
    let (key, raw) = line.split_once(':')?;
    let value = raw.trim();
    let inner = unquote(value);
    if !is_bare_bundle_path(&inner) {
        return None;
    }
    if value.starts_with('"') || value.starts_with('\'') {
        let quote = &value[..1];
        Some(format!("{key}: {quote}/{inner}{quote}"))
    } else {
        Some(format!("{key}: /{inner}"))
    }
}

/// Rewrites a resource line inside a sources entry the same
/// way. None when the line is not a resource line or its value
/// is not a bare in-bundle path.
fn rewrite_resource_line(line: &str) -> Option<String> {
    let colon = line.find("resource:")?;
    let head = &line[..colon + "resource:".len()];
    if !head.trim_start().starts_with("resource:") && !head.trim_start().starts_with("- resource:")
    {
        return None;
    }
    let rest = line[colon + "resource:".len()..].trim_start();
    let token = rest.split_whitespace().next()?;
    if !is_bare_bundle_path(&unquote(token)) {
        return None;
    }
    let start = line[colon..].find(token)? + colon;
    Some(format!("{}/{token}", &line[..start]))
}

/// What one native conversion measured, for the ledger counts.
#[derive(Default)]
struct NativeStats {
    extension_keys: usize,
    unknown_keys: usize,
    verified: usize,
    review_dates: usize,
    paths_rewritten: usize,
}

/// Converts one native concept: frontmatter spans carried
/// verbatim apart from the path rewrites the version step
/// requires, the migrator's own provenance keys appended, and
/// the body carried byte for byte.
fn convert_native(
    rel: &str,
    spans: &[FmSpan],
    body: &str,
    rewrite_paths: bool,
    as_of: &str,
) -> (ConvertedConcept, NativeStats) {
    let mut stats = NativeStats::default();
    let mut concept_type = String::new();
    let mut title = String::new();
    let mut content = String::from("---\n");
    for span in spans {
        if span.key == "type" {
            concept_type = span_scalar(span).unwrap_or_default();
        } else if span.key == "title" {
            title = span_scalar(span).unwrap_or_default();
        }
        if span.key.starts_with("x-") {
            stats.extension_keys += 1;
        } else if !span.key.is_empty() && !STANDARD_KEYS.contains(&span.key.as_str()) {
            stats.unknown_keys += 1;
        }
        if span.key == "verified" {
            stats.verified += 1;
        }
        if span.key == "stale_after" && span_scalar(span).is_some() {
            stats.review_dates += 1;
        }
        for (index, line) in span.lines.iter().enumerate() {
            let rewritten = if !rewrite_paths {
                None
            } else if index == 0 && (span.key == "superseded_by" || span.key == "resource") {
                rewrite_path_line(line)
            } else if span.key == "sources" && index > 0 {
                rewrite_resource_line(line)
            } else {
                None
            };
            match rewritten {
                Some(line) => {
                    stats.paths_rewritten += 1;
                    content.push_str(&line);
                }
                None => content.push_str(line),
            }
            content.push('\n');
        }
    }
    content.push_str(&format!("x-anchorwatch-source: {}\n", quoted(rel)));
    content.push_str(&format!("x-anchorwatch-migrated-at: {}\n", quoted(as_of)));
    content.push_str("---\n");
    content.push_str(body);
    if title.is_empty() {
        title = rel
            .rsplit('/')
            .next()
            .unwrap_or(rel)
            .trim_end_matches(".md")
            .to_string();
    }
    (
        ConvertedConcept {
            relpath: rel.to_string(),
            concept_type,
            title,
            content,
        },
        stats,
    )
}

impl Profile for OkfNativeProfile {
    fn name(&self) -> &str {
        "okf-native"
    }

    fn convert_tree(&self, source: &Path, as_of: &str) -> Result<ProfileOutcome, String> {
        let mut files = Vec::new();
        collect_files(source, source, &mut files);
        files.sort();

        // The declared version and the bundle metadata come from
        // the source root index, read before anything converts,
        // because the version decides the path rewrite.
        let mut rewrite_paths = true;
        let mut root_fields: Vec<(String, String)> = Vec::new();
        if files.iter().any(|rel| rel == "index.md") {
            let text = std::fs::read_to_string(source.join("index.md"))
                .map_err(|e| format!("cannot read index.md: {e}"))?;
            let (spans, _) = split_spans(&text);
            for span in &spans {
                if span.key == "okf_version"
                    && let Some(version) = span_scalar(span)
                {
                    rewrite_paths = version == "0.1" || version == "0.2";
                }
                if ["title", "description", "license"].contains(&span.key.as_str())
                    && let Some(value) = span_scalar(span)
                    && !value.is_empty()
                {
                    root_fields.push((span.key.clone(), value));
                }
            }
        }

        let mut concepts: Vec<ConvertedConcept> = Vec::new();
        let mut assets: Vec<AssetFile> = Vec::new();
        let mut carried_log: Option<String> = None;
        let mut stats = NativeStats::default();
        let mut typeless = 0usize;
        let mut indexes = 0usize;
        let mut index_prose = 0usize;
        let mut log_groups = 0usize;
        for rel in &files {
            // Dot paths are not part of the bundle.
            if rel.split('/').any(|segment| segment.starts_with('.')) {
                continue;
            }
            let path = source.join(rel);
            let base = rel.rsplit('/').next().unwrap_or(rel);
            if base == "index.md" {
                indexes += 1;
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {rel}: {e}"))?;
                let (_, body) = split_spans(&text);
                let has_prose = body.lines().any(|line| {
                    let line = line.trim();
                    !line.is_empty()
                        && !line.starts_with('#')
                        && !line.starts_with("* [")
                        && !line.starts_with("- [")
                });
                if has_prose {
                    index_prose += 1;
                }
                continue;
            }
            if rel == "log.md" {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {rel}: {e}"))?;
                log_groups = text.lines().filter(|line| line.starts_with("## ")).count();
                let carried = text
                    .lines()
                    .skip_while(|line| !line.starts_with("## "))
                    .collect::<Vec<_>>()
                    .join("\n");
                if !carried.is_empty() {
                    carried_log = Some(carried);
                }
                continue;
            }
            if !base.ends_with(".md") {
                let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {rel}: {e}"))?;
                assets.push(AssetFile {
                    relpath: rel.clone(),
                    bytes,
                });
                continue;
            }
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("cannot read {rel}: {e}"))?;
            let (spans, body) = split_spans(&text);
            let has_type = spans
                .iter()
                .find(|span| span.key == "type")
                .and_then(span_scalar)
                .is_some_and(|value| !value.is_empty());
            if !has_type {
                typeless += 1;
                continue;
            }
            let (concept, one) = convert_native(rel, &spans, body, rewrite_paths, as_of);
            stats.extension_keys += one.extension_keys;
            stats.unknown_keys += one.unknown_keys;
            stats.verified += one.verified;
            stats.review_dates += one.review_dates;
            stats.paths_rewritten += one.paths_rewritten;
            concepts.push(concept);
        }
        concepts.sort_by(|a, b| a.relpath.cmp(&b.relpath));
        assets.sort_by(|a, b| a.relpath.cmp(&b.relpath));

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
            concepts.len(),
            LedgerDraft {
                construct: "OKF concepts".to_string(),
                count: concepts.len(),
                disposition: Disposition::Mapped,
                target: "OKF v0.3 concepts at the same paths".to_string(),
                reason: "paths, bodies, and frontmatter carry across, with the standard fields keeping their v0.3 homes by construction.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            stats.paths_rewritten,
            LedgerDraft {
                construct: "root-relative path fields".to_string(),
                count: stats.paths_rewritten,
                disposition: Disposition::Mapped,
                target: "leading-slash path values naming the same targets".to_string(),
                reason: "a bundle at 0.2 or earlier, or with no declared version, wrote bare path values from the bundle root, while v0.3 resolves them from the file's own directory, so the values are rewritten to the leading-slash form that names the same target under both readings.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            stats.extension_keys,
            LedgerDraft {
                construct: "extension keys".to_string(),
                count: stats.extension_keys,
                disposition: Disposition::PreservedAsExtension,
                target: "the same x- keys on the converted concepts".to_string(),
                reason:
                    "extension keys are the spec's own producer space and carry across unchanged."
                        .to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            stats.unknown_keys,
            LedgerDraft {
                construct: "unrecognised frontmatter keys".to_string(),
                count: stats.unknown_keys,
                disposition: Disposition::PreservedAsExtension,
                target: "the same keys on the converted concepts".to_string(),
                reason: "the spec requires a producer that modifies a file to keep the keys it does not know, so unknown keys ride across verbatim rather than being renamed or dropped.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            stats.verified,
            LedgerDraft {
                construct: "verification events".to_string(),
                count: stats.verified,
                disposition: Disposition::Mapped,
                target: "the verified lists on the converted concepts".to_string(),
                reason: "verification events carry across unchanged, so trust tiers computed from them are the same before and after the migration.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            stats.review_dates,
            LedgerDraft {
                construct: "review dates".to_string(),
                count: stats.review_dates,
                disposition: Disposition::Mapped,
                target: "the stale_after values on the converted concepts".to_string(),
                reason: "a native bundle records its own review dates, and they carry across unchanged, where a memory-shaped tree has none to carry.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            typeless,
            LedgerDraft {
                construct: "Markdown files without a type".to_string(),
                count: typeless,
                disposition: Disposition::Excluded,
                target: "not carried".to_string(),
                reason: "the spec's own rule is that a Markdown file without a type is not a concept, so the migration carries concepts and leaves these files behind, named here rather than dropped silently.".to_string(),
                load_bearing: false,
                recovery: "give the file a type and re-run the migration".to_string(),
            },
        );
        pair(
            indexes,
            LedgerDraft {
                construct: "source index files".to_string(),
                count: indexes,
                disposition: Disposition::Approximated,
                target: "regenerated directory indexes".to_string(),
                reason: "indexes are furniture and are regenerated from the converted concepts, so their link sets are exact by construction.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            index_prose,
            LedgerDraft {
                construct: "index prose".to_string(),
                count: index_prose,
                disposition: Disposition::Lost,
                target: "no target".to_string(),
                reason: "prose written into a source index has no home in a regenerated index, whose whole content is its link set.".to_string(),
                load_bearing: false,
                recovery: "move the prose into a concept and re-run the migration".to_string(),
            },
        );
        pair(
            log_groups,
            LedgerDraft {
                construct: "bundle log history".to_string(),
                count: log_groups,
                disposition: Disposition::Approximated,
                target: "dated groups carried under the migration's own creation group".to_string(),
                reason: "the source log's dated groups carry across under the new log's head, with the source log's own title line dropped.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            assets.len(),
            LedgerDraft {
                construct: "asset files".to_string(),
                count: assets.len(),
                disposition: Disposition::Mapped,
                target: "the same files at the same paths".to_string(),
                reason: "non-Markdown files are bundle assets and copy across byte for byte."
                    .to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );
        pair(
            root_fields.len(),
            LedgerDraft {
                construct: "bundle metadata".to_string(),
                count: root_fields.len(),
                disposition: Disposition::Mapped,
                target: "the regenerated root index frontmatter".to_string(),
                reason: "the spec requires a producer that regenerates the root index to keep its title, description, and license, so those fields carry into the new frontmatter beside the 0.3 version stamp.".to_string(),
                load_bearing: false,
                recovery: "none needed".to_string(),
            },
        );

        Ok(ProfileOutcome {
            classes,
            concepts,
            drafts,
            assets,
            carried_log,
            root_fields,
        })
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
