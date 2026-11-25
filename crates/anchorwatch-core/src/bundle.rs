//! Bundle inventory and snapshots.
//!
//! A bundle is a directory tree of Markdown concept files. Dot files
//! and dot directories sit outside the bundle by spec, which is where
//! the engine keeps its own state. Traversal is sorted at every level
//! so the inventory, and every artefact derived from it, is
//! deterministic. Symbolic links are never followed out of the root.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::frontmatter::{Frontmatter, parse_document};
use crate::json::parse;
use crate::sha256::sha256_hex;

/// One Markdown file in the bundle, with the frontmatter the engine reads.
#[derive(Debug, Clone)]
pub struct ConceptFile {
    /// Path relative to the bundle root, with forward slashes.
    pub relpath: String,
    /// SHA-256 of the file bytes, hex encoded.
    pub hash: String,
    /// Whether the file carries a frontmatter block at all.
    pub has_frontmatter: bool,
    /// The parsed frontmatter fields.
    pub frontmatter: Frontmatter,
}

impl ConceptFile {
    /// A file is a concept when it carries the required `type` key.
    pub fn is_concept(&self) -> bool {
        self.frontmatter.concept_type.is_some()
    }
}

/// The full inventory of a bundle at one instant.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// The bundle root as given.
    pub root: PathBuf,
    /// Every Markdown file, sorted by relative path.
    pub files: Vec<ConceptFile>,
}

impl Bundle {
    /// Reads the bundle tree under `root`. Files that cannot be read
    /// are reported as an error naming the path, never skipped
    /// silently, because a partial inventory would corrupt the pass.
    pub fn load(root: &Path) -> Result<Bundle, String> {
        let mut relpaths = Vec::new();
        collect_markdown(root, root, &mut relpaths)?;
        relpaths.sort();
        let mut files = Vec::new();
        for relpath in relpaths {
            let bytes = std::fs::read(root.join(&relpath))
                .map_err(|e| format!("cannot read {relpath}: {e}"))?;
            let text = String::from_utf8_lossy(&bytes);
            let (frontmatter, has_frontmatter) = parse_document(&text);
            files.push(ConceptFile {
                relpath,
                hash: sha256_hex(&bytes),
                has_frontmatter,
                frontmatter,
            });
        }
        Ok(Bundle {
            root: root.to_path_buf(),
            files,
        })
    }

    /// The concepts in the bundle, in path order.
    pub fn concepts(&self) -> impl Iterator<Item = &ConceptFile> {
        self.files.iter().filter(|f| f.is_concept())
    }

    /// Finds one file by its relative path.
    pub fn file(&self, relpath: &str) -> Option<&ConceptFile> {
        self.files.iter().find(|f| f.relpath == relpath)
    }

    /// A deterministic hash of the whole tree: every file's path and
    /// content hash, in sorted order. Two passes over an unchanged
    /// bundle always record the same snapshot hash.
    pub fn snapshot_hash(&self) -> String {
        let mut material = String::new();
        for file in &self.files {
            material.push_str(&file.relpath);
            material.push('\n');
            material.push_str(&file.hash);
            material.push('\n');
        }
        sha256_hex(material.as_bytes())
    }
}

fn collect_markdown(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?
    {
        // An entry that errors mid-listing is reported like any
        // other unreadable path, never dropped: a dropped entry
        // is a file missing from the inventory, and a partial
        // inventory would corrupt the pass.
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        entries.push(entry.path());
    }
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.starts_with('.') {
            continue;
        }
        let kind = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
            .file_type();
        if kind.is_symlink() {
            // Never follow a link out of the bundle. A link whose
            // target resolves inside the root is still skipped, so a
            // pass can never be redirected by bundle content.
            continue;
        }
        if kind.is_dir() {
            collect_markdown(root, &path, out)?;
        } else if kind.is_file() && name.ends_with(".md") {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| format!("path escapes bundle root: {}", path.display()))?;
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

/// The migrator's state manifest at `.recension/state.json`, reduced
/// to the shape the type-stripping guard needs: which relative paths
/// were concepts at migration time, and of what type.
#[derive(Debug, Clone, Default)]
pub struct StateManifest {
    /// Concept relative path to its recorded type.
    pub concepts: BTreeMap<String, String>,
}

impl StateManifest {
    /// Loads the manifest when one exists. A bundle without a
    /// manifest simply has no guard baseline.
    pub fn load(root: &Path) -> StateManifest {
        let path = root.join(".recension").join("state.json");
        let Ok(text) = std::fs::read_to_string(path) else {
            return StateManifest::default();
        };
        let mut concepts = BTreeMap::new();
        // The manifest is a flat object with a nested "concepts" map
        // of path to type, read through the engine's one JSON parser
        // like every other artefact the engine consumes.
        if let Some(root) = parse(&text)
            && let Some(entries) = root.get("concepts").and_then(|v| v.as_obj())
        {
            for (key, value) in entries {
                if key.ends_with(".md")
                    && let Some(recorded) = value.as_str()
                {
                    concepts.insert(key.clone(), recorded.to_string());
                }
            }
        }
        StateManifest { concepts }
    }
}
