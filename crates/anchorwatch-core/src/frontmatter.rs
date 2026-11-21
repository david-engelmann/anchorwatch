//! A purpose-built parser for the frontmatter subset the engine reads.
//!
//! The engine never interprets body text and never rewrites
//! frontmatter it does not own, so it does not need a general YAML
//! parser. It needs the standard OKF fields named in the upkeep
//! contract: `type`, `title`, `status`, `superseded_by`,
//! `stale_after`, `generated.at`, the `verified` event list, and the
//! presence of `sources`. This parser reads exactly those, in the
//! block and flow forms the spec shows, and reports everything else
//! as untouched. Unknown keys are ignored, never rejected, as the
//! spec requires of consumers.

/// One verification event from a concept's `verified` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvent {
    /// The actor that confirmed the content, for example `human:ada`.
    pub by: String,
    /// The timestamp of the confirmation, as written.
    pub at: String,
}

/// The fields the upkeep contract reads from one concept file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frontmatter {
    /// The concept type, the one field the spec requires.
    pub concept_type: Option<String>,
    /// The concept title, used by index regeneration.
    pub title: Option<String>,
    /// The lifecycle status, for example `deprecated`.
    pub status: Option<String>,
    /// The declared supersession target, when one is declared.
    pub superseded_by: Option<String>,
    /// The review date exactly as written, never rewritten.
    pub stale_after: Option<String>,
    /// The `generated.at` timestamp, the last meaningful change.
    pub generated_at: Option<String>,
    /// Verification events, current and historical, in file order.
    pub verified: Vec<VerifiedEvent>,
    /// Whether the concept carries a `sources` family at all.
    pub has_sources: bool,
}

/// Splits a document into its parsed frontmatter and whether a
/// frontmatter block was present at all.
pub fn parse_document(text: &str) -> (Frontmatter, bool) {
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        return (Frontmatter::default(), false);
    }
    let mut fm = Frontmatter::default();
    let mut current_key = String::new();
    let mut pending_event: Option<(Option<String>, Option<String>)> = None;
    let flush_event = |fm: &mut Frontmatter, pending: &mut Option<(Option<String>, Option<String>)>| {
        if let Some((by, at)) = pending.take() {
            if let (Some(by), Some(at)) = (by, at) {
                fm.verified.push(VerifiedEvent { by, at });
            }
        }
    };
    for line in lines {
        if line == "---" {
            flush_event(&mut fm, &mut pending_event);
            return (fm, true);
        }
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            flush_event(&mut fm, &mut pending_event);
            let Some((key, value)) = trimmed.split_once(':') else {
                current_key.clear();
                continue;
            };
            current_key = key.trim().to_string();
            let value = clean_scalar(value);
            match current_key.as_str() {
                "type" => fm.concept_type = Some(value),
                "title" => fm.title = Some(value),
                "status" => fm.status = Some(value),
                "superseded_by" => fm.superseded_by = Some(value),
                "stale_after" => fm.stale_after = Some(value),
                "generated" => {
                    if let Some(at) = flow_value(&value, "at") {
                        fm.generated_at = Some(at);
                    }
                }
                "verified" => {
                    if value.starts_with('{') {
                        if let (Some(by), Some(at)) =
                            (flow_value(&value, "by"), flow_value(&value, "at"))
                        {
                            fm.verified.push(VerifiedEvent { by, at });
                        }
                    }
                }
                "sources" => {
                    if !value.is_empty() {
                        fm.has_sources = true;
                    }
                }
                _ => {}
            }
            continue;
        }
        match current_key.as_str() {
            "generated" => {
                if let Some((key, value)) = trimmed.split_once(':') {
                    if key.trim() == "at" {
                        fm.generated_at = Some(clean_scalar(value));
                    }
                }
            }
            "verified" => {
                let item = trimmed.strip_prefix("- ").unwrap_or(trimmed);
                if trimmed.starts_with("- ") || pending_event.is_some() {
                    if item.starts_with('{') {
                        if let (Some(by), Some(at)) =
                            (flow_value(item, "by"), flow_value(item, "at"))
                        {
                            fm.verified.push(VerifiedEvent { by, at });
                        }
                    } else if let Some((key, value)) = item.split_once(':') {
                        let entry = pending_event.get_or_insert((None, None));
                        match key.trim() {
                            "by" => entry.0 = Some(clean_scalar(value)),
                            "at" => entry.1 = Some(clean_scalar(value)),
                            _ => {}
                        }
                        if entry.0.is_some() && entry.1.is_some() {
                            flush_event(&mut fm, &mut pending_event);
                        }
                    }
                }
            }
            "sources" => {
                if trimmed.starts_with("- ") || trimmed.contains(':') {
                    fm.has_sources = true;
                }
            }
            _ => {}
        }
    }
    flush_event(&mut fm, &mut pending_event);
    (fm, true)
}

fn clean_scalar(value: &str) -> String {
    let value = value.trim();
    let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
    value.to_string()
}

fn flow_value(flow: &str, wanted: &str) -> Option<String> {
    let inner = flow.trim().strip_prefix('{')?.strip_suffix('}')?;
    for part in inner.split(',') {
        if let Some((key, value)) = part.split_once(':') {
            if key.trim() == wanted {
                return Some(clean_scalar(value));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_document;

    #[test]
    fn reads_the_standard_fields() {
        let doc = "---\ntype: Person\ntitle: \"Ada\"\nstatus: deprecated\nsuperseded_by: people/grace.md\nstale_after: 2026-12-01\ngenerated:\n  at: \"2026-11-01T10:00:00Z\"\n  by: \"process:import\"\n---\n\n# Ada\n";
        let (fm, present) = parse_document(doc);
        assert!(present);
        assert_eq!(fm.concept_type.as_deref(), Some("Person"));
        assert_eq!(fm.title.as_deref(), Some("Ada"));
        assert_eq!(fm.status.as_deref(), Some("deprecated"));
        assert_eq!(fm.superseded_by.as_deref(), Some("people/grace.md"));
        assert_eq!(fm.stale_after.as_deref(), Some("2026-12-01"));
        assert_eq!(fm.generated_at.as_deref(), Some("2026-11-01T10:00:00Z"));
    }

    #[test]
    fn reads_block_and_flow_verified_events() {
        let doc = "---\ntype: Note\nverified:\n  - by: \"human:ada\"\n    at: \"2026-11-02T09:00:00Z\"\n  - by: \"process:nightly\"\n    at: \"2026-11-03T09:00:00Z\"\n---\nbody\n";
        let (fm, _) = parse_document(doc);
        assert_eq!(fm.verified.len(), 2);
        assert_eq!(fm.verified[0].by, "human:ada");
        assert_eq!(fm.verified[1].at, "2026-11-03T09:00:00Z");
        let flow = "---\ntype: Note\nverified: { by: \"human:ada\", at: \"2026-11-02T09:00:00Z\" }\n---\n";
        let (fm, _) = parse_document(flow);
        assert_eq!(fm.verified.len(), 1);
    }

    #[test]
    fn a_document_without_frontmatter_is_not_a_concept() {
        let (fm, present) = parse_document("# Just a heading\n");
        assert!(!present);
        assert_eq!(fm.concept_type, None);
    }

    #[test]
    fn extension_keys_are_ignored_not_rejected() {
        let doc = "---\ntype: Note\nx-acme-owner: ada\n---\n";
        let (fm, present) = parse_document(doc);
        assert!(present);
        assert_eq!(fm.concept_type.as_deref(), Some("Note"));
    }
}
