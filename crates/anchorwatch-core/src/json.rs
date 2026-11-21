//! A deterministic JSON writer.
//!
//! Reports and queue files must be byte-identical across runs over
//! the same inputs, so this writer emits object keys in sorted order
//! with fixed indentation and no incidental whitespace. It writes
//! JSON; it does not parse it.

use std::collections::BTreeMap;

/// A JSON value in the small subset the engine emits.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// A string value.
    Str(String),
    /// An integer value.
    Int(i64),
    /// A boolean value.
    Bool(bool),
    /// An array of values.
    Arr(Vec<Json>),
    /// An object; keys are stored sorted by construction.
    Obj(BTreeMap<String, Json>),
}

impl Json {
    /// Builds an object from key and value pairs.
    pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
        Json::Obj(
            pairs
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    /// Builds an array of strings.
    pub fn strings(items: &[String]) -> Json {
        Json::Arr(items.iter().cloned().map(Json::Str).collect())
    }

    /// Renders the value with two-space indentation and a trailing
    /// newline, the house form for every emitted JSON artefact.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, indent: usize) {
        match self {
            Json::Str(s) => out.push_str(&escape(s)),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    item.write(out, indent + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push(']');
            }
            Json::Obj(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                let len = map.len();
                for (i, (key, value)) in map.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    out.push_str(&escape(key));
                    out.push_str(": ");
                    value.write(out, indent + 1);
                    if i + 1 < len {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push('}');
            }
        }
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::Json;

    #[test]
    fn keys_render_in_sorted_order() {
        let value = Json::obj(vec![
            ("b", Json::Int(2)),
            ("a", Json::Int(1)),
        ]);
        let rendered = value.render();
        assert!(rendered.find("\"a\"").unwrap() < rendered.find("\"b\"").unwrap());
    }

    #[test]
    fn rendering_is_stable_across_calls() {
        let value = Json::obj(vec![("x", Json::strings(&["p".to_string()]))]);
        assert_eq!(value.render(), value.render());
    }
}
