//! A deterministic JSON writer, and a parser for foreign inputs.
//!
//! Reports and queue files must be byte-identical across runs over
//! the same inputs, so this writer emits object keys in sorted order
//! with fixed indentation and no incidental whitespace. The parser
//! below reads JSON the engine did not write, the exported
//! definition and schema files the drift check consumes. Numbers
//! keep their source literal, because the engine compares
//! identifiers and hashes and never does arithmetic on foreign
//! values.

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
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
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

/// A parsed JSON value from a foreign file.
#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    /// A JSON null.
    Null,
    /// A JSON boolean.
    Bool(bool),
    /// A JSON number, kept as its source literal.
    Num(String),
    /// A JSON string, fully unescaped.
    Str(String),
    /// A JSON array.
    Arr(Vec<Parsed>),
    /// A JSON object; keys are stored sorted by construction.
    Obj(BTreeMap<String, Parsed>),
}

impl Parsed {
    /// Looks up a key on an object value.
    pub fn get(&self, key: &str) -> Option<&Parsed> {
        match self {
            Parsed::Obj(map) => map.get(key),
            _ => None,
        }
    }

    /// The value as a string slice, when it is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Parsed::Str(value) => Some(value),
            _ => None,
        }
    }

    /// The value as an array slice, when it is an array.
    pub fn as_arr(&self) -> Option<&[Parsed]> {
        match self {
            Parsed::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// The value as an object map, when it is an object.
    pub fn as_obj(&self) -> Option<&BTreeMap<String, Parsed>> {
        match self {
            Parsed::Obj(map) => Some(map),
            _ => None,
        }
    }
}

/// The deepest nesting the parser accepts. A file nested deeper is
/// treated as malformed, so a corrupt or hostile export cannot
/// exhaust the stack.
const MAX_DEPTH: usize = 128;

/// Parses JSON text into a [`Parsed`] value. Returns None on any
/// malformed input, including trailing content after the value.
pub fn parse(text: &str) -> Option<Parsed> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = parser.value(0)?;
    parser.ws();
    if parser.pos != parser.bytes.len() {
        return None;
    }
    Some(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Option<Parsed> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match *self.bytes.get(self.pos)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Parsed::Str),
            b't' => self.literal("true", Parsed::Bool(true)),
            b'f' => self.literal("false", Parsed::Bool(false)),
            b'n' => self.literal("null", Parsed::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &str, value: Parsed) -> Option<Parsed> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Some(value)
        } else {
            None
        }
    }

    fn number(&mut self) -> Option<Parsed> {
        let start = self.pos;
        while self.pos < self.bytes.len()
            && matches!(
                self.bytes[self.pos],
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
            )
        {
            self.pos += 1;
        }
        let literal = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
        literal.parse::<f64>().ok()?;
        Some(Parsed::Num(literal.to_string()))
    }

    fn object(&mut self, depth: usize) -> Option<Parsed> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Some(Parsed::Obj(map));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return None;
            }
            self.pos += 1;
            let value = self.value(depth + 1)?;
            map.insert(key, value);
            self.ws();
            match self.bytes.get(self.pos) {
                Some(&b',') => self.pos += 1,
                Some(&b'}') => {
                    self.pos += 1;
                    return Some(Parsed::Obj(map));
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Parsed> {
        self.pos += 1;
        let mut items = Vec::new();
        self.ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Some(Parsed::Arr(items));
        }
        loop {
            let value = self.value(depth + 1)?;
            items.push(value);
            self.ws();
            match self.bytes.get(self.pos) {
                Some(&b',') => self.pos += 1,
                Some(&b']') => {
                    self.pos += 1;
                    return Some(Parsed::Arr(items));
                }
                _ => return None,
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let byte = *self.bytes.get(self.pos)?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Some(out);
                }
                b'\\' => {
                    let esc = *self.bytes.get(self.pos + 1)?;
                    self.pos += 2;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.bytes.get(self.pos) == Some(&b'\\')
                                    && self.bytes.get(self.pos + 1) == Some(&b'u')
                                {
                                    self.pos += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return None;
                                    }
                                    let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    out.push(char::from_u32(cp)?);
                                } else {
                                    return None;
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return None;
                            } else {
                                out.push(char::from_u32(hi)?);
                            }
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1F => return None,
                _ => {
                    let len = utf8_len(byte);
                    let text =
                        std::str::from_utf8(self.bytes.get(self.pos..self.pos + len)?).ok()?;
                    let ch = text.chars().next()?;
                    out.push(ch);
                    self.pos += len;
                }
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let byte = *self.bytes.get(self.pos)?;
            let digit = match byte {
                b'0'..=b'9' => (byte - b'0') as u32,
                b'a'..=b'f' => (byte - b'a' + 10) as u32,
                b'A'..=b'F' => (byte - b'A' + 10) as u32,
                _ => return None,
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Some(value)
    }
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

#[cfg(test)]
mod tests {
    use super::{Json, Parsed, parse};

    #[test]
    fn parses_a_nested_document() {
        let value = parse(r#"{"b": [1, 2.5, null], "a": {"x": true}}"#).unwrap();
        assert_eq!(
            value.get("a").and_then(|v| v.get("x")),
            Some(&Parsed::Bool(true))
        );
        let arr = value.get("b").and_then(|v| v.as_arr()).unwrap();
        assert_eq!(arr[0], Parsed::Num("1".to_string()));
        assert_eq!(arr[1], Parsed::Num("2.5".to_string()));
        assert_eq!(arr[2], Parsed::Null);
    }

    #[test]
    fn parses_escapes_and_unicode() {
        let value = parse(r#""a\nbé😀""#).unwrap();
        assert_eq!(value.as_str(), Some("a\nbé😀"));
        let pair = parse(r#""\uD83D\uDE00""#).unwrap();
        assert_eq!(pair.as_str(), Some("😀"));
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("{"), None);
        assert_eq!(parse("{} trailing"), None);
        assert_eq!(parse("[1,]"), None);
        assert_eq!(parse(r#""unterminated"#), None);
        assert_eq!(parse(r#""\uD83D alone""#), None);
        assert_eq!(parse("nul"), None);
    }

    #[test]
    fn nesting_is_capped() {
        let deep = "[".repeat(500);
        assert_eq!(parse(&deep), None);
    }

    #[test]
    fn keys_render_in_sorted_order() {
        let value = Json::obj(vec![("b", Json::Int(2)), ("a", Json::Int(1))]);
        let rendered = value.render();
        assert!(rendered.find("\"a\"").unwrap() < rendered.find("\"b\"").unwrap());
    }

    #[test]
    fn rendering_is_stable_across_calls() {
        let value = Json::obj(vec![("x", Json::strings(&["p".to_string()]))]);
        assert_eq!(value.render(), value.render());
    }
}
