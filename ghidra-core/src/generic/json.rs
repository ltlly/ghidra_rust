//! JSON parsing utilities for Ghidra Rust.
//!
//! A JSMN-inspired token parser that produces a tree of typed values.
//! Corresponds to Ghidra's `generic.json` package.

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// JSONType — token type classification
// ============================================================================

/// JSON token types matching Ghidra's `JSONType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonType {
    /// A primitive value (number, boolean, null).
    Primitive,
    /// A JSON object (`{ ... }`).
    Object,
    /// A JSON array (`[ ... ]`).
    Array,
    /// A JSON string.
    String,
}

// ============================================================================
// JSONError — parser error codes
// ============================================================================

/// JSON parser error codes matching Ghidra's `JSONError` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Everything was fine.
    Success,
    /// Not enough tokens were provided.
    NoMem,
    /// Invalid character inside JSON string.
    Inval,
    /// The string is not a full JSON packet, more bytes expected.
    Part,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::Success => write!(f, "Success"),
            JsonError::NoMem => write!(f, "Out of memory"),
            JsonError::Inval => write!(f, "Invalid character"),
            JsonError::Part => write!(f, "Incomplete JSON"),
        }
    }
}

// ============================================================================
// JSONToken — a single parsed token
// ============================================================================

/// A single JSON token with type and byte range into the source.
#[derive(Debug, Clone)]
pub struct JsonToken {
    /// The token type.
    pub token_type: JsonType,
    /// Start offset (exclusive of opening quote for strings).
    pub start: usize,
    /// End offset (exclusive).
    pub end: usize,
    /// Number of children (keys + values for objects, elements for arrays).
    pub size: usize,
}

impl JsonToken {
    pub fn new(token_type: JsonType, start: usize, end: usize) -> Self {
        Self {
            token_type,
            start,
            end,
            size: 0,
        }
    }

    pub fn inc_size(&mut self) {
        self.size += 1;
    }
}

// ============================================================================
// JSONParser — token-based parser
// ============================================================================

/// A JSMN-inspired JSON parser that tokenizes a character buffer.
///
/// Use [`JSONParser::parse`] to tokenize, then [`JSONParser::convert`] to
/// build a Rust value tree.
#[derive(Debug)]
pub struct JsonParser {
    pos: usize,
    toknext: usize,
    toksuper: isize,
    ndx: usize,
}

impl Default for JsonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonParser {
    pub fn new() -> Self {
        Self {
            pos: 0,
            toknext: 0,
            toksuper: -1,
            ndx: 0,
        }
    }

    fn allocate_token(
        &mut self,
        tokens: &mut Vec<JsonToken>,
        token_type: JsonType,
        start: usize,
        end: usize,
    ) -> usize {
        tokens.push(JsonToken::new(token_type, start, end));
        self.toknext = tokens.len();
        self.toknext - 1
    }

    fn is_xdigit(c: char) -> bool {
        matches!(c, '0'..='9' | 'A'..='F' | 'a'..='f')
    }

    fn parse_primitive(&mut self, js: &[u8], tokens: &mut Vec<JsonToken>) -> JsonError {
        let start = self.pos;

        while self.pos < js.len() {
            let c = js[self.pos] as char;
            match c {
                '\t' | '\r' | '\n' | ' ' | ':' | ',' | ']' | '}' => {
                    break;
                }
                _ if (c as u32) < 32 => {
                    self.pos = start;
                    return JsonError::Inval;
                }
                _ => {}
            }
            self.pos += 1;
        }

        self.allocate_token(tokens, JsonType::Primitive, start, self.pos);
        self.pos -= 1;
        JsonError::Success
    }

    fn parse_string(&mut self, js: &[u8], tokens: &mut Vec<JsonToken>) -> JsonError {
        let start = self.pos;
        self.pos += 1; // skip opening quote

        while self.pos < js.len() {
            let c = js[self.pos] as char;

            if c == '"' {
                self.allocate_token(tokens, JsonType::String, start + 1, self.pos);
                return JsonError::Success;
            }

            if c == '\\' {
                self.pos += 1;
                if self.pos >= js.len() {
                    self.pos = start;
                    return JsonError::Part;
                }
                let esc = js[self.pos] as char;
                match esc {
                    '"' | '/' | '\\' | 'b' | 'f' | 'r' | 'n' | 't' => {}
                    'u' => {
                        for _ in 0..4 {
                            self.pos += 1;
                            if self.pos >= js.len() || !Self::is_xdigit(js[self.pos] as char) {
                                self.pos = start;
                                return JsonError::Inval;
                            }
                        }
                    }
                    _ => {
                        self.pos = start;
                        return JsonError::Inval;
                    }
                }
            }
            self.pos += 1;
        }

        self.pos = start;
        JsonError::Part
    }

    /// Tokenize a JSON character buffer.
    ///
    /// On success, `tokens` is populated with the parsed tokens and
    /// [`JsonError::Success`] is returned.
    pub fn parse(&mut self, js: &[u8], tokens: &mut Vec<JsonToken>) -> JsonError {
        self.pos = 0;
        self.toknext = 0;
        self.toksuper = -1;

        while self.pos < js.len() {
            let c = js[self.pos] as char;
            match c {
                '{' | '[' => {
                    let token_type = if c == '{' {
                        JsonType::Object
                    } else {
                        JsonType::Array
                    };
                    self.allocate_token(tokens, token_type, self.pos, usize::MAX);
                    if self.toksuper != -1 {
                        let super_idx = self.toksuper as usize;
                        tokens[super_idx].inc_size();
                    }
                    self.toksuper = self.toknext as isize - 1;
                }
                '}' | ']' => {
                    let expected = if c == '}' {
                        JsonType::Object
                    } else {
                        JsonType::Array
                    };
                    let mut found = false;
                    let mut i = self.toknext as isize - 1;
                    while i >= 0 {
                        let idx = i as usize;
                        if tokens[idx].start != usize::MAX && tokens[idx].end == usize::MAX {
                            if tokens[idx].token_type != expected {
                                return JsonError::Inval;
                            }
                            self.toksuper = -1;
                            tokens[idx].end = self.pos + 1;
                            found = true;
                            break;
                        }
                        i -= 1;
                    }
                    if !found {
                        return JsonError::Inval;
                    }
                    // Find new parent
                    while i >= 0 {
                        let idx = i as usize;
                        if tokens[idx].start != usize::MAX && tokens[idx].end == usize::MAX {
                            self.toksuper = i;
                            break;
                        }
                        i -= 1;
                    }
                }
                '"' => {
                    let r = self.parse_string(js, tokens);
                    if r != JsonError::Success {
                        return r;
                    }
                    if self.toksuper != -1 {
                        let super_idx = self.toksuper as usize;
                        tokens[super_idx].inc_size();
                    }
                }
                '\t' | '\r' | '\n' | ':' | ',' | ' ' => {}
                '-' | '0'..='9' | 't' | 'f' | 'n' => {
                    let r = self.parse_primitive(js, tokens);
                    if r != JsonError::Success {
                        return r;
                    }
                    if self.toksuper != -1 {
                        let super_idx = self.toksuper as usize;
                        tokens[super_idx].inc_size();
                    }
                }
                _ => {
                    return JsonError::Inval;
                }
            }
            self.pos += 1;
        }

        // Check for unmatched open brackets
        for i in (0..self.toknext).rev() {
            if tokens[i].start != usize::MAX && tokens[i].end == usize::MAX {
                return JsonError::Part;
            }
        }

        JsonError::Success
    }

    /// Convert tokens into a Rust value tree.
    ///
    /// Returns `None` on parsing error. Supports `HashMap<String, Value>` for
    /// objects, `Vec<Value>` for arrays, `String` for strings, and `i64` for
    /// numeric primitives. `true`/`false`/`null` are also supported.
    pub fn convert(&mut self, js: &[u8], tokens: &[JsonToken]) -> Option<JsonValue> {
        self.ndx = 0;
        self.convert_inner(js, tokens)
    }

    fn convert_inner(&mut self, js: &[u8], tokens: &[JsonToken]) -> Option<JsonValue> {
        if self.ndx >= tokens.len() {
            return None;
        }
        let tp = &tokens[self.ndx];
        self.ndx += 1;

        let tstr = std::str::from_utf8(&js[tp.start..tp.end]).ok()?;

        match tp.token_type {
            JsonType::Object => {
                if tp.size % 2 != 0 {
                    return None; // keys must pair with values
                }
                let mut map = HashMap::with_capacity(tp.size / 2);
                for _ in 0..tp.size / 2 {
                    let k = self.convert_inner(js, tokens)?;
                    let v = self.convert_inner(js, tokens)?;
                    if let JsonValue::String(key) = k {
                        map.insert(key, v);
                    } else {
                        return None;
                    }
                }
                Some(JsonValue::Object(map))
            }
            JsonType::Array => {
                let mut arr = Vec::with_capacity(tp.size);
                for _ in 0..tp.size {
                    arr.push(self.convert_inner(js, tokens)?);
                }
                Some(JsonValue::Array(arr))
            }
            JsonType::Primitive => match tstr {
                "true" => Some(JsonValue::Bool(true)),
                "false" => Some(JsonValue::Bool(false)),
                "null" => Some(JsonValue::Null),
                _ => {
                    // Try to parse as number
                    if let Ok(n) = tstr.parse::<i64>() {
                        Some(JsonValue::Number(n))
                    } else if let Ok(f) = tstr.parse::<f64>() {
                        Some(JsonValue::Float(f))
                    } else {
                        None
                    }
                }
            },
            JsonType::String => Some(JsonValue::String(unescape_json_string(tstr).unwrap_or_else(|| tstr.to_string()))),
        }
    }
}

// ============================================================================
// JsonValue — the parsed value tree
// ============================================================================

/// A parsed JSON value.
///
/// Corresponds to the various types that `JSONParser.convert()` returns in
/// Ghidra's Java implementation.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// A JSON object (key/value pairs).
    Object(HashMap<String, JsonValue>),
    /// A JSON array.
    Array(Vec<JsonValue>),
    /// A JSON string.
    String(String),
    /// An integer number.
    Number(i64),
    /// A floating-point number.
    Float(f64),
    /// A boolean value.
    Bool(bool),
    /// The JSON `null` value.
    Null,
}

impl JsonValue {
    pub fn is_object(&self) -> bool {
        matches!(self, JsonValue::Object(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, JsonValue::Array(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, JsonValue::String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, JsonValue::Number(_) | JsonValue::Float(_))
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, JsonValue::Bool(_))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }

    /// Get an object value by key.
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        if let JsonValue::Object(map) = self {
            map.get(key)
        } else {
            None
        }
    }

    /// Get an array element by index.
    pub fn get_index(&self, index: usize) -> Option<&JsonValue> {
        if let JsonValue::Array(arr) = self {
            arr.get(index)
        } else {
            None
        }
    }

    /// Get as string slice.
    pub fn as_str(&self) -> Option<&str> {
        if let JsonValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Get as i64.
    pub fn as_i64(&self) -> Option<i64> {
        if let JsonValue::Number(n) = self {
            Some(*n)
        } else {
            None
        }
    }

    /// Get as f64.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Float(f) => Some(*f),
            JsonValue::Number(n) => Some(*n as f64),
            _ => None,
        }
    }

    /// Get as bool.
    pub fn as_bool(&self) -> Option<bool> {
        if let JsonValue::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    /// Get as array slice.
    pub fn as_array(&self) -> Option<&[JsonValue]> {
        if let JsonValue::Array(arr) = self {
            Some(arr)
        } else {
            None
        }
    }

    /// Get as object map.
    pub fn as_object(&self) -> Option<&HashMap<String, JsonValue>> {
        if let JsonValue::Object(map) = self {
            Some(map)
        } else {
            None
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonValue::Object(map) => {
                write!(f, "{{")?;
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "\"{}\":{}", k, v)?;
                }
                write!(f, "}}")
            }
            JsonValue::Array(arr) => {
                write!(f, "[")?;
                for (i, v) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
            JsonValue::String(s) => write!(f, "\"{}\"", s),
            JsonValue::Number(n) => write!(f, "{}", n),
            JsonValue::Float(fl) => write!(f, "{}", fl),
            JsonValue::Bool(b) => write!(f, "{}", b),
            JsonValue::Null => write!(f, "null"),
        }
    }
}

// ============================================================================
// Helper: unescape JSON strings
// ============================================================================

fn unescape_json_string(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 1;
            match bytes[i] {
                b'"' => result.push(b'"'),
                b'\\' => result.push(b'\\'),
                b'/' => result.push(b'/'),
                b'b' => result.push(0x08),
                b'f' => result.push(0x0C),
                b'n' => result.push(b'\n'),
                b'r' => result.push(b'\r'),
                b't' => result.push(b'\t'),
                b'u' => {
                    if i + 4 >= bytes.len() {
                        return None;
                    }
                    let hex = std::str::from_utf8(&bytes[i + 1..i + 5]).ok()?;
                    let cp = u32::from_str_radix(hex, 16).ok()?;
                    let ch = char::from_u32(cp)?;
                    let mut buf = [0u8; 4];
                    let encoded = ch.encode_utf8(&mut buf);
                    result.extend_from_slice(encoded.as_bytes());
                    i += 4;
                }
                _ => return None,
            }
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(result).ok()
}

// ============================================================================
// Convenience: parse a JSON string into a JsonValue
// ============================================================================

/// Parse a JSON string into a [`JsonValue`].
///
/// Returns `None` if the input is not valid JSON.
pub fn parse_json(input: &str) -> Option<JsonValue> {
    let bytes = input.as_bytes();
    let mut parser = JsonParser::new();
    let mut tokens = Vec::new();
    let err = parser.parse(bytes, &mut tokens);
    if err != JsonError::Success {
        return None;
    }
    parser.ndx = 0;
    parser.convert(bytes, &tokens)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_object() {
        let json = r#"{"name":"test","value":42}"#;
        let val = parse_json(json).unwrap();
        assert!(val.is_object());
        assert_eq!(val.get("name").unwrap().as_str(), Some("test"));
        assert_eq!(val.get("value").unwrap().as_i64(), Some(42));
    }

    #[test]
    fn test_parse_array() {
        let json = r#"[1,2,3]"#;
        let val = parse_json(json).unwrap();
        assert!(val.is_array());
        assert_eq!(val.as_array().unwrap().len(), 3);
        assert_eq!(val.get_index(0).unwrap().as_i64(), Some(1));
    }

    #[test]
    fn test_parse_nested() {
        let json = r#"{"a":{"b":[true,false,null]}}"#;
        let val = parse_json(json).unwrap();
        let inner = val.get("a").unwrap().get("b").unwrap();
        assert_eq!(inner.get_index(0).unwrap().as_bool(), Some(true));
        assert_eq!(inner.get_index(1).unwrap().as_bool(), Some(false));
        assert!(inner.get_index(2).unwrap().is_null());
    }

    #[test]
    fn test_parse_string_escapes() {
        let json = r#""hello\nworld""#;
        let val = parse_json(json).unwrap();
        assert_eq!(val.as_str(), Some("hello\nworld"));
    }

    #[test]
    fn test_parse_empty() {
        let val = parse_json("");
        assert!(val.is_none());
    }

    #[test]
    fn test_parse_invalid() {
        let val = parse_json("{invalid}");
        assert!(val.is_none());
    }

    #[test]
    fn test_json_value_display() {
        let val = JsonValue::Number(42);
        assert_eq!(format!("{}", val), "42");

        let val = JsonValue::String("hello".to_string());
        assert_eq!(format!("{}", val), "\"hello\"");

        let val = JsonValue::Bool(true);
        assert_eq!(format!("{}", val), "true");

        let val = JsonValue::Null;
        assert_eq!(format!("{}", val), "null");
    }

    #[test]
    fn test_json_value_as_f64() {
        let val = JsonValue::Number(42);
        assert_eq!(val.as_f64(), Some(42.0));
        let val = JsonValue::Float(3.14);
        assert!((val.as_f64().unwrap() - 3.14).abs() < 0.001);
    }

    #[test]
    fn test_tokenizer_only() {
        let json = r#"{"key":"value"}"#;
        let bytes = json.as_bytes();
        let mut parser = JsonParser::new();
        let mut tokens = Vec::new();
        let err = parser.parse(bytes, &mut tokens);
        assert_eq!(err, JsonError::Success);
        // Should have at least: 1 object, 1 string key, 1 string value
        assert!(tokens.len() >= 3);
    }

    #[test]
    fn test_parse_float() {
        let json = r#"{"pi":3.14}"#;
        let val = parse_json(json).unwrap();
        let pi = val.get("pi").unwrap();
        assert!(pi.is_number());
        assert!((pi.as_f64().unwrap() - 3.14).abs() < 0.001);
    }
}
