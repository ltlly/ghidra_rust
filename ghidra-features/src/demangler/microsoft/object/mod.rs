//! Object parsing for Microsoft demangling.
//!
//! Ported from `mdemangler.object.*` Java classes.

use std::fmt;

// ---------------------------------------------------------------------------
// MDString
// ---------------------------------------------------------------------------

/// An encoded string literal in a mangled name.
///
/// Ported from `MDString.java`.
#[derive(Debug, Clone)]
pub struct MangledString {
    /// The decoded string content.
    pub content: String,
    /// Whether the string is UTF-16 encoded.
    pub is_utf16: bool,
}

impl MangledString {
    pub fn new(content: String) -> Self {
        Self {
            content,
            is_utf16: false,
        }
    }

    /// Parse a mangled string from the character stream.
    ///
    /// A mangled string is a sequence of characters terminated by `@`.
    /// Special sequences like `?0`, `?1`, etc. encode special characters.
    pub fn parse(chars: &[char], index: &mut usize) -> Result<Self, String> {
        let mut content = String::new();
        while *index < chars.len() {
            let ch = chars[*index];
            if ch == '@' {
                *index += 1;
                break;
            }
            if ch == '?' && *index + 1 < chars.len() {
                let next = chars[*index + 1];
                *index += 2;
                match next {
                    '0'..='9' => {
                        content.push((b'0' + (next as u8 - b'0')) as char);
                    }
                    'A'..='Z' => {
                        content.push((b'A' + (next as u8 - b'A')) as char);
                    }
                    'a'..='z' => {
                        content.push((b'a' + (next as u8 - b'a')) as char);
                    }
                    '$' => {
                        content.push('$');
                    }
                    '@' => {
                        content.push('@');
                    }
                    _ => {
                        return Err(format!("Unknown string escape: ?{}", next));
                    }
                }
            } else {
                content.push(ch);
                *index += 1;
            }
        }
        Ok(Self::new(content))
    }
}

impl fmt::Display for MangledString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_string() {
        let chars: Vec<char> = "hello@".chars().collect();
        let mut index = 0;
        let s = MangledString::parse(&chars, &mut index).unwrap();
        assert_eq!(s.content, "hello");
    }

    #[test]
    fn test_string_with_escape() {
        let chars: Vec<char> = "ab?0cd@".chars().collect();
        let mut index = 0;
        let s = MangledString::parse(&chars, &mut index).unwrap();
        assert_eq!(s.content, "ab0cd");
    }

    #[test]
    fn test_empty_string() {
        let chars: Vec<char> = "@".chars().collect();
        let mut index = 0;
        let s = MangledString::parse(&chars, &mut index).unwrap();
        assert_eq!(s.content, "");
    }
}
