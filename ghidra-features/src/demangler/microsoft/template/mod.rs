//! Template name and arguments parsing.
//!
//! Ported from `mdemangler.template.*` Java classes.

use std::fmt;

// ---------------------------------------------------------------------------
// TemplateNameAndArguments
// ---------------------------------------------------------------------------

/// A template name with its argument list.
///
/// Ported from `MDTemplateNameAndArguments.java`.
#[derive(Debug, Clone)]
pub struct TemplateNameAndArguments {
    /// The template name (e.g., "vector").
    pub name: String,
    /// The template arguments (as demangled strings).
    pub arguments: Vec<String>,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// Cast type string for type-cast operators.
    pub cast_type_string: Option<String>,
}

impl TemplateNameAndArguments {
    pub fn new(name: String) -> Self {
        Self {
            name,
            arguments: Vec::new(),
            is_constructor: false,
            is_destructor: false,
            cast_type_string: None,
        }
    }

    /// Emit the template name with arguments in angle brackets.
    pub fn emit(&self) -> String {
        if self.arguments.is_empty() {
            self.name.clone()
        } else {
            format!("{}<{}>", self.name, self.arguments.join(", "))
        }
    }
}

impl fmt::Display for TemplateNameAndArguments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit())
    }
}

// ---------------------------------------------------------------------------
// TemplateConstant
// ---------------------------------------------------------------------------

/// A template constant argument (integer or enum value).
///
/// Ported from `MDTemplateConstant.java`.
#[derive(Debug, Clone)]
pub struct TemplateConstant {
    /// The constant value as a string.
    pub value: String,
}

impl TemplateConstant {
    pub fn new(value: String) -> Self {
        Self { value }
    }

    /// Parse a template constant from the character stream.
    ///
    /// Template constants can be:
    /// - `$0` through `$9` for 0-9
    /// - `$A` through `$O` for negative numbers (-1 through -15)
    /// - `$P` for 0 (prefix)
    /// - A number terminated by `@`
    pub fn parse(chars: &[char], index: &mut usize) -> Option<Self> {
        if *index >= chars.len() {
            return None;
        }

        if chars[*index] == '$' {
            *index += 1;
            if *index >= chars.len() {
                return None;
            }
            let ch = chars[*index];
            *index += 1;
            match ch {
                '0'..='9' => {
                    let val = (ch as u8 - b'0') as i64;
                    Some(Self::new(val.to_string()))
                }
                'A'..='O' => {
                    let val = -((ch as u8 - b'A') as i64 + 1);
                    Some(Self::new(val.to_string()))
                }
                _ => None,
            }
        } else {
            // Parse a number terminated by '@'
            let mut num_str = String::new();
            while *index < chars.len() {
                let ch = chars[*index];
                if ch == '@' {
                    *index += 1;
                    break;
                }
                if ch == '?' && *index + 1 < chars.len() && chars[*index + 1] == '$' {
                    // Signed negative: `?$` prefix
                    *index += 2;
                    if *index < chars.len() {
                        let neg_ch = chars[*index];
                        *index += 1;
                        match neg_ch {
                            '0'..='9' => {
                                let val = -((neg_ch as u8 - b'0') as i64);
                                return Some(Self::new(val.to_string()));
                            }
                            _ => return None,
                        }
                    }
                }
                num_str.push(ch);
                *index += 1;
            }
            if num_str.is_empty() {
                None
            } else {
                Some(Self::new(num_str))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_name_emit() {
        let t = TemplateNameAndArguments::new("vector".to_string());
        assert_eq!(t.emit(), "vector");

        let mut t = TemplateNameAndArguments::new("vector".to_string());
        t.arguments.push("int".to_string());
        t.arguments.push("std::allocator<int>".to_string());
        assert_eq!(t.emit(), "vector<int, std::allocator<int>>");
    }

    #[test]
    fn test_template_constant_dollar() {
        let chars: Vec<char> = "$0".chars().collect();
        let mut index = 0;
        let tc = TemplateConstant::parse(&chars, &mut index).unwrap();
        assert_eq!(tc.value, "0");
        assert_eq!(index, 2);
    }

    #[test]
    fn test_template_constant_negative() {
        let chars: Vec<char> = "$A".chars().collect();
        let mut index = 0;
        let tc = TemplateConstant::parse(&chars, &mut index).unwrap();
        assert_eq!(tc.value, "-1");
    }

    #[test]
    fn test_template_constant_number() {
        let chars: Vec<char> = "42@".chars().collect();
        let mut index = 0;
        let tc = TemplateConstant::parse(&chars, &mut index).unwrap();
        assert_eq!(tc.value, "42");
    }
}
