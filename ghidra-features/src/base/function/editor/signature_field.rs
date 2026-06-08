//! Function signature text field logic.
//!
//! Ported from `FunctionSignatureTextField.java` in
//! `ghidra.app.plugin.core.function.editor`.
//!
//! Provides the color-computation logic for syntax-highlighting a
//! function signature string.  The actual Swing UI rendering is handled
//! elsewhere; this module focuses on the parsing and region-detection
//! business logic.

use std::fmt;

/// The kind of region in a function signature string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureRegionKind {
    /// The function name.
    FunctionName,
    /// A parameter name.
    ParameterName,
    /// The return type.
    ReturnType,
    /// Default text (types, punctuation).
    Default,
    /// Error region (unparseable).
    Error,
}

impl fmt::Display for SignatureRegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FunctionName => write!(f, "FunctionName"),
            Self::ParameterName => write!(f, "ParameterName"),
            Self::ReturnType => write!(f, "ReturnType"),
            Self::Default => write!(f, "Default"),
            Self::Error => write!(f, "Error"),
        }
    }
}

/// A colored region in a function signature string.
///
/// Ported from the inner `ColorField` class of
/// `FunctionSignatureTextField.java`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorField {
    /// Start offset (inclusive).
    pub start: usize,
    /// End offset (exclusive).
    pub end: usize,
    /// The kind of region.
    pub kind: SignatureRegionKind,
}

impl ColorField {
    /// Creates a new color field.
    pub fn new(start: usize, end: usize, kind: SignatureRegionKind) -> Self {
        Self { start, end, kind }
    }

    /// Returns the length of this region.
    pub fn length(&self) -> usize {
        self.end - self.start
    }

    /// Returns the text of this region from the given source string.
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start..self.end]
    }
}

/// Computes syntax-highlighting regions for a function signature string.
///
/// Ported from `FunctionSignatureTextField.computeColors()`.
///
/// Given a string like `"int main(int argc, char **argv)"`, this function
/// returns regions for the function name and each parameter name.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::signature_field::*;
///
/// let fields = compute_signature_colors("int main(int argc, char *argv)");
/// assert!(!fields.is_empty());
/// // First field should be the function name "main"
/// let name_field = &fields[0];
/// assert_eq!(name_field.kind, SignatureRegionKind::FunctionName);
/// ```
pub fn compute_signature_colors(text: &str) -> Vec<ColorField> {
    let mut list = Vec::new();

    let function_right_paren = match text.rfind(')') {
        Some(idx) => idx,
        None => return list,
    };

    let function_left_paren = match find_matching_left_paren(text, function_right_paren) {
        Some(idx) => idx,
        None => return list,
    };

    // Find parameter boundaries (comma-separated, respecting template brackets)
    let param_boundaries =
        match find_param_boundaries(text, function_left_paren, function_right_paren) {
            Some(b) => b,
            None => return list,
        };

    // Extract function name (last word before the opening paren)
    let before_paren = &text[..function_left_paren];
    if let Some(func_name) = get_last_word_range(before_paren) {
        list.push(ColorField::new(
            func_name.0,
            func_name.1,
            SignatureRegionKind::FunctionName,
        ));
    }

    // Extract parameter names
    for i in 0..param_boundaries.len() - 1 {
        let start = param_boundaries[i] + 1;
        let end = param_boundaries[i + 1];
        let param_str = text[start..end].trim();

        if param_str == "..." || param_str == "void" {
            continue;
        }

        // Empty param list
        if param_str.is_empty() && param_boundaries.len() == 2 {
            break;
        }

        // Find the last word in the parameter declaration
        let trimmed_param = param_str.trim_end();
        if let Some(last_space) = trimmed_param.rfind(' ') {
            let name_start_in_param = last_space + 1;
            let name_text = &trimmed_param[name_start_in_param..];

            // Skip leading '*' characters in the parameter name
            let skip_stars = name_text.chars().take_while(|c| *c == '*').count();
            let abs_start = start + (text[start..end].len() - text[start..end].trim_start().len());
            let name_abs_start = abs_start + name_start_in_param + skip_stars;
            let name_abs_end = abs_start + trimmed_param.len();

            if name_abs_start < name_abs_end {
                list.push(ColorField::new(
                    name_abs_start,
                    name_abs_end,
                    SignatureRegionKind::ParameterName,
                ));
            }
        }
    }

    list
}

/// Finds the matching left parenthesis for the given right parenthesis.
fn find_matching_left_paren(text: &str, right_paren: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut paren_level = 1u32;
    for i in (0..right_paren).rev() {
        match bytes[i] {
            b')' => paren_level += 1,
            b'(' => {
                paren_level -= 1;
                if paren_level == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Finds the comma-separated parameter boundaries within the parentheses.
fn find_param_boundaries(
    text: &str,
    start_paren: usize,
    end_paren: usize,
) -> Option<Vec<usize>> {
    let bytes = text.as_bytes();
    let mut boundaries = vec![start_paren];
    let mut template_count = 0i32;

    for i in start_paren + 1..end_paren {
        match bytes[i] {
            b'<' => template_count += 1,
            b'>' => template_count -= 1,
            b',' if template_count == 0 => boundaries.push(i),
            _ => {}
        }
    }

    if template_count != 0 {
        return None;
    }

    boundaries.push(end_paren);
    Some(boundaries)
}

/// Returns the (start, end) range of the last word in the given text,
/// relative to the start of the input.
fn get_last_word_range(text: &str) -> Option<(usize, usize)> {
    let trimmed = text.trim_end();
    if trimmed.is_empty() {
        return None;
    }
    let last_space = trimmed.rfind(' ').map(|i| i + 1).unwrap_or(0);
    let start_offset = text.len() - trimmed.len();
    Some((start_offset + last_space, text.len()))
}

/// Parses a function signature string into its component parts.
///
/// Returns `(return_type, function_name, param_types_and_names)` if
/// the signature is well-formed.
pub fn parse_signature(text: &str) -> Option<SignatureParts> {
    let right_paren = text.rfind(')')?;
    let left_paren = find_matching_left_paren(text, right_paren)?;

    let before = text[..left_paren].trim();
    let last_space = before.rfind(' ')?;
    let return_type = before[..last_space].trim().to_string();
    let function_name = before[last_space + 1..].trim().to_string();

    if function_name.is_empty() {
        return None;
    }

    let params_str = text[left_paren + 1..right_paren].trim();
    let params = if params_str == "void" || params_str.is_empty() {
        Vec::new()
    } else {
        params_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    };

    Some(SignatureParts {
        return_type,
        function_name,
        params,
    })
}

/// Parsed parts of a function signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureParts {
    /// The return type.
    pub return_type: String,
    /// The function name.
    pub function_name: String,
    /// The parameter declarations (as raw strings).
    pub params: Vec<String>,
}

impl fmt::Display for SignatureParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}(", self.return_type, self.function_name)?;
        for (i, p) in self.params.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", p)?;
        }
        write!(f, ")")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_colors_simple() {
        let fields = compute_signature_colors("int main(int argc, char *argv)");
        assert!(!fields.is_empty());
        assert_eq!(fields[0].kind, SignatureRegionKind::FunctionName);
        assert_eq!(fields[0].text("int main(int argc, char *argv)"), "main");
    }

    #[test]
    fn test_compute_colors_no_parens() {
        let fields = compute_signature_colors("no parens here");
        assert!(fields.is_empty());
    }

    #[test]
    fn test_compute_colors_empty_params() {
        let fields = compute_signature_colors("void func(void)");
        // "void" params are skipped
        let param_fields: Vec<_> = fields
            .iter()
            .filter(|f| f.kind == SignatureRegionKind::ParameterName)
            .collect();
        assert!(param_fields.is_empty());
    }

    #[test]
    fn test_compute_colors_varargs() {
        let fields = compute_signature_colors("int printf(const char *fmt, ...)");
        // "..." is skipped
        let param_fields: Vec<_> = fields
            .iter()
            .filter(|f| f.kind == SignatureRegionKind::ParameterName)
            .collect();
        // Only "fmt" should be a parameter name
        assert_eq!(param_fields.len(), 1);
    }

    #[test]
    fn test_find_matching_left_paren() {
        assert_eq!(find_matching_left_paren("int main(int x)", 14), Some(8));
        assert_eq!(find_matching_left_paren("a((b))", 5), Some(1));
        assert_eq!(find_matching_left_paren("no paren", 7), None);
    }

    #[test]
    fn test_parse_signature() {
        let parts = parse_signature("int main(int argc, char *argv)").unwrap();
        assert_eq!(parts.return_type, "int");
        assert_eq!(parts.function_name, "main");
        assert_eq!(parts.params.len(), 2);
    }

    #[test]
    fn test_parse_signature_void() {
        let parts = parse_signature("void func(void)").unwrap();
        assert_eq!(parts.return_type, "void");
        assert_eq!(parts.function_name, "func");
        assert!(parts.params.is_empty());
    }

    #[test]
    fn test_parse_signature_empty() {
        let parts = parse_signature("int func()").unwrap();
        assert!(parts.params.is_empty());
    }

    #[test]
    fn test_parse_signature_invalid() {
        assert!(parse_signature("no parens").is_none());
        assert!(parse_signature("()").is_none());
    }

    #[test]
    fn test_parse_signature_display() {
        let parts = SignatureParts {
            return_type: "int".into(),
            function_name: "add".into(),
            params: vec!["int a".into(), "int b".into()],
        };
        assert_eq!(format!("{}", parts), "int add(int a, int b)");
    }

    #[test]
    fn test_color_field() {
        let field = ColorField::new(4, 8, SignatureRegionKind::FunctionName);
        assert_eq!(field.length(), 4);
        assert_eq!(field.text("int main("), "main");
    }

    #[test]
    fn test_signature_region_kind_display() {
        assert_eq!(SignatureRegionKind::FunctionName.to_string(), "FunctionName");
        assert_eq!(SignatureRegionKind::ParameterName.to_string(), "ParameterName");
        assert_eq!(SignatureRegionKind::ReturnType.to_string(), "ReturnType");
    }

    #[test]
    fn test_compute_colors_multiple_params() {
        let fields = compute_signature_colors("void f(int a, int b, int c)");
        let param_fields: Vec<_> = fields
            .iter()
            .filter(|f| f.kind == SignatureRegionKind::ParameterName)
            .collect();
        assert_eq!(param_fields.len(), 3);
    }

    #[test]
    fn test_compute_colors_nested_templates() {
        // Template brackets should not cause false comma splits
        let fields = compute_signature_colors("void f(std::map<int,int> m, int x)");
        let param_fields: Vec<_> = fields
            .iter()
            .filter(|f| f.kind == SignatureRegionKind::ParameterName)
            .collect();
        assert_eq!(param_fields.len(), 2);
    }

    #[test]
    fn test_get_last_word_range() {
        assert_eq!(get_last_word_range("int main"), Some((4, 8)));
        assert_eq!(get_last_word_range("word"), Some((0, 4)));
        assert_eq!(get_last_word_range(""), None);
        assert_eq!(get_last_word_range("   "), None);
    }
}
