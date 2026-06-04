//! Jython utility functions.
//!
//! Ported from `JythonUtils.java` in the Jython extension.

/// Utilities for Jython integration.
pub struct JythonUtils;

impl JythonUtils {
    /// Sanitize a script name for use as a Python module name.
    ///
    /// Replaces non-alphanumeric characters (except underscores) with
    /// underscores and strips the `.py` extension.
    pub fn sanitize_module_name(name: &str) -> String {
        let name = name.strip_suffix(".py").unwrap_or(name);
        name.chars()
            .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
            .collect()
    }

    /// Check if a string is a valid Python identifier.
    pub fn is_valid_identifier(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        let first = s.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Escape a string for use in Python source code.
    pub fn escape_python_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len() + 2);
        result.push('"');
        for c in s.chars() {
            match c {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                _ => result.push(c),
            }
        }
        result.push('"');
        result
    }

    /// Extract the shebang line from a script, if present.
    pub fn extract_shebang(source: &str) -> Option<&str> {
        source
            .lines()
            .next()
            .filter(|line| line.starts_with("#!"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_module_name() {
        assert_eq!(JythonUtils::sanitize_module_name("hello.py"), "hello");
        assert_eq!(
            JythonUtils::sanitize_module_name("my-script.py"),
            "my_script"
        );
        assert_eq!(JythonUtils::sanitize_module_name("test"), "test");
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(JythonUtils::is_valid_identifier("hello"));
        assert!(JythonUtils::is_valid_identifier("_private"));
        assert!(JythonUtils::is_valid_identifier("x1"));
        assert!(!JythonUtils::is_valid_identifier(""));
        assert!(!JythonUtils::is_valid_identifier("123"));
        assert!(!JythonUtils::is_valid_identifier("hello world"));
    }

    #[test]
    fn test_escape_python_string() {
        assert_eq!(
            JythonUtils::escape_python_string("hello"),
            "\"hello\""
        );
        assert_eq!(
            JythonUtils::escape_python_string("say \"hi\""),
            "\"say \\\"hi\\\"\""
        );
        assert_eq!(
            JythonUtils::escape_python_string("line\nnew"),
            "\"line\\nnew\""
        );
    }

    #[test]
    fn test_extract_shebang() {
        assert_eq!(
            JythonUtils::extract_shebang("#!/usr/bin/env python\nprint('hi')"),
            Some("#!/usr/bin/env python")
        );
        assert_eq!(
            JythonUtils::extract_shebang("print('hi')"),
            None
        );
    }
}
