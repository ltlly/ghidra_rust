//! `BrowserCodeUnitFormat` -- format options for code unit display.
//!
//! Ported from `ghidra.app.util.viewer.field.BrowserCodeUnitFormat`.

/// Format options controlling how code units are displayed in the listing.
///
/// Ported from `BrowserCodeUnitFormat.java`.
#[derive(Debug, Clone)]
pub struct BrowserCodeUnitFormat {
    /// Show the address prefix for labels.
    pub show_address: bool,
    /// Show the namespace for labels.
    pub show_namespace: bool,
    /// Show the parameter names in function signatures.
    pub show_param_names: bool,
    /// Default label limit per field.
    pub label_limit: usize,
}

impl Default for BrowserCodeUnitFormat {
    fn default() -> Self {
        Self {
            show_address: true,
            show_namespace: true,
            show_param_names: true,
            label_limit: 10,
        }
    }
}

impl BrowserCodeUnitFormat {
    /// Create a new format with default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Format an address for display.
    pub fn format_address(&self, address: u64) -> String {
        format!("0x{:08X}", address)
    }

    /// Format a label with optional namespace.
    pub fn format_label(&self, label: &str, namespace: Option<&str>) -> String {
        match (self.show_namespace, namespace) {
            (true, Some(ns)) => format!("{}::{}", ns, label),
            _ => label.to_string(),
        }
    }

    /// Format a function signature.
    pub fn format_signature(&self, return_type: &str, name: &str, params: &str) -> String {
        format!("{} {}({})", return_type, name, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_address() {
        let fmt = BrowserCodeUnitFormat::default();
        assert_eq!(fmt.format_address(0x401000), "0x00401000");
    }

    #[test]
    fn test_format_label_with_namespace() {
        let fmt = BrowserCodeUnitFormat::default();
        assert_eq!(fmt.format_label("main", Some("libc")), "libc::main");
    }

    #[test]
    fn test_format_label_no_namespace() {
        let mut fmt = BrowserCodeUnitFormat::default();
        fmt.show_namespace = false;
        assert_eq!(fmt.format_label("main", Some("libc")), "main");
    }

    #[test]
    fn test_format_signature() {
        let fmt = BrowserCodeUnitFormat::default();
        assert_eq!(
            fmt.format_signature("int", "main", "int argc, char **argv"),
            "int main(int argc, char **argv)"
        );
    }
}
