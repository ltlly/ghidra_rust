//! Scoped view into a parent options store.
//!
//! Ports `ghidra.framework.options.SubOptions`.


/// A scoped view into a parent `ToolOptions` that prepends a prefix to all
/// option names.
///
/// Ported from Ghidra's `ghidra.framework.options.SubOptions`.
#[derive(Debug)]
pub struct SubOptions {
    /// Display name for this sub-options level.
    name: String,
    /// Prefix prepended to all option names.
    prefix: String,
}

impl SubOptions {
    /// Create a new sub-options view.
    pub fn new(name: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self { name: name.into(), prefix: prefix.into() }
    }

    /// Get the prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

impl PartialEq for SubOptions {
    fn eq(&self, other: &Self) -> bool {
        self.prefix == other.prefix
    }
}

impl Eq for SubOptions {}

impl std::hash::Hash for SubOptions {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.prefix.hash(state);
    }
}

impl std::fmt::Display for SubOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_options_creation() {
        let so = SubOptions::new("Display", "display.");
        assert_eq!(so.name, "Display");
        assert_eq!(so.prefix(), "display.");
    }

    #[test]
    fn test_sub_options_display() {
        let so = SubOptions::new("General", "general.");
        assert_eq!(so.to_string(), "General");
    }

    #[test]
    fn test_sub_options_equality() {
        let a = SubOptions::new("A", "prefix.");
        let b = SubOptions::new("B", "prefix.");
        assert_eq!(a, b); // Same prefix
    }
}
