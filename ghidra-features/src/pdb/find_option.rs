//! Find Options -- options for controlling PDB file searches.
//!
//! Ports Ghidra's `pdb.symbolserver.FindOption`.

use std::collections::HashSet;
use std::fmt;

/// Options that control how PDB files are searched for on a SymbolServer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindOption {
    /// Allow connections to untrusted symbol servers.
    AllowUntrusted,
    /// Only return the first result.
    OnlyFirstResult,
    /// Match any PDB with the same name, regardless of GUID/signature/age.
    /// Implies `AnyAge`.
    AnyId,
    /// Match any PDB with the same name and ID, regardless of age.
    AnyAge,
}

impl FindOption {
    /// Get the display label for this option.
    pub fn label(&self) -> &'static str {
        match self {
            FindOption::AllowUntrusted => "Allow Untrusted",
            FindOption::OnlyFirstResult => "Only First Result",
            FindOption::AnyId => "Any ID",
            FindOption::AnyAge => "Any Age",
        }
    }
}

impl fmt::Display for FindOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A set of FindOptions.
#[derive(Debug, Clone, Default)]
pub struct FindOptions {
    options: HashSet<FindOption>,
}

impl FindOptions {
    /// Create an empty set of options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a set with the given options.
    pub fn with(options: &[FindOption]) -> Self {
        Self {
            options: options.iter().copied().collect(),
        }
    }

    /// Add an option to the set.
    pub fn add(&mut self, option: FindOption) {
        self.options.insert(option);
    }

    /// Check if an option is present.
    pub fn contains(&self, option: FindOption) -> bool {
        self.options.contains(&option)
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.options.is_empty()
    }

    /// Get the number of options.
    pub fn len(&self) -> usize {
        self.options.len()
    }

    /// Check if untrusted servers are allowed.
    pub fn allow_untrusted(&self) -> bool {
        self.contains(FindOption::AllowUntrusted)
    }

    /// Check if only the first result should be returned.
    pub fn only_first_result(&self) -> bool {
        self.contains(FindOption::OnlyFirstResult)
    }

    /// Check if any ID match is acceptable.
    pub fn any_id(&self) -> bool {
        self.contains(FindOption::AnyId)
    }

    /// Check if any age match is acceptable.
    pub fn any_age(&self) -> bool {
        self.contains(FindOption::AnyAge) || self.any_id()
    }
}

impl fmt::Display for FindOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.options.is_empty() {
            return write!(f, "NoOptions");
        }
        let opts: Vec<String> = self.options.iter().map(|o| o.label().to_string()).collect();
        write!(f, "{}", opts.join(", "))
    }
}

/// A constant empty set of no FindOptions.
pub fn no_options() -> FindOptions {
    FindOptions::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_options() {
        let opts = FindOptions::new();
        assert!(opts.is_empty());
        assert!(!opts.allow_untrusted());
        assert!(!opts.any_id());
        assert!(!opts.any_age()); // any_age checks AnyAge || any_id(), both false
    }

    #[test]
    fn test_with_options() {
        let opts = FindOptions::with(&[FindOption::AllowUntrusted, FindOption::AnyAge]);
        assert!(opts.allow_untrusted());
        assert!(opts.any_age());
        assert!(!opts.only_first_result());
    }

    #[test]
    fn test_any_id_implies_any_age() {
        let opts = FindOptions::with(&[FindOption::AnyId]);
        assert!(opts.any_id());
        assert!(opts.any_age()); // any_age checks AnyAge || any_id()
    }

    #[test]
    fn test_add_option() {
        let mut opts = FindOptions::new();
        opts.add(FindOption::OnlyFirstResult);
        assert!(opts.only_first_result());
        assert_eq!(opts.len(), 1);
    }

    #[test]
    fn test_display() {
        let opts = FindOptions::new();
        assert_eq!(format!("{}", opts), "NoOptions");

        let opts = FindOptions::with(&[FindOption::AllowUntrusted]);
        let s = format!("{}", opts);
        assert!(s.contains("Allow Untrusted"));
    }

    #[test]
    fn test_option_display() {
        assert_eq!(format!("{}", FindOption::AllowUntrusted), "Allow Untrusted");
        assert_eq!(format!("{}", FindOption::AnyId), "Any ID");
    }

    #[test]
    fn test_no_options_function() {
        let opts = no_options();
        assert!(opts.is_empty());
    }

    #[test]
    fn test_duplicate_options() {
        let opts = FindOptions::with(&[
            FindOption::AllowUntrusted,
            FindOption::AllowUntrusted,
        ]);
        assert_eq!(opts.len(), 1);
    }
}
