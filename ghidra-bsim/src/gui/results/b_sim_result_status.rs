//! Enum of BSim results apply statuses.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.search.results.BSimResultStatus`.

/// Enum of BSim results apply statuses for when users attempt to apply
/// function names or signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BSimResultStatus {
    /// This result has not been applied.
    NotApplied,
    /// The name and namespace have been applied.
    NameApplied,
    /// The name, namespace and signature have been applied.
    SignatureApplied,
    /// The name already matches.
    Matches,
    /// This result has been applied, but no longer matches.
    AppliedNoLongerMatches,
    /// An error occurred while attempting to apply this result.
    Error,
    /// There is no longer a function at the result address.
    NoFunction,
    /// The result was not applied because it already matched.
    Ignored,
}

impl BSimResultStatus {
    /// Get a human-readable description of this status.
    pub fn description(&self) -> &'static str {
        match self {
            Self::NotApplied => "This result has not been applied.",
            Self::NameApplied => "The name and namespace have been applied.",
            Self::SignatureApplied => "The name, namespace and signature have been applied.",
            Self::Matches => "The name already matches.",
            Self::AppliedNoLongerMatches => {
                "This result has been applied, but no longer matches!"
            }
            Self::Error => "An error occurred while attempting to apply this result.",
            Self::NoFunction => "There is no longer a function at the result address!",
            Self::Ignored => "The result was not applied because it already matched.",
        }
    }

    /// Whether this status represents an applied state (name or signature).
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::NameApplied | Self::SignatureApplied)
    }

    /// Whether this status represents an error.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }

    /// Whether this status means the result was ignored.
    pub fn is_ignored(&self) -> bool {
        matches!(self, Self::Ignored)
    }
}

impl Default for BSimResultStatus {
    fn default() -> Self {
        Self::NotApplied
    }
}

impl std::fmt::Display for BSimResultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_not_applied() {
        assert_eq!(BSimResultStatus::default(), BSimResultStatus::NotApplied);
    }

    #[test]
    fn test_description_not_empty() {
        let statuses = [
            BSimResultStatus::NotApplied,
            BSimResultStatus::NameApplied,
            BSimResultStatus::SignatureApplied,
            BSimResultStatus::Matches,
            BSimResultStatus::AppliedNoLongerMatches,
            BSimResultStatus::Error,
            BSimResultStatus::NoFunction,
            BSimResultStatus::Ignored,
        ];
        for status in &statuses {
            assert!(!status.description().is_empty());
        }
    }

    #[test]
    fn test_is_applied() {
        assert!(!BSimResultStatus::NotApplied.is_applied());
        assert!(BSimResultStatus::NameApplied.is_applied());
        assert!(BSimResultStatus::SignatureApplied.is_applied());
        assert!(!BSimResultStatus::Error.is_applied());
    }

    #[test]
    fn test_is_error() {
        assert!(BSimResultStatus::Error.is_error());
        assert!(!BSimResultStatus::NotApplied.is_error());
    }

    #[test]
    fn test_is_ignored() {
        assert!(BSimResultStatus::Ignored.is_ignored());
        assert!(!BSimResultStatus::NotApplied.is_ignored());
    }

    #[test]
    fn test_display() {
        let s = format!("{}", BSimResultStatus::NameApplied);
        assert!(s.contains("name and namespace"));
    }
}
