//! Warnings generated during stack unwind analysis.
//!
//! Ported from Ghidra's `StackUnwindWarning` and `StackUnwindWarningSet`.

use serde::{Deserialize, Serialize};

/// The kind of unwind warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnwindWarningKind {
    /// No return path could be found from the given address.
    NoReturnPath,
    /// The return path is opaque / cannot be fully analyzed.
    OpaqueReturnPath,
    /// A custom/warning from analysis.
    Custom,
    /// The unwind was cancelled.
    Cancelled,
    /// Analysis encountered an error but continued.
    AnalysisError,
}

/// A single warning from stack unwind analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindWarning {
    /// The kind of warning.
    pub kind: UnwindWarningKind,
    /// Human-readable message.
    pub message: String,
}

impl UnwindWarning {
    /// Create a custom warning.
    pub fn custom(message: impl Into<String>) -> Self {
        Self {
            kind: UnwindWarningKind::Custom,
            message: message.into(),
        }
    }

    /// Create a cancellation warning.
    pub fn cancelled(frame_level: u32) -> Self {
        Self {
            kind: UnwindWarningKind::Cancelled,
            message: format!("Unwind cancelled for frame {}", frame_level),
        }
    }
}

/// A set of warnings collected during unwind analysis.
///
/// De-duplicates warnings by kind+message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnwindWarningSet {
    warnings: Vec<UnwindWarning>,
}

impl UnwindWarningSet {
    /// Create an empty warning set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a warning (de-duplicates).
    pub fn add(&mut self, warning: UnwindWarning) {
        if !self.warnings.iter().any(|w| w.kind == warning.kind && w.message == warning.message) {
            self.warnings.push(warning);
        }
    }

    /// Add all warnings from another set.
    pub fn extend(&mut self, other: &UnwindWarningSet) {
        for w in &other.warnings {
            self.add(w.clone());
        }
    }

    /// Whether there are any warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// The number of warnings.
    pub fn len(&self) -> usize {
        self.warnings.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.warnings.is_empty()
    }

    /// Iterate over warnings.
    pub fn iter(&self) -> impl Iterator<Item = &UnwindWarning> {
        self.warnings.iter()
    }

    /// Check if a warning with the given kind exists.
    pub fn has_kind(&self, kind: UnwindWarningKind) -> bool {
        self.warnings.iter().any(|w| w.kind == kind)
    }
}

impl IntoIterator for UnwindWarningSet {
    type Item = UnwindWarning;
    type IntoIter = std::vec::IntoIter<UnwindWarning>;

    fn into_iter(self) -> Self::IntoIter {
        self.warnings.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warning_set_dedup() {
        let mut set = UnwindWarningSet::new();
        set.add(UnwindWarning::custom("test"));
        set.add(UnwindWarning::custom("test"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_warning_set_different_messages() {
        let mut set = UnwindWarningSet::new();
        set.add(UnwindWarning::custom("msg1"));
        set.add(UnwindWarning::custom("msg2"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_warning_set_extend() {
        let mut set1 = UnwindWarningSet::new();
        set1.add(UnwindWarning::custom("a"));

        let mut set2 = UnwindWarningSet::new();
        set2.add(UnwindWarning::custom("b"));
        set2.add(UnwindWarning::custom("a")); // duplicate

        set1.extend(&set2);
        assert_eq!(set1.len(), 2);
    }

    #[test]
    fn test_cancelled_warning() {
        let w = UnwindWarning::cancelled(3);
        assert_eq!(w.kind, UnwindWarningKind::Cancelled);
        assert!(w.message.contains("3"));
    }

    #[test]
    fn test_has_kind() {
        let mut set = UnwindWarningSet::new();
        assert!(!set.has_kind(UnwindWarningKind::NoReturnPath));
        set.add(UnwindWarning {
            kind: UnwindWarningKind::NoReturnPath,
            message: "test".into(),
        });
        assert!(set.has_kind(UnwindWarningKind::NoReturnPath));
    }

    #[test]
    fn test_into_iter() {
        let mut set = UnwindWarningSet::new();
        set.add(UnwindWarning::custom("a"));
        set.add(UnwindWarning::custom("b"));
        let names: Vec<_> = set.into_iter().map(|w| w.message).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_serde() {
        let mut set = UnwindWarningSet::new();
        set.add(UnwindWarning::custom("test"));
        let json = serde_json::to_string(&set).unwrap();
        let back: UnwindWarningSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
