//! Merge resolver trait -- individual merge phase handlers.
//!
//! Port of Ghidra's `MergeResolver` interface.

use super::error::MergeResult;

/// A conflict resolution strategy that a user can choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Keep the latest version.
    KeepLatest,
    /// Keep the user's (my) version.
    KeepMy,
    /// Keep the original (ancestor) version.
    KeepOriginal,
    /// Keep the existing result version.
    KeepResult,
    /// Keep both latest and my versions (where applicable).
    KeepBoth,
    /// Remove the item.
    Remove,
    /// The user needs to be prompted (default state).
    AskUser,
}

impl Default for ConflictResolution {
    fn default() -> Self {
        Self::AskUser
    }
}

/// A merge phase descriptor.
///
/// Each phase has a hierarchical path (e.g., `["Listing", "Comments"]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergePhase {
    /// Hierarchical path of phase names, from outermost to innermost.
    pub path: Vec<String>,
    /// Current status of this phase.
    pub status: PhaseStatus,
}

/// Status of a merge phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseStatus {
    /// The phase has not started yet.
    Pending,
    /// The phase is currently being processed.
    InProgress,
    /// The phase completed successfully.
    Completed,
    /// The phase was skipped (e.g., no conflicts).
    Skipped,
}

impl Default for PhaseStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl MergePhase {
    /// Create a simple single-level phase.
    pub fn simple(name: impl Into<String>) -> Self {
        Self {
            path: vec![name.into()],
            status: PhaseStatus::Pending,
        }
    }

    /// Create a nested phase (e.g., "Listing" > "Comments").
    pub fn nested(parent: impl Into<String>, child: impl Into<String>) -> Self {
        Self {
            path: vec![parent.into(), child.into()],
            status: PhaseStatus::Pending,
        }
    }
}

/// Interface for resolving domain object merge conflicts.
///
/// Each [`MergeResolver`] handles one logical phase of the merge process
/// (e.g., data types, comments, symbols). The [`MergeManager`] calls each
/// resolver's methods in order.
///
/// Port of Ghidra's `MergeResolver` interface.
pub trait MergeResolver: Send {
    /// Get the human-readable name of this resolver.
    fn name(&self) -> &str;

    /// Get a description of what this resolver does.
    fn description(&self) -> &str;

    /// Notification that the "apply" button was hit.
    fn apply(&mut self) {}

    /// Notification that the merge process was canceled.
    fn cancel(&mut self) {}

    /// Perform the merge process.
    ///
    /// Implementations should auto-merge non-conflicting changes and
    /// record conflicts for later interactive resolution.
    fn merge(&mut self) -> MergeResult<()>;

    /// Return the phase descriptors for progress tracking.
    ///
    /// If the merge has no sub-phases, return a single-element vector.
    /// For nested phases, return multiple elements with hierarchical paths.
    fn phases(&self) -> Vec<MergePhase>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestResolver {
        applied: bool,
        canceled: bool,
    }

    impl TestResolver {
        fn new() -> Self {
            Self {
                applied: false,
                canceled: false,
            }
        }
    }

    impl MergeResolver for TestResolver {
        fn name(&self) -> &str {
            "Test Resolver"
        }

        fn description(&self) -> &str {
            "A test merge resolver"
        }

        fn apply(&mut self) {
            self.applied = true;
        }

        fn cancel(&mut self) {
            self.canceled = true;
        }

        fn merge(&mut self) -> MergeResult<()> {
            Ok(())
        }

        fn phases(&self) -> Vec<MergePhase> {
            vec![MergePhase::simple("Test Phase")]
        }
    }

    #[test]
    fn test_resolver_trait() {
        let mut resolver = TestResolver::new();
        assert_eq!(resolver.name(), "Test Resolver");
        assert_eq!(resolver.description(), "A test merge resolver");

        let phases = resolver.phases();
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0].path, vec!["Test Phase"]);
        assert_eq!(phases[0].status, PhaseStatus::Pending);

        resolver.apply();
        assert!(resolver.applied);

        resolver.cancel();
        assert!(resolver.canceled);
    }

    #[test]
    fn test_merge_phase_nested() {
        let phase = MergePhase::nested("Listing", "Comments");
        assert_eq!(phase.path, vec!["Listing", "Comments"]);
    }

    #[test]
    fn test_conflict_resolution_default() {
        let res = ConflictResolution::default();
        assert_eq!(res, ConflictResolution::AskUser);
    }
}
