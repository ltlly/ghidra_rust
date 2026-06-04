//! Top-level merge manager -- orchestrates the entire merge process.
//!
//! Port of Ghidra's `MergeManager` (headless, no GUI).

use super::constants::MergeVersion;
use super::error::{MergeError, MergeResult};
use super::listing::ListingMergeManager;
use super::resolver::{MergePhase, MergeResolver};

use std::collections::HashMap;

/// State of the overall merge process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeState {
    /// Merge has not started yet.
    NotStarted,
    /// Merge is currently running.
    Running,
    /// Merge completed successfully.
    Completed,
    /// Merge was canceled.
    Canceled,
    /// Merge failed with an error.
    Failed,
}

impl Default for MergeState {
    fn default() -> Self {
        Self::NotStarted
    }
}

/// Top-level merge manager that orchestrates each step of the merge/resolve
/// conflicts process.
///
/// This is the headless (no-GUI) Rust port of Ghidra's `MergeManager`.
/// It manages the four program copies (Result, Latest, My, Original) and
/// drives each [`MergeResolver`] through its phases.
///
/// # Usage
///
/// ```ignore
/// use ghidra_features::base::merge::manager::MergeManager;
///
/// let mut manager = MergeManager::new(result, my, original, latest);
/// manager.add_resolver(Box::new(my_resolver));
/// let success = manager.run().unwrap();
/// ```
pub struct MergeManager {
    /// The resolvers that handle individual merge phases.
    resolvers: Vec<Box<dyn MergeResolver>>,

    /// Index of the currently executing resolver.
    current_index: usize,

    /// Overall merge state.
    state: MergeState,

    /// Whether the merge was successful.
    merge_status: bool,

    /// Map for passing resolve information between merge managers.
    /// Keys are standardized strings from `MergeConstants`.
    resolve_map: HashMap<String, ResolveInfo>,

    /// All collected phases from all resolvers.
    all_phases: Vec<MergePhase>,

    /// Listing merge manager (convenience accessor).
    listing_merge_manager: Option<ListingMergeManager>,
}

/// An opaque container for resolve information passed between merge managers.
///
/// Different merge managers use this to share information (e.g., the data type
/// merger tells the listing merger which data types were resolved).
#[derive(Debug, Clone)]
pub enum ResolveInfo {
    /// A set of resolved data type names.
    DataTypeSet(Vec<String>),
    /// A set of resolved code unit addresses.
    AddressSet(Vec<String>),
    /// A set of resolved symbol names.
    SymbolSet(Vec<String>),
    /// Arbitrary string value.
    String(String),
    /// Integer value.
    Int(i64),
    /// Boolean flag.
    Bool(bool),
}

impl MergeManager {
    /// Create a new merge manager.
    pub fn new() -> Self {
        Self {
            resolvers: Vec::new(),
            current_index: 0,
            state: MergeState::NotStarted,
            merge_status: true,
            resolve_map: HashMap::new(),
            all_phases: Vec::new(),
            listing_merge_manager: None,
        }
    }

    /// Register a merge resolver.
    ///
    /// Resolvers are executed in the order they are added.
    pub fn add_resolver(&mut self, resolver: Box<dyn MergeResolver>) {
        let phases = resolver.phases();
        self.all_phases.extend(phases);
        self.resolvers.push(resolver);
    }

    /// Set the listing merge manager for convenience access.
    pub fn set_listing_merge_manager(&mut self, mgr: ListingMergeManager) {
        self.listing_merge_manager = Some(mgr);
    }

    /// Get a reference to the listing merge manager.
    pub fn listing_merge_manager(&self) -> Option<&ListingMergeManager> {
        self.listing_merge_manager.as_ref()
    }

    /// Get a mutable reference to the listing merge manager.
    pub fn listing_merge_manager_mut(&mut self) -> Option<&mut ListingMergeManager> {
        self.listing_merge_manager.as_mut()
    }

    /// Run the entire merge process.
    ///
    /// Returns `true` if the merge completed successfully, `false` otherwise.
    pub fn run(&mut self) -> MergeResult<bool> {
        self.state = MergeState::Running;
        self.merge_status = true;
        self.current_index = 0;

        while self.current_index < self.resolvers.len() {
            let resolver = &mut self.resolvers[self.current_index];
            match resolver.merge() {
                Ok(()) => {
                    self.current_index += 1;
                }
                Err(MergeError::Canceled) => {
                    self.state = MergeState::Canceled;
                    return Ok(false);
                }
                Err(e) => {
                    self.state = MergeState::Failed;
                    self.merge_status = false;
                    return Err(e);
                }
            }
        }

        self.state = MergeState::Completed;
        Ok(self.merge_status)
    }

    /// Cancel the merge process.
    pub fn cancel(&mut self) {
        self.state = MergeState::Canceled;
        if self.current_index < self.resolvers.len() {
            self.resolvers[self.current_index].cancel();
        }
    }

    /// Get the current merge state.
    pub fn state(&self) -> MergeState {
        self.state
    }

    /// Get the domain object for a given version.
    ///
    /// In this headless implementation, this returns the version name as a
    /// placeholder. A full implementation would return the actual domain object.
    pub fn get_version_name(&self, version: MergeVersion) -> &str {
        version.title()
    }

    /// Set resolve information for inter-manager communication.
    pub fn set_resolve_information(&mut self, info_type: impl Into<String>, info: ResolveInfo) {
        self.resolve_map.insert(info_type.into(), info);
    }

    /// Get resolve information by key.
    pub fn get_resolve_information(&self, info_type: &str) -> Option<&ResolveInfo> {
        self.resolve_map.get(info_type)
    }

    /// Find a merge resolver by name.
    pub fn get_resolver_by_name(&self, name: &str) -> Option<&dyn MergeResolver> {
        self.resolvers
            .iter()
            .find(|r| r.name() == name)
            .map(|r| r.as_ref())
    }

    /// Get all phases from all registered resolvers.
    pub fn all_phases(&self) -> &[MergePhase] {
        &self.all_phases
    }

    /// Get the number of registered resolvers.
    pub fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }

    /// Get the index of the currently executing resolver.
    pub fn current_resolver_index(&self) -> usize {
        self.current_index
    }
}

impl Default for MergeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::merge::error::MergeResult;
    use crate::base::merge::resolver::{MergePhase, MergeResolver};

    struct DummyResolver {
        name: String,
        called: bool,
        should_fail: bool,
    }

    impl DummyResolver {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                called: false,
                should_fail: false,
            }
        }

        fn with_failure(name: &str) -> Self {
            Self {
                name: name.to_string(),
                called: false,
                should_fail: true,
            }
        }
    }

    impl MergeResolver for DummyResolver {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "A dummy resolver"
        }

        fn merge(&mut self) -> MergeResult<()> {
            self.called = true;
            if self.should_fail {
                Err(MergeError::Other {
                    message: "deliberate failure".to_string(),
                })
            } else {
                Ok(())
            }
        }

        fn phases(&self) -> Vec<MergePhase> {
            vec![MergePhase::simple(&self.name)]
        }
    }

    #[test]
    fn test_merge_manager_run_empty() {
        let mut mgr = MergeManager::new();
        let result = mgr.run().unwrap();
        assert!(result);
        assert_eq!(mgr.state(), MergeState::Completed);
    }

    #[test]
    fn test_merge_manager_run_single_resolver() {
        let mut mgr = MergeManager::new();
        mgr.add_resolver(Box::new(DummyResolver::new("Phase1")));
        let result = mgr.run().unwrap();
        assert!(result);
        assert_eq!(mgr.state(), MergeState::Completed);
    }

    #[test]
    fn test_merge_manager_run_multiple_resolvers() {
        let mut mgr = MergeManager::new();
        mgr.add_resolver(Box::new(DummyResolver::new("Phase1")));
        mgr.add_resolver(Box::new(DummyResolver::new("Phase2")));
        mgr.add_resolver(Box::new(DummyResolver::new("Phase3")));
        let result = mgr.run().unwrap();
        assert!(result);
        assert_eq!(mgr.resolver_count(), 3);
    }

    #[test]
    fn test_merge_manager_run_failure() {
        let mut mgr = MergeManager::new();
        mgr.add_resolver(Box::new(DummyResolver::new("Phase1")));
        mgr.add_resolver(Box::new(DummyResolver::with_failure("Phase2")));
        let result = mgr.run();
        assert!(result.is_err());
        assert_eq!(mgr.state(), MergeState::Failed);
    }

    #[test]
    fn test_merge_manager_cancel() {
        let mut mgr = MergeManager::new();
        mgr.add_resolver(Box::new(DummyResolver::new("Phase1")));
        mgr.cancel();
        assert_eq!(mgr.state(), MergeState::Canceled);
    }

    #[test]
    fn test_merge_manager_resolve_information() {
        let mut mgr = MergeManager::new();
        mgr.set_resolve_information(
            "ResolvedLatestDataTypes",
            ResolveInfo::DataTypeSet(vec!["int".to_string(), "float".to_string()]),
        );
        let info = mgr.get_resolve_information("ResolvedLatestDataTypes");
        assert!(info.is_some());
        match info.unwrap() {
            ResolveInfo::DataTypeSet(types) => assert_eq!(types.len(), 2),
            _ => panic!("Expected DataTypeSet"),
        }
    }

    #[test]
    fn test_merge_manager_get_resolver_by_name() {
        let mut mgr = MergeManager::new();
        mgr.add_resolver(Box::new(DummyResolver::new("Alpha")));
        mgr.add_resolver(Box::new(DummyResolver::new("Beta")));
        assert!(mgr.get_resolver_by_name("Alpha").is_some());
        assert!(mgr.get_resolver_by_name("Beta").is_some());
        assert!(mgr.get_resolver_by_name("Gamma").is_none());
    }

    #[test]
    fn test_merge_manager_version_names() {
        let mgr = MergeManager::new();
        assert_eq!(mgr.get_version_name(MergeVersion::Result), "Result");
        assert_eq!(mgr.get_version_name(MergeVersion::Latest), "Latest");
        assert_eq!(mgr.get_version_name(MergeVersion::My), "Checked Out");
        assert_eq!(mgr.get_version_name(MergeVersion::Original), "Original");
    }

    #[test]
    fn test_merge_manager_all_phases() {
        let mut mgr = MergeManager::new();
        mgr.add_resolver(Box::new(DummyResolver::new("A")));
        mgr.add_resolver(Box::new(DummyResolver::new("B")));
        assert_eq!(mgr.all_phases().len(), 2);
    }

    #[test]
    fn test_merge_manager_listing_integration() {
        let mut mgr = MergeManager::new();
        let listing_mgr = ListingMergeManager::new();
        mgr.set_listing_merge_manager(listing_mgr);
        assert!(mgr.listing_merge_manager().is_some());
    }
}
