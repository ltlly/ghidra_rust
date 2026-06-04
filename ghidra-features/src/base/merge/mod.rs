//! Program merge and conflict resolution.
//!
//! Ports Ghidra's merge infrastructure from:
//!
//! - `ghidra.app.merge` (top-level merge management, constants, resolver)
//! - `ghidra.app.merge.listing` (listing merge: comments, symbols, code units)
//! - `ghidra.app.merge.util` (conflict display utilities)
//! - `ghidra.program.database.data.merge` (data type merging: enum, structure, union)
//!
//! # Architecture
//!
//! The merge system implements a three-way merge algorithm with interactive
//! conflict resolution. Four program copies participate:
//!
//! - **Result**: The target where merged changes are written.
//! - **Latest**: The latest version from version control.
//! - **My**: The user's checked-out (working) version.
//! - **Original**: The common ancestor.
//!
//! # Key Types
//!
//! - [`MergeManager`]: Top-level orchestrator that drives all merge phases.
//! - [`MergeResolver`]: Trait for individual merge phase handlers.
//! - [`MergeVersion`]: Enum identifying the four program copies.
//! - [`CommentMerger`]: Merges five kinds of comments across versions.
//! - [`ListingMergeManager`]: Orchestrates all listing merge sub-phases.
//! - [`EnumMerger`], [`StructureMerger`], [`UnionMerger`]: Data type mergers.
//!
//! # Usage
//!
//! ```ignore
//! use ghidra_features::base::merge::{
//!     manager::MergeManager,
//!     listing::{ListingMergeManager, CommentType},
//!     resolver::ConflictResolution,
//! };
//!
//! let mut manager = MergeManager::new();
//! let mut listing_mgr = ListingMergeManager::new();
//!
//! // Feed comment pairs for merging.
//! listing_mgr.comment_merger_mut().add_comment_pair(
//!     "0x401000",
//!     CommentType::Eol,
//!     Some("latest text".to_string()),
//!     Some("my text".to_string()),
//!     None,
//! );
//!
//! manager.set_listing_merge_manager(listing_mgr);
//! manager.add_resolver(Box::new(/* your resolver */));
//! let success = manager.run().unwrap();
//! ```

pub mod constants;
pub mod datatypes;
pub mod error;
pub mod listing;
pub mod manager;
pub mod resolver;
pub mod util;

// Re-export key types for convenience.
pub use constants::MergeVersion;
pub use datatypes::{EnumMerger, MergeDataTypeComponent, MergedDataType, StructureMerger, UnionMerger};
pub use error::{DataTypeMergeError, MergeError, MergeResult};
pub use listing::{CommentMerger, CommentType, ListingConflict, ListingElementType, ListingMergeManager};
pub use manager::{MergeManager, MergeState, ResolveInfo};
pub use resolver::{ConflictResolution, MergePhase, MergeResolver, PhaseStatus};

// Re-export utility functions.
pub use util::{
    color_string, color_string_int, get_address_conflict_count, get_address_string,
    get_conflict_count, get_conflict_count_with_address, get_conflict_count_with_range,
    get_emphasize_string, get_hash_string, get_number_string, get_offset_string,
    get_truncated_html_string, get_truncated_html_string_default, html_spaces,
    replace_newlines, wrap_as_html, adjust_address_sets,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::merge::datatypes::{DataTypeMerger, EnumEntry};

    // ========================================================================
    // Integration tests: end-to-end merge workflows
    // ========================================================================

    #[test]
    fn test_full_enum_merge_workflow() {
        // Simulate a three-way merge of an enum.
        let working = MergedDataType {
            name: "Status".to_string(),
            category_path: "/".to_string(),
            description: Some("Status codes".to_string()),
            components: vec![],
            enum_entries: vec![
                EnumEntry::new("OK", 0, None),
                EnumEntry::new("ERROR", 1, Some("general error".to_string())),
                EnumEntry::new("TIMEOUT", 2, None),
            ],
            size: 4,
            packing_enabled: false,
            warnings: vec![],
        };

        let other = MergedDataType {
            name: "Status".to_string(),
            category_path: "/".to_string(),
            description: Some("Status codes".to_string()),
            components: vec![],
            enum_entries: vec![
                EnumEntry::new("OK", 0, Some("success".to_string())),
                EnumEntry::new("ERROR", 1, Some("general error".to_string())),
                EnumEntry::new("NOT_FOUND", 3, Some("resource missing".to_string())),
            ],
            size: 4,
            packing_enabled: false,
            warnings: vec![],
        };

        let mut merger = EnumMerger::new(working, other);
        let result = merger.merge().unwrap();

        // Should have all four entries.
        assert_eq!(result.enum_entries.len(), 4);
        // OK should have the comment from `other`.
        let ok = result.enum_entries.iter().find(|e| e.name == "OK").unwrap();
        assert_eq!(ok.comment.as_deref(), Some("success"));
        // NOT_FOUND should be newly added.
        assert!(result
            .enum_entries
            .iter()
            .any(|e| e.name == "NOT_FOUND" && e.value == 3));
    }

    #[test]
    fn test_full_structure_merge_workflow() {
        let working = MergedDataType {
            name: "Point".to_string(),
            category_path: "/geometry".to_string(),
            description: None,
            components: vec![
                MergeDataTypeComponent::new(0, 0, 4, Some("x".to_string()), "int", None),
                MergeDataTypeComponent::new(1, 4, 4, Some("y".to_string()), "int", None),
            ],
            enum_entries: vec![],
            size: 8,
            packing_enabled: false,
            warnings: vec![],
        };

        let other = MergedDataType {
            name: "Point".to_string(),
            category_path: "/geometry".to_string(),
            description: Some("2D point".to_string()),
            components: vec![
                MergeDataTypeComponent::new(0, 0, 4, Some("x".to_string()), "int", None),
                MergeDataTypeComponent::new(1, 4, 4, Some("y".to_string()), "int", None),
            ],
            enum_entries: vec![],
            size: 8,
            packing_enabled: false,
            warnings: vec![],
        };

        let mut merger = StructureMerger::strict(working, other);
        let result = merger.merge().unwrap();

        assert_eq!(result.size, 8);
        assert_eq!(result.components.len(), 2);
        // Description should be adopted from `other`.
        assert_eq!(result.description.as_deref(), Some("2D point"));
    }

    #[test]
    fn test_full_union_merge_workflow() {
        let working = MergedDataType {
            name: "Value".to_string(),
            category_path: "/".to_string(),
            description: None,
            components: vec![
                MergeDataTypeComponent::new(0, 0, 4, Some("i".to_string()), "int", None),
                MergeDataTypeComponent::new(1, 0, 4, Some("f".to_string()), "float", None),
            ],
            enum_entries: vec![],
            size: 4,
            packing_enabled: false,
            warnings: vec![],
        };

        let other = MergedDataType {
            name: "Value".to_string(),
            category_path: "/".to_string(),
            description: None,
            components: vec![
                MergeDataTypeComponent::new(0, 0, 4, Some("i".to_string()), "int", Some("integer".to_string())),
                MergeDataTypeComponent::new(1, 0, 4, Some("ptr".to_string()), "pointer", None),
            ],
            enum_entries: vec![],
            size: 4,
            packing_enabled: false,
            warnings: vec![],
        };

        let mut merger = UnionMerger::new(working, other);
        let result = merger.merge().unwrap();

        // Should have: i (with comment joined), f (original), ptr (new).
        assert!(result.components.len() >= 3);
        let i_comp = result
            .components
            .iter()
            .find(|c| c.field_name.as_deref() == Some("i"))
            .unwrap();
        assert_eq!(i_comp.comment.as_deref(), Some("integer"));
    }

    #[test]
    fn test_full_comment_merge_workflow() {
        let mut merger = ListingMergeManager::new();

        // Auto-merge: only latest changed.
        merger.comment_merger_mut().add_comment_pair(
            "0x401000",
            CommentType::Pre,
            Some("auto merged from latest".to_string()),
            None,
            None,
        );

        // Conflict: both changed differently.
        merger.comment_merger_mut().add_comment_pair(
            "0x402000",
            CommentType::Eol,
            Some("latest version".to_string()),
            Some("my version".to_string()),
            Some("original version".to_string()),
        );

        // Auto-merge: both changed to same value.
        merger.comment_merger_mut().add_comment_pair(
            "0x403000",
            CommentType::Plate,
            Some("same text".to_string()),
            Some("same text".to_string()),
            None,
        );

        assert_eq!(merger.comment_merger().auto_merged().len(), 2);
        assert_eq!(merger.comment_conflict_count(), 1);

        // Resolve the conflict.
        merger
            .comment_merger_mut()
            .resolve_current(ConflictResolution::KeepMy);

        assert_eq!(merger.comment_conflict_count(), 0);
        assert_eq!(merger.comment_merger().auto_merged().len(), 3);
    }

    #[test]
    fn test_full_merge_manager_with_listing() {
        let mut mgr = MergeManager::new();
        let listing_mgr = ListingMergeManager::new();
        mgr.set_listing_merge_manager(listing_mgr);

        // The listing merge manager is accessible.
        assert!(mgr.listing_merge_manager().is_some());

        // Run with no resolvers (trivially succeeds).
        let result = mgr.run().unwrap();
        assert!(result);
    }

    #[test]
    fn test_merge_version_all_variants() {
        for v in [
            MergeVersion::Result,
            MergeVersion::Latest,
            MergeVersion::My,
            MergeVersion::Original,
        ] {
            let title = v.title();
            assert!(!title.is_empty());
            assert_eq!(format!("{}", v), title);
        }
    }

    #[test]
    fn test_resolve_info_types() {
        let mut mgr = MergeManager::new();

        mgr.set_resolve_information(
            constants::RESOLVED_LATEST_DTS,
            ResolveInfo::DataTypeSet(vec!["int".into()]),
        );
        mgr.set_resolve_information(
            constants::RESOLVED_CODE_UNITS,
            ResolveInfo::AddressSet(vec!["0x401000".into()]),
        );
        mgr.set_resolve_information(
            constants::RESOLVED_MY_SYMBOLS,
            ResolveInfo::SymbolSet(vec!["main".into()]),
        );
        mgr.set_resolve_information("custom", ResolveInfo::Bool(true));

        assert!(mgr
            .get_resolve_information(constants::RESOLVED_LATEST_DTS)
            .is_some());
        assert!(mgr
            .get_resolve_information(constants::RESOLVED_CODE_UNITS)
            .is_some());
        assert!(mgr
            .get_resolve_information(constants::RESOLVED_MY_SYMBOLS)
            .is_some());
        assert!(mgr.get_resolve_information("custom").is_some());
        assert!(mgr.get_resolve_information("nonexistent").is_none());
    }

    #[test]
    fn test_util_integration() {
        // Test that utilities are accessible through the re-exports.
        let colored = color_string("#FF0000", "test");
        assert!(colored.contains("test"));

        let count = get_conflict_count(3, 10);
        assert!(count.contains("Conflict #"));

        let html = wrap_as_html("content");
        assert!(html.contains("<html>"));
    }
}
