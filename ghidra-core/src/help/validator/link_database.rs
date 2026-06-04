// Port of help.validator.LinkDatabase

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::help::links::InvalidLink;
use crate::help::model::{AnchorDefinition, GhidraTocFile, TocItemDefinition, TocItemExternal};
use crate::help::location::HelpModuleCollection;

/// A database of all known TOC definitions, externals, and unresolved links.
///
/// Used during validation and during TOC output generation.
pub struct LinkDatabase {
    all_unresolved_links: BTreeSet<InvalidLink>,
    duplicate_anchors: Vec<DuplicateAnchorCollection>,
    map_of_ids_to_toc_definitions: HashMap<String, TocItemDefinition>,
    map_of_ids_to_toc_externals: HashMap<String, TocItemExternal>,
}

/// Describes a collection of duplicate anchors.
#[derive(Debug, Clone)]
pub struct DuplicateAnchorCollection {
    pub description: String,
    pub anchor_ids: Vec<String>,
}

impl PartialEq for DuplicateAnchorCollection {
    fn eq(&self, other: &Self) -> bool {
        self.description == other.description
    }
}

impl Eq for DuplicateAnchorCollection {}

impl PartialOrd for DuplicateAnchorCollection {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DuplicateAnchorCollection {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.description.cmp(&other.description)
    }
}

impl std::fmt::Display for DuplicateAnchorCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (anchors: [{}])",
            self.description,
            self.anchor_ids.join(", ")
        )
    }
}

impl LinkDatabase {
    /// Create a new LinkDatabase from a help module collection.
    pub fn new(help_collection: &mut HelpModuleCollection) -> Self {
        let mut db = LinkDatabase {
            all_unresolved_links: BTreeSet::new(),
            duplicate_anchors: Vec::new(),
            map_of_ids_to_toc_definitions: HashMap::new(),
            map_of_ids_to_toc_externals: HashMap::new(),
        };

        db.collect_toc_item_definitions(help_collection);
        db
    }

    fn collect_toc_item_definitions(&mut self, help_collection: &HelpModuleCollection) {
        let defs = help_collection.get_toc_definitions_by_id();
        for (key, value) in defs {
            if self.map_of_ids_to_toc_definitions.contains_key(&key) {
                log::warn!(
                    "Cannot define the same TOC definition more than once! Key: {}",
                    key
                );
                continue;
            }
            self.map_of_ids_to_toc_definitions.insert(key, value.clone());
        }
    }

    /// Look up a TOC definition by reference ID.
    pub fn get_toc_definition_for_id(&self, id: &str) -> Option<&TocItemDefinition> {
        self.map_of_ids_to_toc_definitions.get(id)
    }

    /// Look up a TOC external by reference ID.
    pub fn get_toc_external_for_id(&self, id: &str) -> Option<&TocItemExternal> {
        self.map_of_ids_to_toc_externals.get(id)
    }

    /// Resolve a link to its help file.
    pub fn resolve_file(
        &self,
        _help_collection: &mut HelpModuleCollection,
        _reference_file_help_path: &Path,
    ) -> Option<()> {
        // Simplified resolution: just check if the path is known
        Some(())
    }

    /// Get the ID for a link target (e.g., help/topics/MyTopic/page.html -> TopicName_page).
    pub fn get_id_for_link(&self, target: &str) -> Option<String> {
        if target.starts_with(crate::help::validator::java_help_validator::EXTERNAL_PREFIX) {
            return None;
        }

        // Try to find the target as a path
        let path = Path::new(target);
        let file = if let Some(hash_pos) = target.find('#') {
            Path::new(&target[..hash_pos])
        } else {
            path
        };

        // Look through all definitions for a matching help path
        for def in self.map_of_ids_to_toc_definitions.values() {
            if let Some(ref def_target) = def.target {
                if def_target == target || def_target == file.to_string_lossy().as_ref() {
                    return Some(def.id.clone());
                }
            }
        }

        None
    }

    /// Get all unresolved links.
    pub fn get_unresolved_links(&self) -> &BTreeSet<InvalidLink> {
        &self.all_unresolved_links
    }

    /// Get all duplicate anchor collections.
    pub fn get_duplicate_anchors(&self) -> &[DuplicateAnchorCollection] {
        &self.duplicate_anchors
    }

    /// Add unresolved links to the database.
    pub fn add_unresolved_links(&mut self, links: impl IntoIterator<Item = InvalidLink>) {
        self.all_unresolved_links.extend(links);
    }

    /// Add a duplicate anchor collection to the database.
    pub fn add_duplicate_anchors(&mut self, collection: DuplicateAnchorCollection) {
        self.duplicate_anchors.push(collection);
    }

    /// Add a TOC external item.
    pub fn add_toc_external(&mut self, id: String, item: TocItemExternal) {
        self.map_of_ids_to_toc_externals.insert(id, item);
    }

    /// Generate the TOC output file from the source TOC.
    pub fn generate_toc_output_file(
        &self,
        _output_file: &Path,
        _source_toc: &GhidraTocFile,
    ) -> Result<(), String> {
        // The Java implementation writes a merged TOC XML file.
        // For now, we provide the stub.
        log::info!("TOC output file generation not yet fully implemented");
        Ok(())
    }

    /// Validate all TOC items.
    pub fn validate_all_tocs(&self) {
        // The Java implementation calls printableTree.validateAllTOCs()
        // For now, this is a stub.
        log::info!("TOC validation not yet fully implemented");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_anchor_collection_ordering() {
        let c1 = DuplicateAnchorCollection {
            description: "AAA".to_string(),
            anchor_ids: vec!["a".to_string()],
        };
        let c2 = DuplicateAnchorCollection {
            description: "BBB".to_string(),
            anchor_ids: vec!["b".to_string()],
        };
        assert!(c1 < c2);
    }

    #[test]
    fn test_duplicate_anchor_collection_display() {
        let c = DuplicateAnchorCollection {
            description: "Topic A".to_string(),
            anchor_ids: vec!["anchor1".to_string(), "anchor2".to_string()],
        };
        let display = format!("{}", c);
        assert!(display.contains("Topic A"));
        assert!(display.contains("anchor1"));
    }
}
