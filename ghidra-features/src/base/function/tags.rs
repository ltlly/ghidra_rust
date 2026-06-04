//! Function tags -- ported from `ghidra.app.plugin.core.function.tags`.
//!
//! Provides the function tag system for categorizing and annotating
//! functions with user-defined tags (e.g., "decompiled", "library",
//! "thunk", "dangerous").
//!
//! # Types ported
//!
//! | Rust struct            | Java class               |
//! |------------------------|--------------------------|
//! | `FunctionTag`          | `InMemoryFunctionTag`    |
//! | `FunctionTagManager`   | `FunctionTagLoader` + `FunctionTagPlugin` |
//! | `FunctionTagRowObject` | `FunctionTagRowObject`   |
//! | `FunctionTagTableModel`| `FunctionTagTableModel`  |

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// FunctionTag
// ---------------------------------------------------------------------------

/// A function tag.
///
/// Ported from `InMemoryFunctionTag.java`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::tags::*;
///
/// let tag = FunctionTag::new(1, "decompiled");
/// assert_eq!(tag.name(), "decompiled");
/// assert_eq!(tag.id(), 1);
/// assert!(!tag.is_auto_set());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionTag {
    /// The unique tag ID.
    id: u64,
    /// The tag name.
    name: String,
    /// Whether this tag is automatically set by analysis.
    auto_set: bool,
    /// An optional description.
    description: Option<String>,
}

impl FunctionTag {
    /// Creates a new function tag.
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            auto_set: false,
            description: None,
        }
    }

    /// Returns the tag ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the tag name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the tag is auto-set.
    pub fn is_auto_set(&self) -> bool {
        self.auto_set
    }

    /// Sets the auto-set flag.
    pub fn set_auto_set(&mut self, auto_set: bool) {
        self.auto_set = auto_set;
    }

    /// Returns the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Sets the description.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = Some(desc.into());
    }
}

impl fmt::Display for FunctionTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// FunctionTagRowObject
// ---------------------------------------------------------------------------

/// A row object for the function tag table.
///
/// Ported from `FunctionTagRowObject.java`.
#[derive(Debug, Clone)]
pub struct FunctionTagRowObject {
    /// The function address.
    function_address: u64,
    /// The function name.
    function_name: String,
    /// The tags applied to this function.
    tags: Vec<FunctionTag>,
}

impl FunctionTagRowObject {
    /// Creates a new row object.
    pub fn new(
        function_address: u64,
        function_name: impl Into<String>,
        tags: Vec<FunctionTag>,
    ) -> Self {
        Self {
            function_address,
            function_name: function_name.into(),
            tags,
        }
    }

    /// Returns the function address.
    pub fn function_address(&self) -> u64 {
        self.function_address
    }

    /// Returns the function name.
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Returns the tags.
    pub fn tags(&self) -> &[FunctionTag] {
        &self.tags
    }

    /// Returns the tag names as a comma-separated string.
    pub fn tag_names_display(&self) -> String {
        self.tags
            .iter()
            .map(|t| t.name().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Adds a tag.
    pub fn add_tag(&mut self, tag: FunctionTag) {
        if !self.tags.iter().any(|t| t.id() == tag.id()) {
            self.tags.push(tag);
        }
    }

    /// Removes a tag by ID.
    pub fn remove_tag(&mut self, tag_id: u64) -> bool {
        let len = self.tags.len();
        self.tags.retain(|t| t.id() != tag_id);
        self.tags.len() < len
    }

    /// Returns `true` if this function has the given tag.
    pub fn has_tag(&self, tag_id: u64) -> bool {
        self.tags.iter().any(|t| t.id() == tag_id)
    }
}

// ---------------------------------------------------------------------------
// FunctionTagTableModel
// ---------------------------------------------------------------------------

/// Column identifiers for the function tag table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionTagColumn {
    /// Function name.
    FunctionName,
    /// Function address.
    Address,
    /// Tags (comma-separated).
    Tags,
}

impl fmt::Display for FunctionTagColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FunctionName => write!(f, "Function"),
            Self::Address => write!(f, "Address"),
            Self::Tags => write!(f, "Tags"),
        }
    }
}

/// The function tag table model.
///
/// Ported from `FunctionTagTableModel.java`.
#[derive(Debug, Clone)]
pub struct FunctionTagTableModel {
    /// The rows.
    rows: Vec<FunctionTagRowObject>,
}

impl FunctionTagTableModel {
    /// Creates a new table model.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Adds a row.
    pub fn add_row(&mut self, row: FunctionTagRowObject) {
        self.rows.push(row);
    }

    /// Returns the rows.
    pub fn rows(&self) -> &[FunctionTagRowObject] {
        &self.rows
    }

    /// Returns the row count.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Gets a cell value by row and column index.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        match col {
            0 => Some(r.function_name().to_string()),
            1 => Some(format!("0x{:x}", r.function_address())),
            2 => Some(r.tag_names_display()),
            _ => None,
        }
    }

    /// Removes a row by index.
    pub fn remove_row(&mut self, index: usize) -> Option<FunctionTagRowObject> {
        if index < self.rows.len() {
            Some(self.rows.remove(index))
        } else {
            None
        }
    }

    /// Clears all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for FunctionTagTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionTagManager
// ---------------------------------------------------------------------------

/// Manages function tags for a program.
///
/// Ported from the combined functionality of `FunctionTagLoader` and
/// `FunctionTagPlugin`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::tags::*;
///
/// let mut mgr = FunctionTagManager::new();
/// let tag = mgr.create_tag("decompiled");
/// assert_eq!(mgr.tag_count(), 1);
///
/// mgr.add_tag_to_function(0x401000, tag);
/// let tags = mgr.tags_for_function(0x401000);
/// assert_eq!(tags.len(), 1);
/// ```
#[derive(Debug)]
pub struct FunctionTagManager {
    /// All known tags.
    tags: HashMap<u64, FunctionTag>,
    /// Mapping from function address to tag IDs.
    function_tags: HashMap<u64, Vec<u64>>,
    /// Next tag ID.
    next_id: u64,
}

impl FunctionTagManager {
    /// Creates a new function tag manager.
    pub fn new() -> Self {
        Self {
            tags: HashMap::new(),
            function_tags: HashMap::new(),
            next_id: 1,
        }
    }

    /// Creates a new tag and returns its ID.
    pub fn create_tag(&mut self, name: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.tags.insert(id, FunctionTag::new(id, name));
        id
    }

    /// Returns a tag by ID.
    pub fn get_tag(&self, id: u64) -> Option<&FunctionTag> {
        self.tags.get(&id)
    }

    /// Returns a mutable reference to a tag by ID.
    pub fn get_tag_mut(&mut self, id: u64) -> Option<&mut FunctionTag> {
        self.tags.get_mut(&id)
    }

    /// Returns all tags.
    pub fn all_tags(&self) -> Vec<&FunctionTag> {
        self.tags.values().collect()
    }

    /// Returns the number of tags.
    pub fn tag_count(&self) -> usize {
        self.tags.len()
    }

    /// Deletes a tag by ID.
    pub fn delete_tag(&mut self, id: u64) -> bool {
        // Remove from all functions
        for tags in self.function_tags.values_mut() {
            tags.retain(|&t| t != id);
        }
        self.tags.remove(&id).is_some()
    }

    /// Adds a tag to a function.
    pub fn add_tag_to_function(&mut self, function_address: u64, tag_id: u64) {
        let tags = self.function_tags.entry(function_address).or_default();
        if !tags.contains(&tag_id) {
            tags.push(tag_id);
        }
    }

    /// Removes a tag from a function.
    pub fn remove_tag_from_function(&mut self, function_address: u64, tag_id: u64) -> bool {
        if let Some(tags) = self.function_tags.get_mut(&function_address) {
            let len = tags.len();
            tags.retain(|&t| t != tag_id);
            tags.len() < len
        } else {
            false
        }
    }

    /// Returns the tags for a function.
    pub fn tags_for_function(&self, function_address: u64) -> Vec<&FunctionTag> {
        self.function_tags
            .get(&function_address)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.tags.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the number of functions with tags.
    pub fn tagged_function_count(&self) -> usize {
        self.function_tags
            .values()
            .filter(|tags| !tags.is_empty())
            .count()
    }

    /// Clears all tag assignments (but keeps the tag definitions).
    pub fn clear_assignments(&mut self) {
        self.function_tags.clear();
    }

    /// Clears everything.
    pub fn clear(&mut self) {
        self.tags.clear();
        self.function_tags.clear();
        self.next_id = 1;
    }
}

impl Default for FunctionTagManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_tag() {
        let tag = FunctionTag::new(1, "decompiled");
        assert_eq!(tag.id(), 1);
        assert_eq!(tag.name(), "decompiled");
        assert!(!tag.is_auto_set());
        assert!(tag.description().is_none());
    }

    #[test]
    fn test_function_tag_display() {
        let tag = FunctionTag::new(1, "library");
        assert_eq!(tag.to_string(), "library");
    }

    #[test]
    fn test_function_tag_auto_set() {
        let mut tag = FunctionTag::new(1, "thunk");
        tag.set_auto_set(true);
        assert!(tag.is_auto_set());
    }

    #[test]
    fn test_row_object() {
        let tags = vec![FunctionTag::new(1, "a"), FunctionTag::new(2, "b")];
        let row = FunctionTagRowObject::new(0x401000, "main", tags);
        assert_eq!(row.function_address(), 0x401000);
        assert_eq!(row.function_name(), "main");
        assert_eq!(row.tags().len(), 2);
        assert_eq!(row.tag_names_display(), "a, b");
    }

    #[test]
    fn test_row_object_add_remove_tag() {
        let mut row = FunctionTagRowObject::new(0x401000, "main", vec![]);
        row.add_tag(FunctionTag::new(1, "tag1"));
        assert!(row.has_tag(1));
        assert!(!row.has_tag(2));

        row.remove_tag(1);
        assert!(!row.has_tag(1));
    }

    #[test]
    fn test_row_object_dedup() {
        let mut row = FunctionTagRowObject::new(0x401000, "main", vec![]);
        row.add_tag(FunctionTag::new(1, "tag1"));
        row.add_tag(FunctionTag::new(1, "tag1")); // duplicate
        assert_eq!(row.tags().len(), 1);
    }

    #[test]
    fn test_table_model() {
        let mut model = FunctionTagTableModel::new();
        assert_eq!(model.row_count(), 0);

        let row = FunctionTagRowObject::new(0x401000, "main", vec![]);
        model.add_row(row);
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_table_model_get_value() {
        let mut model = FunctionTagTableModel::new();
        model.add_row(FunctionTagRowObject::new(
            0x401000,
            "main",
            vec![FunctionTag::new(1, "tag1")],
        ));

        assert_eq!(model.get_value_at(0, 0), Some("main".into()));
        assert_eq!(model.get_value_at(0, 1), Some("0x401000".into()));
        assert_eq!(model.get_value_at(0, 2), Some("tag1".into()));
        assert_eq!(model.get_value_at(1, 0), None);
    }

    #[test]
    fn test_table_model_remove() {
        let mut model = FunctionTagTableModel::new();
        model.add_row(FunctionTagRowObject::new(0x401000, "a", vec![]));
        model.add_row(FunctionTagRowObject::new(0x401100, "b", vec![]));
        model.remove_row(0);
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_manager_create_tag() {
        let mut mgr = FunctionTagManager::new();
        let id = mgr.create_tag("decompiled");
        assert_eq!(mgr.tag_count(), 1);
        let tag = mgr.get_tag(id).unwrap();
        assert_eq!(tag.name(), "decompiled");
    }

    #[test]
    fn test_manager_add_tag_to_function() {
        let mut mgr = FunctionTagManager::new();
        let id = mgr.create_tag("library");
        mgr.add_tag_to_function(0x401000, id);

        let tags = mgr.tags_for_function(0x401000);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name(), "library");
    }

    #[test]
    fn test_manager_remove_tag_from_function() {
        let mut mgr = FunctionTagManager::new();
        let id = mgr.create_tag("tag1");
        mgr.add_tag_to_function(0x401000, id);
        assert!(mgr.remove_tag_from_function(0x401000, id));
        assert_eq!(mgr.tags_for_function(0x401000).len(), 0);
    }

    #[test]
    fn test_manager_delete_tag() {
        let mut mgr = FunctionTagManager::new();
        let id = mgr.create_tag("temp");
        mgr.add_tag_to_function(0x401000, id);

        mgr.delete_tag(id);
        assert_eq!(mgr.tag_count(), 0);
        assert_eq!(mgr.tags_for_function(0x401000).len(), 0);
    }

    #[test]
    fn test_manager_tagged_function_count() {
        let mut mgr = FunctionTagManager::new();
        let id1 = mgr.create_tag("a");
        let id2 = mgr.create_tag("b");
        mgr.add_tag_to_function(0x401000, id1);
        mgr.add_tag_to_function(0x401100, id2);
        assert_eq!(mgr.tagged_function_count(), 2);
    }

    #[test]
    fn test_manager_clear() {
        let mut mgr = FunctionTagManager::new();
        mgr.create_tag("a");
        mgr.add_tag_to_function(0x401000, 1);
        mgr.clear();
        assert_eq!(mgr.tag_count(), 0);
    }

    #[test]
    fn test_column_display() {
        assert_eq!(FunctionTagColumn::FunctionName.to_string(), "Function");
        assert_eq!(FunctionTagColumn::Tags.to_string(), "Tags");
    }
}
