//! Object model query and table model types for the debugger GUI.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.model` package.
//! Provides `ModelQuery` for querying trace objects via path filters,
//! and table/tree model row types for displaying object hierarchies.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::target::key_path::KeyPath;
use crate::target::path_matcher::{NoneFilter, PathFilter, PathMatcher};
use crate::target::path_pattern::PathPattern;

// ---------------------------------------------------------------------------
// ModelQuery
// ---------------------------------------------------------------------------

/// A query over trace objects, consisting of path filter patterns.
///
/// Ported from Ghidra's `ModelQuery`. Executes against a trace's object
/// manager to find matching objects within a given lifespan (snapshot span).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelQuery {
    filter: PathMatcher,
}

impl ModelQuery {
    /// An empty query that matches nothing.
    pub fn empty() -> Self {
        Self {
            filter: PathMatcher::new(Default::default()),
        }
    }

    /// Create a query from a path filter.
    pub fn new(filter: PathMatcher) -> Self {
        Self { filter }
    }

    /// Parse a query string into a ModelQuery.
    pub fn parse(query_string: &str) -> Self {
        let pattern = PathPattern::new(KeyPath::parse(query_string));
        let patterns = {
            let mut s = std::collections::HashSet::new();
            s.insert(pattern);
            s
        };
        Self {
            filter: PathMatcher::new(patterns),
        }
    }

    /// Create a query matching elements (indexed children) of a path.
    pub fn elements_of(path: &KeyPath) -> Self {
        let pattern = PathPattern::new(path.extend(""));
        let mut patterns = HashSet::new();
        patterns.insert(pattern);
        Self {
            filter: PathMatcher::new(patterns),
        }
    }

    /// Create a query matching attributes (named children) of a path.
    pub fn attributes_of(path: &KeyPath) -> Self {
        let pattern = PathPattern::new(path.extend(""));
        let mut patterns = HashSet::new();
        patterns.insert(pattern);
        Self {
            filter: PathMatcher::new(patterns),
        }
    }

    /// The underlying path filter.
    pub fn filter(&self) -> &PathMatcher {
        &self.filter
    }

    /// Render the query as a string.
    pub fn to_query_string(&self) -> String {
        self.filter
            .singleton_pattern()
            .map(|p| p.as_path().to_string())
            .unwrap_or_default()
    }

    /// Whether this query matches nothing.
    pub fn is_empty(&self) -> bool {
        self.filter.is_none()
    }

    /// Compute the schemas matching this query from a root schema.
    ///
    /// Returns the list of schema names that could match.
    pub fn compute_schema_names(&self) -> Vec<String> {
        self.filter
            .get_patterns()
            .iter()
            .map(|p| p.as_path().to_string())
            .collect()
    }

    /// Check whether this query includes a specific value path.
    ///
    /// Determines if the given path (with its last key being the value's
    /// entry key) matches any pattern in this query.
    pub fn includes_path(&self, path: &KeyPath) -> bool {
        for pattern in self.filter.get_patterns() {
            if pattern.matches(path) {
                return true;
            }
        }
        false
    }

    /// Check whether this query involves (traverses) a given path.
    ///
    /// A path is involved if it could be an ancestor (prefix) of some
    /// matching path, i.e., the query results might depend on this path.
    pub fn involves_path(&self, path: &KeyPath) -> bool {
        for pattern in self.filter.get_patterns() {
            // Every query involves the root
            if path.is_root() {
                return true;
            }
            // Check if path could be a prefix of the pattern (left-to-right)
            if pattern.successor_could_match(path, false) {
                return true;
            }
            // Also check if path is deeper than pattern but has it as ancestor
            if pattern.ancestor_matches(path, false) {
                return true;
            }
        }
        false
    }
}

impl std::fmt::Display for ModelQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<ModelQuery: {}>", self.filter)
    }
}

// ---------------------------------------------------------------------------
// Value display helper
// ---------------------------------------------------------------------------

/// Display helper for values in the model viewer.
///
/// Ported from Ghidra's `DisplaysObjectValues` and related display logic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueDisplay {
    /// Whether to show hidden values.
    pub show_hidden: bool,
    /// The maximum display length for string values.
    pub max_string_length: usize,
}

impl ValueDisplay {
    /// Create a new display with defaults.
    pub fn new() -> Self {
        Self {
            show_hidden: false,
            max_string_length: 256,
        }
    }

    /// Get the display for a primitive value.
    pub fn get_primitive_value_display(&self, value: &Option<ModelValue>) -> String {
        match value {
            None => String::new(),
            Some(v) => v.display_string(),
        }
    }

    /// Get the display for a model value entry.
    pub fn get_edge_display(&self, entry: &ModelValueEntry) -> String {
        entry.display()
    }

    /// Get HTML display for a model value entry.
    pub fn get_edge_html_display(&self, entry: &ModelValueEntry) -> String {
        format!("<html>{}</entry>", entry.display())
    }

    /// Get tooltip text for a model value entry.
    pub fn get_edge_tooltip(&self, entry: &ModelValueEntry) -> String {
        entry.display()
    }

    /// Get tooltip for a primitive edge.
    pub fn get_primitive_edge_tooltip(&self, entry: &ModelValueEntry) -> String {
        entry.display()
    }
}

// ---------------------------------------------------------------------------
// Model value types
// ---------------------------------------------------------------------------

/// A primitive or object value in the trace model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ModelValue {
    /// A boolean value.
    Bool(bool),
    /// A byte value.
    Byte(u8),
    /// A 16-bit integer.
    Short(i16),
    /// A 32-bit integer.
    Int(i32),
    /// A 64-bit integer.
    Long(i64),
    /// A 32-bit float.
    Float(f32),
    /// A 64-bit float.
    Double(f64),
    /// A string value.
    String(String),
    /// Raw bytes.
    Bytes(Vec<u8>),
    /// An object reference (by path).
    ObjectRef(KeyPath),
    /// A null value.
    Null,
}

impl ModelValue {
    /// Get a display string for this value.
    pub fn display_string(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Byte(b) => format!("0x{:02x}", b),
            Self::Short(s) => format!("0x{:04x}", s),
            Self::Int(i) => format!("0x{:08x}", i),
            Self::Long(l) => format!("0x{:016x}", l),
            Self::Float(f) => format!("{}", f),
            Self::Double(d) => format!("{}", d),
            Self::String(s) => s.clone(),
            Self::Bytes(bytes) => {
                bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
            }
            Self::ObjectRef(path) => path.to_string(),
            Self::Null => "null".to_string(),
        }
    }

    /// Whether this is a null value.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Whether this is an object reference.
    pub fn is_object(&self) -> bool {
        matches!(self, Self::ObjectRef(_))
    }
}

impl std::fmt::Display for ModelValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

// ---------------------------------------------------------------------------
// Model value entry
// ---------------------------------------------------------------------------

/// An entry (edge) in the trace object value graph.
///
/// Ported from Ghidra's `TraceObjectValue` as represented in the GUI model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelValueEntry {
    /// The entry key (name or index).
    pub key: String,
    /// The value.
    pub value: Option<ModelValue>,
    /// The lifespan during which this entry exists.
    pub lifespan: Lifespan,
    /// Whether this entry is canonical.
    pub canonical: bool,
    /// Whether this entry is hidden.
    pub hidden: bool,
    /// The parent path.
    pub parent_path: KeyPath,
}

impl ModelValueEntry {
    /// Create a new entry.
    pub fn new(
        key: impl Into<String>,
        value: Option<ModelValue>,
        lifespan: Lifespan,
        parent_path: KeyPath,
    ) -> Self {
        Self {
            key: key.into(),
            value,
            lifespan,
            canonical: false,
            hidden: false,
            parent_path,
        }
    }

    /// The full path to this entry.
    pub fn full_path(&self) -> KeyPath {
        self.parent_path.extend(&self.key)
    }

    /// Get the display string.
    pub fn display(&self) -> String {
        match &self.value {
            None => String::new(),
            Some(v) => v.display_string(),
        }
    }

    /// Whether this entry has an object value.
    pub fn is_object(&self) -> bool {
        self.value.as_ref().map_or(false, |v| v.is_object())
    }

    /// Whether this entry has a canonical object value.
    pub fn is_canonical(&self) -> bool {
        self.canonical
    }
}

// ---------------------------------------------------------------------------
// Value row types (table model)
// ---------------------------------------------------------------------------

/// A row in the object model table.
///
/// Ported from Ghidra's `ObjectTableModel.ValueRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectModelRow {
    /// The entry key.
    pub key: String,
    /// The display string.
    pub display: String,
    /// The HTML display.
    pub html_display: String,
    /// The tooltip text.
    pub tooltip: String,
    /// The lifespan.
    pub lifespan: Lifespan,
    /// Whether the value is modified.
    pub modified: bool,
    /// Whether the value is current.
    pub current: bool,
    /// The underlying value entry.
    pub entry: ModelValueEntry,
    /// Attribute values keyed by attribute name.
    pub attributes: std::collections::BTreeMap<String, AttributeValue>,
}

impl ObjectModelRow {
    /// Create a new row from a value entry.
    pub fn new(entry: ModelValueEntry) -> Self {
        let key = entry.key.clone();
        let display = entry.display();
        let html_display = format!("<html>{}</html>", display);
        let tooltip = display.clone();
        let lifespan = entry.lifespan;
        Self {
            key,
            display,
            html_display,
            tooltip,
            lifespan,
            modified: false,
            current: false,
            entry,
            attributes: std::collections::BTreeMap::new(),
        }
    }

    /// Get an attribute value by name.
    pub fn get_attribute(&self, name: &str) -> Option<&AttributeValue> {
        self.attributes.get(name)
    }

    /// Set an attribute value.
    pub fn set_attribute(&mut self, name: impl Into<String>, value: AttributeValue) {
        self.attributes.insert(name.into(), value);
    }
}

/// An attribute value for display in a column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeValue {
    /// The display string.
    pub display: String,
    /// The HTML display.
    pub html_display: String,
    /// The tooltip text.
    pub tooltip: String,
    /// Whether the value is modified.
    pub modified: bool,
}

impl AttributeValue {
    /// Create a new attribute value.
    pub fn new(display: impl Into<String>) -> Self {
        let display = display.into();
        let html_display = format!("<html>{}</html>", display);
        let tooltip = display.clone();
        Self {
            display,
            html_display,
            tooltip,
            modified: false,
        }
    }

    /// Mark as modified.
    pub fn with_modified(mut self, modified: bool) -> Self {
        self.modified = modified;
        self
    }
}

// ---------------------------------------------------------------------------
// Path table row
// ---------------------------------------------------------------------------

/// A row in the path-based table model.
///
/// Ported from Ghidra's `PathTableModel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathModelRow {
    /// The full path.
    pub path: KeyPath,
    /// The last key in the path.
    pub last_key: String,
    /// The value at this path.
    pub value: Option<ModelValue>,
    /// The lifespan.
    pub lifespan: Lifespan,
    /// The display string for the value.
    pub value_display: String,
}

impl PathModelRow {
    /// Create a new path row.
    pub fn new(path: KeyPath, value: Option<ModelValue>, lifespan: Lifespan) -> Self {
        let last_key = path.last().unwrap_or("").to_string();
        let value_display = value
            .as_ref()
            .map(|v| v.display_string())
            .unwrap_or_default();
        Self {
            path,
            last_key,
            value,
            lifespan,
            value_display,
        }
    }
}

// ---------------------------------------------------------------------------
// Keep tree state
// ---------------------------------------------------------------------------

/// Tracks expanded state for tree nodes.
///
/// Ported from Ghidra's `KeepTreeState`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TreeState {
    /// Set of expanded paths.
    expanded: HashSet<KeyPath>,
    /// The selected path, if any.
    selected: Option<KeyPath>,
}

impl TreeState {
    /// Create a new empty tree state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a path is expanded.
    pub fn is_expanded(&self, path: &KeyPath) -> bool {
        self.expanded.contains(path)
    }

    /// Expand a path.
    pub fn expand(&mut self, path: KeyPath) {
        self.expanded.insert(path);
    }

    /// Collapse a path.
    pub fn collapse(&mut self, path: &KeyPath) {
        self.expanded.remove(path);
    }

    /// Toggle expanded state.
    pub fn toggle(&mut self, path: KeyPath) {
        if self.expanded.contains(&path) {
            self.expanded.remove(&path);
        } else {
            self.expanded.insert(path);
        }
    }

    /// Get the selected path.
    pub fn selected(&self) -> Option<&KeyPath> {
        self.selected.as_ref()
    }

    /// Set the selected path.
    pub fn set_selected(&mut self, path: Option<KeyPath>) {
        self.selected = path;
    }

    /// Expand all paths from root to the given path.
    pub fn expand_to(&mut self, path: &KeyPath) {
        for i in 1..=path.size() {
            if let Some(parent) = path.parent_n(path.size() - i) {
                if !parent.is_root() {
                    self.expanded.insert(parent);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Display modification tracking
// ---------------------------------------------------------------------------

/// Tracks whether display properties have been modified.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisplaysModified {
    /// Whether the display has been modified.
    pub modified: bool,
    /// The diff color.
    pub diff_color: Option<[u8; 4]>,
    /// The diff selected color.
    pub diff_color_sel: Option<[u8; 4]>,
}

impl DisplaysModified {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the diff color.
    pub fn set_diff_color(&mut self, color: [u8; 4]) {
        self.diff_color = Some(color);
        self.modified = true;
    }

    /// Set the diff selected color.
    pub fn set_diff_color_sel(&mut self, color: [u8; 4]) {
        self.diff_color_sel = Some(color);
        self.modified = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_query_parse() {
        let query = ModelQuery::parse("Processes.[].Threads");
        assert!(!query.is_empty());
        assert_eq!(query.to_query_string(), "Processes.[].Threads");
    }

    #[test]
    fn test_model_query_empty() {
        let query = ModelQuery::empty();
        assert!(query.is_empty());
    }

    #[test]
    fn test_model_query_includes_path() {
        let query = ModelQuery::parse("Processes.[].Threads");
        assert!(query.includes_path(&KeyPath::of(&["Processes", "[5]", "Threads"])));
        assert!(!query.includes_path(&KeyPath::of(&["Processes"])));
        assert!(!query.includes_path(&KeyPath::of(&["Modules"])));
    }

    #[test]
    fn test_model_query_involves_path() {
        let query = ModelQuery::parse("Processes.[].Threads");
        // Root is always involved
        assert!(query.involves_path(&KeyPath::ROOT));
        // "Processes" is an ancestor of a match
        assert!(query.involves_path(&KeyPath::of(&["Processes"])));
        // "Processes.[5]" is an ancestor of "Processes.[5].Threads"
        assert!(query.involves_path(&KeyPath::of(&["Processes", "[5]"])));
        // "Modules" is not involved
        assert!(!query.involves_path(&KeyPath::of(&["Modules"])));
    }

    #[test]
    fn test_model_query_elements_of() {
        let path = KeyPath::of(&["Processes"]);
        let query = ModelQuery::elements_of(&path);
        assert!(!query.is_empty());
    }

    #[test]
    fn test_model_query_attributes_of() {
        let path = KeyPath::of(&["Processes", "[5]"]);
        let query = ModelQuery::attributes_of(&path);
        assert!(!query.is_empty());
    }

    #[test]
    fn test_model_query_compute_schema_names() {
        let query = ModelQuery::parse("Processes.[].Threads");
        let names = query.compute_schema_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "Processes.[].Threads");
    }

    #[test]
    fn test_model_value_display() {
        let v = ModelValue::Bool(true);
        assert_eq!(v.display_string(), "true");
        assert!(!v.is_null());
        assert!(!v.is_object());

        let v = ModelValue::Long(0xdeadbeef);
        assert_eq!(v.display_string(), "0x00000000deadbeef");

        let v = ModelValue::Bytes(vec![0xca, 0xfe]);
        assert_eq!(v.display_string(), "ca:fe");

        let v = ModelValue::Null;
        assert!(v.is_null());
        assert_eq!(v.display_string(), "null");

        let v = ModelValue::ObjectRef(KeyPath::of(&["Processes", "[5]"]));
        assert!(v.is_object());
    }

    #[test]
    fn test_model_value_entry() {
        let entry = ModelValueEntry::new(
            "name",
            Some(ModelValue::String("hello".into())),
            Lifespan::now_on(0),
            KeyPath::of(&["root"]),
        );
        assert_eq!(entry.display(), "hello");
        assert_eq!(entry.full_path(), KeyPath::of(&["root", "name"]));
        assert!(!entry.is_object());
        assert!(!entry.is_canonical());
    }

    #[test]
    fn test_object_model_row() {
        let entry = ModelValueEntry::new(
            "pid",
            Some(ModelValue::Int(1234)),
            Lifespan::now_on(0),
            KeyPath::of(&["Processes", "[5]"]),
        );
        let mut row = ObjectModelRow::new(entry);
        assert_eq!(row.key, "pid");
        assert_eq!(row.display, "0x000004d2");

        let attr = AttributeValue::new("5").with_modified(true);
        row.set_attribute("id", attr);
        assert!(row.get_attribute("id").unwrap().modified);
    }

    #[test]
    fn test_path_model_row() {
        let path = KeyPath::of(&["Processes", "[5]", "name"]);
        let row = PathModelRow::new(
            path,
            Some(ModelValue::String("init".into())),
            Lifespan::now_on(0),
        );
        assert_eq!(row.last_key, "name");
        assert_eq!(row.value_display, "init");
    }

    #[test]
    fn test_tree_state() {
        let mut state = TreeState::new();
        let path = KeyPath::of(&["a", "b"]);
        assert!(!state.is_expanded(&path));

        state.expand(path.clone());
        assert!(state.is_expanded(&path));

        state.toggle(path.clone());
        assert!(!state.is_expanded(&path));

        state.set_selected(Some(KeyPath::of(&["a"])));
        assert_eq!(state.selected(), Some(&KeyPath::of(&["a"])));
    }

    #[test]
    fn test_tree_state_expand_to() {
        let mut state = TreeState::new();
        let deep_path = KeyPath::of(&["a", "b", "c"]);
        state.expand_to(&deep_path);
        assert!(state.is_expanded(&KeyPath::of(&["a"])));
        assert!(state.is_expanded(&KeyPath::of(&["a", "b"])));
        assert!(state.is_expanded(&KeyPath::of(&["a", "b", "c"])));
    }

    #[test]
    fn test_value_display_helper() {
        let display = ValueDisplay::new();
        assert_eq!(
            display.get_primitive_value_display(&Some(ModelValue::Bool(true))),
            "true"
        );
        assert_eq!(
            display.get_primitive_value_display(&None),
            ""
        );
    }

    #[test]
    fn test_displays_modified() {
        let mut dm = DisplaysModified::new();
        assert!(!dm.modified);
        dm.set_diff_color([255, 0, 0, 255]);
        assert!(dm.modified);
        assert_eq!(dm.diff_color, Some([255, 0, 0, 255]));
    }

    #[test]
    fn test_model_query_serde() {
        let query = ModelQuery::parse("Processes");
        // ModelQuery doesn't derive Serialize/Deserialize (contains PathMatcher which may not)
        // Test the display trait instead
        let display = format!("{}", query);
        assert!(display.contains("Processes"));
    }

    #[test]
    fn test_attribute_value() {
        let av = AttributeValue::new("test");
        assert_eq!(av.display, "test");
        assert_eq!(av.html_display, "<html>test</html>");
        assert_eq!(av.tooltip, "test");
        assert!(!av.modified);
    }
}
