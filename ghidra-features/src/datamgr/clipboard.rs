//! Data type clipboard operations.
//!
//! Ported from cut/copy/paste actions in `ghidra.app.plugin.core.datamgr.actions`.
//!
//! Provides clipboard support for data types in the data type manager tree,
//! allowing users to cut, copy, and paste data types between archives.


/// Content on the data type clipboard.
#[derive(Debug, Clone)]
pub struct DataTypeClipboardContent {
    /// The data type names on the clipboard.
    pub type_names: Vec<String>,
    /// The source archive name.
    pub source_archive: String,
    /// Whether this is a cut operation (vs copy).
    pub is_cut: bool,
    /// Serialized data type definitions.
    pub definitions: Vec<DataTypeDefinition>,
}

impl DataTypeClipboardContent {
    /// Create a new clipboard content.
    pub fn new(source_archive: impl Into<String>, is_cut: bool) -> Self {
        Self {
            type_names: Vec::new(),
            source_archive: source_archive.into(),
            is_cut,
            definitions: Vec::new(),
        }
    }

    /// Whether the clipboard has content.
    pub fn has_content(&self) -> bool {
        !self.type_names.is_empty()
    }

    /// The number of items on the clipboard.
    pub fn len(&self) -> usize {
        self.type_names.len()
    }

    /// Whether the clipboard is empty.
    pub fn is_empty(&self) -> bool {
        self.type_names.is_empty()
    }

    /// Add a data type to the clipboard.
    pub fn add_type(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.type_names.contains(&name) {
            self.type_names.push(name);
        }
    }
}

/// A simplified data type definition for clipboard operations.
#[derive(Debug, Clone)]
pub struct DataTypeDefinition {
    /// The data type name.
    pub name: String,
    /// The category path.
    pub category: String,
    /// The type kind (struct, union, enum, typedef, etc.).
    pub kind: DataTypeKind,
    /// Size in bytes.
    pub size: u64,
}

/// The kind of data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeKind {
    /// Structure.
    Structure,
    /// Union.
    Union,
    /// Enum.
    Enum,
    /// Typedef.
    TypeDef,
    /// Function definition.
    FunctionDef,
    /// Pointer.
    Pointer,
    /// Array.
    Array,
    /// Built-in/primitive.
    BuiltIn,
}

impl DataTypeKind {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Structure => "Structure",
            Self::Union => "Union",
            Self::Enum => "Enum",
            Self::TypeDef => "Typedef",
            Self::FunctionDef => "Function Definition",
            Self::Pointer => "Pointer",
            Self::Array => "Array",
            Self::BuiltIn => "Built-in",
        }
    }
}

/// Manages clipboard operations for data types.
#[derive(Debug)]
pub struct DataTypeClipboard {
    /// Current clipboard content.
    content: Option<DataTypeClipboardContent>,
    /// Clipboard history.
    history: Vec<DataTypeClipboardContent>,
    /// Max history entries.
    max_history: usize,
}

impl DataTypeClipboard {
    /// Create a new clipboard.
    pub fn new() -> Self {
        Self {
            content: None,
            history: Vec::new(),
            max_history: 20,
        }
    }

    /// Set clipboard content.
    pub fn set_content(&mut self, content: DataTypeClipboardContent) {
        if let Some(prev) = self.content.take() {
            self.history.push(prev);
            if self.history.len() > self.max_history {
                self.history.remove(0);
            }
        }
        self.content = Some(content);
    }

    /// Get the clipboard content.
    pub fn content(&self) -> Option<&DataTypeClipboardContent> {
        self.content.as_ref()
    }

    /// Clear the clipboard.
    pub fn clear(&mut self) {
        self.content = None;
    }

    /// Whether the clipboard has content.
    pub fn has_content(&self) -> bool {
        self.content.as_ref().map_or(false, |c| c.has_content())
    }

    /// Get clipboard history.
    pub fn history(&self) -> &[DataTypeClipboardContent] {
        &self.history
    }
}

impl Default for DataTypeClipboard {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_content() {
        let mut content = DataTypeClipboardContent::new("BuiltInTypes", false);
        assert!(!content.has_content());
        assert!(content.is_empty());

        content.add_type("int");
        content.add_type("char");
        assert!(content.has_content());
        assert_eq!(content.len(), 2);
    }

    #[test]
    fn test_clipboard_content_dedup() {
        let mut content = DataTypeClipboardContent::new("archive", false);
        content.add_type("int");
        content.add_type("int");
        assert_eq!(content.len(), 1);
    }

    #[test]
    fn test_clipboard_lifecycle() {
        let mut clipboard = DataTypeClipboard::new();
        assert!(!clipboard.has_content());

        let mut content = DataTypeClipboardContent::new("archive", true);
        content.add_type("MyStruct");
        clipboard.set_content(content);

        assert!(clipboard.has_content());
        let c = clipboard.content().unwrap();
        assert_eq!(c.source_archive, "archive");
        assert!(c.is_cut);
        assert_eq!(c.type_names, vec!["MyStruct"]);
    }

    #[test]
    fn test_clipboard_history() {
        let mut clipboard = DataTypeClipboard::new();

        let mut c1 = DataTypeClipboardContent::new("a1", false);
        c1.add_type("int");
        clipboard.set_content(c1);

        let mut c2 = DataTypeClipboardContent::new("a2", true);
        c2.add_type("char");
        clipboard.set_content(c2);

        assert_eq!(clipboard.history().len(), 1);
        assert_eq!(clipboard.history()[0].type_names, vec!["int"]);
    }

    #[test]
    fn test_clipboard_clear() {
        let mut clipboard = DataTypeClipboard::new();
        let mut content = DataTypeClipboardContent::new("archive", false);
        content.add_type("int");
        clipboard.set_content(content);

        clipboard.clear();
        assert!(!clipboard.has_content());
        assert!(clipboard.content().is_none());
    }

    #[test]
    fn test_data_type_kind_display() {
        assert_eq!(DataTypeKind::Structure.display_name(), "Structure");
        assert_eq!(DataTypeKind::Union.display_name(), "Union");
        assert_eq!(DataTypeKind::Enum.display_name(), "Enum");
        assert_eq!(DataTypeKind::BuiltIn.display_name(), "Built-in");
    }

    #[test]
    fn test_clipboard_history_max() {
        let mut clipboard = DataTypeClipboard::new();
        clipboard.max_history = 2;
        for i in 0..5 {
            let mut content = DataTypeClipboardContent::new(format!("archive_{}", i), false);
            content.add_type(format!("type_{}", i));
            clipboard.set_content(content);
        }
        assert!(clipboard.history().len() <= 2);
    }
}
