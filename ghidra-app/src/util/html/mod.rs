//! HTML data-type representations (ported from `ghidra.app.util.html`).
//!
//! Provides structured HTML representations for data types, used in
//! tooltips and the data type manager.
//!
//! Key types:
//! - [`HtmlDataTypeRepresentation`] -- base trait for all HTML representations
//! - [`TextLine`] / [`DataTypeLine`] / [`VariableTextLine`] -- line types
//! - [`DefaultDataTypeRepresentation`] -- simple text representation
//! - [`CompositeDataTypeRepresentation`] -- struct/union representation
//! - [`FunctionDataTypeRepresentation`] -- function signature representation
//! - [`EnumDataTypeRepresentation`] -- enum representation
//! - [`PointerDataTypeRepresentation`] -- pointer representation

use serde::{Deserialize, Serialize};

// ===================================================================
// TextLine hierarchy  (ghidra.app.util.html.*TextLine)
// ===================================================================

/// A single line of text in an HTML representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextLine {
    /// Plain text.
    Plain(String),
    /// Text styled as a data type.
    DataType {
        /// The data type name.
        name: String,
        /// Whether it is an alignment filler.
        is_alignment: bool,
    },
    /// Text styled with a variable name.
    Variable {
        /// Variable name.
        name: String,
        /// Whether this is a validatable line (e.g. syntax error).
        valid: bool,
    },
    /// Empty placeholder.
    Empty,
    /// Indentation / spacing.
    PlaceHolder(String),
}

impl TextLine {
    /// Return the text content.
    pub fn text(&self) -> &str {
        match self {
            Self::Plain(s) => s,
            Self::DataType { name, .. } => name,
            Self::Variable { name, .. } => name,
            Self::Empty => "",
            Self::PlaceHolder(s) => s,
        }
    }

    /// Convert to an HTML string.
    pub fn to_html(&self) -> String {
        match self {
            Self::Plain(s) => html_escape(s),
            Self::DataType { name, .. } => {
                format!("<b>{}</b>", html_escape(name))
            }
            Self::Variable { name, valid } => {
                if *valid {
                    format!("<i>{}</i>", html_escape(name))
                } else {
                    format!("<i style='color:red'>{}</i>", html_escape(name))
                }
            }
            Self::Empty => String::new(),
            Self::PlaceHolder(s) => html_escape(s),
        }
    }
}

// ===================================================================
// HtmlDataTypeRepresentation  (ghidra.app.util.html.HTMLDataTypeRepresentation)
// ===================================================================

/// Trait for structured HTML representations of data types.
pub trait HtmlDataTypeRepresentation: Send + Sync {
    /// Return the short HTML string (for tooltips).
    fn get_html_string(&self) -> String;

    /// Return the full HTML string (not truncated).
    fn get_full_html_string(&self) -> String {
        self.get_html_string()
    }

    /// Return the lines that make up this representation.
    fn get_lines(&self) -> &[TextLine];

    /// Return the display name of the represented data type.
    fn data_type_name(&self) -> &str;
}

// ===================================================================
// DefaultDataTypeRepresentation
// ===================================================================

/// Simple HTML representation for a data type with a single name line.
#[derive(Debug, Clone)]
pub struct DefaultDataTypeRepresentation {
    /// Data type name.
    name: String,
    /// Category path (e.g. "/builtin").
    category: String,
    /// Additional description.
    description: Option<String>,
}

impl DefaultDataTypeRepresentation {
    /// Create a new representation.
    pub fn new(name: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
            description: None,
        }
    }

    /// Set a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

impl HtmlDataTypeRepresentation for DefaultDataTypeRepresentation {
    fn get_html_string(&self) -> String {
        let mut html = format!("<b>{}</b>", html_escape(&self.name));
        if !self.category.is_empty() && self.category != "/" {
            html.push_str(&format!(
                " <font color='gray'>{}</font>",
                html_escape(&self.category)
            ));
        }
        if let Some(desc) = &self.description {
            html.push_str(&format!("<br/>{}", html_escape(desc)));
        }
        html
    }

    fn get_lines(&self) -> &[TextLine] {
        &[] // simplified; real impl would store lines
    }

    fn data_type_name(&self) -> &str {
        &self.name
    }
}

// ===================================================================
// CompositeDataTypeRepresentation  (struct / union)
// ===================================================================

/// HTML representation for composite types (structs, unions).
#[derive(Debug, Clone)]
pub struct CompositeDataTypeRepresentation {
    name: String,
    kind: CompositeKind,
    fields: Vec<CompositeField>,
}

/// Whether a composite is a struct or union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompositeKind {
    /// Structure.
    Struct,
    /// Union.
    Union,
}

/// A field in a composite type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeField {
    /// Offset from the start of the composite.
    pub offset: u64,
    /// Field name.
    pub name: String,
    /// Field data type name.
    pub type_name: String,
    /// Field size in bytes.
    pub size: u64,
}

impl CompositeDataTypeRepresentation {
    /// Create a new composite representation.
    pub fn new(
        name: impl Into<String>,
        kind: CompositeKind,
        fields: Vec<CompositeField>,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            fields,
        }
    }
}

impl HtmlDataTypeRepresentation for CompositeDataTypeRepresentation {
    fn get_html_string(&self) -> String {
        let kind_str = match self.kind {
            CompositeKind::Struct => "struct",
            CompositeKind::Union => "union",
        };
        let mut html = format!("<b>{} {}</b> {{", kind_str, html_escape(&self.name));
        for field in &self.fields {
            html.push_str(&format!(
                "<br/>&nbsp;&nbsp;{} {};",
                html_escape(&field.type_name),
                html_escape(&field.name)
            ));
        }
        html.push_str("<br/>}");
        html
    }

    fn get_lines(&self) -> &[TextLine] {
        &[]
    }

    fn data_type_name(&self) -> &str {
        &self.name
    }
}

// ===================================================================
// FunctionDataTypeRepresentation
// ===================================================================

/// HTML representation for function signatures.
#[derive(Debug, Clone)]
pub struct FunctionDataTypeRepresentation {
    return_type: String,
    name: String,
    parameters: Vec<(String, String)>, // (type, name)
    is_vararg: bool,
}

impl FunctionDataTypeRepresentation {
    /// Create a new function representation.
    pub fn new(
        return_type: impl Into<String>,
        name: impl Into<String>,
        parameters: Vec<(String, String)>,
    ) -> Self {
        Self {
            return_type: return_type.into(),
            name: name.into(),
            parameters,
            is_vararg: false,
        }
    }

    /// Mark as variadic.
    pub fn with_vararg(mut self) -> Self {
        self.is_vararg = true;
        self
    }
}

impl HtmlDataTypeRepresentation for FunctionDataTypeRepresentation {
    fn get_html_string(&self) -> String {
        let params: Vec<String> = self
            .parameters
            .iter()
            .map(|(t, n)| format!("{} {}", html_escape(t), html_escape(n)))
            .collect();
        let mut param_str = params.join(", ");
        if self.is_vararg {
            if !param_str.is_empty() {
                param_str.push_str(", ");
            }
            param_str.push_str("...");
        }
        format!(
            "<b>{}</b> {}({})",
            html_escape(&self.return_type),
            html_escape(&self.name),
            param_str
        )
    }

    fn get_lines(&self) -> &[TextLine] {
        &[]
    }

    fn data_type_name(&self) -> &str {
        &self.name
    }
}

// ===================================================================
// EnumDataTypeRepresentation
// ===================================================================

/// HTML representation for enum types.
#[derive(Debug, Clone)]
pub struct EnumDataTypeRepresentation {
    name: String,
    values: Vec<(String, i64)>,
}

impl EnumDataTypeRepresentation {
    /// Create a new enum representation.
    pub fn new(name: impl Into<String>, values: Vec<(String, i64)>) -> Self {
        Self {
            name: name.into(),
            values,
        }
    }
}

impl HtmlDataTypeRepresentation for EnumDataTypeRepresentation {
    fn get_html_string(&self) -> String {
        let mut html = format!("<b>enum {}</b> {{", html_escape(&self.name));
        for (i, (name, val)) in self.values.iter().enumerate() {
            if i > 0 {
                html.push(',');
            }
            html.push_str(&format!(
                "<br/>&nbsp;&nbsp;{} = {}",
                html_escape(name),
                val
            ));
        }
        html.push_str("<br/>}");
        html
    }

    fn get_lines(&self) -> &[TextLine] {
        &[]
    }

    fn data_type_name(&self) -> &str {
        &self.name
    }
}

// ===================================================================
// PointerDataTypeRepresentation
// ===================================================================

/// HTML representation for pointer types.
#[derive(Debug, Clone)]
pub struct PointerDataTypeRepresentation {
    pointee_name: String,
    pointer_size: usize,
}

impl PointerDataTypeRepresentation {
    /// Create a new pointer representation.
    pub fn new(pointee_name: impl Into<String>, pointer_size: usize) -> Self {
        Self {
            pointee_name: pointee_name.into(),
            pointer_size,
        }
    }
}

impl HtmlDataTypeRepresentation for PointerDataTypeRepresentation {
    fn get_html_string(&self) -> String {
        format!(
            "<b>{}*</b> ({} bytes)",
            html_escape(&self.pointee_name),
            self.pointer_size
        )
    }

    fn get_lines(&self) -> &[TextLine] {
        &[]
    }

    fn data_type_name(&self) -> &str {
        &self.pointee_name
    }
}

// ===================================================================
// HTML diff input  (ghidra.app.util.html.HTMLDataTypeRepresentationDiffInput)
// ===================================================================

/// Represents a diff between two data-type HTML representations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtmlDataTypeDiff {
    /// The old data type name.
    pub old_name: String,
    /// The new data type name.
    pub new_name: String,
    /// Changed fields (old, new).
    pub changed_fields: Vec<(String, String)>,
    /// Added fields.
    pub added_fields: Vec<String>,
    /// Removed fields.
    pub removed_fields: Vec<String>,
}

// ===================================================================
// Helpers
// ===================================================================

/// Escape special HTML characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_line_plain() {
        let line = TextLine::Plain("hello".into());
        assert_eq!(line.text(), "hello");
        assert_eq!(line.to_html(), "hello");
    }

    #[test]
    fn text_line_data_type() {
        let line = TextLine::DataType {
            name: "int".into(),
            is_alignment: false,
        };
        assert_eq!(line.text(), "int");
        assert!(line.to_html().contains("<b>int</b>"));
    }

    #[test]
    fn text_line_variable() {
        let line = TextLine::Variable {
            name: "x".into(),
            valid: true,
        };
        assert!(line.to_html().contains("<i>x</i>"));

        let invalid = TextLine::Variable {
            name: "bad".into(),
            valid: false,
        };
        assert!(invalid.to_html().contains("color:red"));
    }

    #[test]
    fn html_escape_test() {
        assert_eq!(html_escape("<b>test</b>"), "&lt;b&gt;test&lt;/b&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("a\"b"), "a&quot;b");
    }

    #[test]
    fn default_representation() {
        let rep = DefaultDataTypeRepresentation::new("int", "/builtin");
        let html = rep.get_html_string();
        assert!(html.contains("<b>int</b>"));
        assert!(html.contains("/builtin"));
        assert_eq!(rep.data_type_name(), "int");
    }

    #[test]
    fn default_representation_with_description() {
        let rep = DefaultDataTypeRepresentation::new("int", "/builtin")
            .with_description("32-bit signed integer");
        let html = rep.get_html_string();
        assert!(html.contains("32-bit signed integer"));
    }

    #[test]
    fn composite_representation() {
        let rep = CompositeDataTypeRepresentation::new(
            "Point",
            CompositeKind::Struct,
            vec![
                CompositeField {
                    offset: 0,
                    name: "x".into(),
                    type_name: "int".into(),
                    size: 4,
                },
                CompositeField {
                    offset: 4,
                    name: "y".into(),
                    type_name: "int".into(),
                    size: 4,
                },
            ],
        );
        let html = rep.get_html_string();
        assert!(html.contains("struct Point"));
        assert!(html.contains("int x"));
        assert!(html.contains("int y"));
    }

    #[test]
    fn function_representation() {
        let rep = FunctionDataTypeRepresentation::new(
            "int",
            "add",
            vec![("int".into(), "a".into()), ("int".into(), "b".into())],
        );
        let html = rep.get_html_string();
        assert!(html.contains("int"));
        assert!(html.contains("add"));
        assert!(html.contains("int a"));
        assert!(html.contains("int b"));
    }

    #[test]
    fn function_representation_vararg() {
        let rep = FunctionDataTypeRepresentation::new("int", "printf", vec![]).with_vararg();
        let html = rep.get_html_string();
        assert!(html.contains("..."));
    }

    #[test]
    fn enum_representation() {
        let rep = EnumDataTypeRepresentation::new(
            "Color",
            vec![
                ("RED".into(), 0),
                ("GREEN".into(), 1),
                ("BLUE".into(), 2),
            ],
        );
        let html = rep.get_html_string();
        assert!(html.contains("enum Color"));
        assert!(html.contains("RED = 0"));
        assert!(html.contains("BLUE = 2"));
    }

    #[test]
    fn pointer_representation() {
        let rep = PointerDataTypeRepresentation::new("int", 8);
        let html = rep.get_html_string();
        assert!(html.contains("int*"));
        assert!(html.contains("8 bytes"));
    }

    #[test]
    fn html_diff() {
        let diff = HtmlDataTypeDiff {
            old_name: "OldStruct".into(),
            new_name: "NewStruct".into(),
            changed_fields: vec![("int".into(), "long".into())],
            added_fields: vec!["newField".into()],
            removed_fields: vec!["oldField".into()],
        };
        assert_eq!(diff.old_name, "OldStruct");
        assert_eq!(diff.added_fields.len(), 1);
    }
}
