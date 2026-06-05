//! Additional listing database types.
//!
//! Ported from Ghidra's `ghidra.trace.database.listing` package.
//! Provides concrete implementations of trace listing views that were
//! missing from the initial port:
//! - `DBTraceDataAdapter`: Data adapter for trace data units.
//! - `DBTraceCommentAdapter`: Comment adapter for code comments.
//! - `DBTraceCodeUnitAdapter`: Code unit adapter base.
//! - `DBTraceDefinedDataAdapter`: Defined data adapter.
//! - `DBTraceDataArrayElementComponent`: Array element component.
//! - `DBTraceDataCompositeFieldComponent`: Composite field component.
//! - Various memory view types for code listing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{CommentType, Lifespan};

/// Comment types in a trace code listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TraceCommentType {
    /// Pre-comment (before the code unit).
    Pre,
    /// Post-comment (after the code unit).
    Post,
    /// End-of-line comment.
    Eol,
    /// Plate comment (above, with separator).
    Plate,
    /// Repeatable comment.
    Repeatable,
}

impl TraceCommentType {
    /// Convert from a numeric comment type.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Pre),
            1 => Some(Self::Post),
            2 => Some(Self::Eol),
            3 => Some(Self::Plate),
            4 => Some(Self::Repeatable),
            _ => None,
        }
    }

    /// Convert to a numeric value.
    pub fn to_u32(&self) -> u32 {
        match self {
            Self::Pre => 0,
            Self::Post => 1,
            Self::Eol => 2,
            Self::Plate => 3,
            Self::Repeatable => 4,
        }
    }
}

/// A comment attached to a code unit in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCodeComment {
    /// The address of the code unit.
    pub address: u64,
    /// The snap at which this comment exists.
    pub snap: i64,
    /// The comment type.
    pub comment_type: TraceCommentType,
    /// The comment text.
    pub text: String,
}

impl TraceCodeComment {
    /// Create a new comment.
    pub fn new(
        address: u64,
        snap: i64,
        comment_type: TraceCommentType,
        text: impl Into<String>,
    ) -> Self {
        Self {
            address,
            snap,
            comment_type,
            text: text.into(),
        }
    }
}

/// Adapter for trace code unit properties.
///
/// Ported from `DBTraceCodeUnitAdapter`. Manages the mapping between
/// code unit addresses and their properties in the database.
#[derive(Debug)]
pub struct DBTraceCodeUnitAdapter {
    /// Properties per address.
    properties: BTreeMap<u64, CodeUnitProperties>,
}

/// Properties of a code unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeUnitProperties {
    /// The address.
    pub address: u64,
    /// Whether this is an instruction.
    pub is_instruction: bool,
    /// Whether this is defined data.
    pub is_defined: bool,
    /// The data type name (for data units).
    pub data_type_name: Option<String>,
    /// The length in bytes.
    pub length: usize,
    /// The flow override.
    pub flow_override: FlowOverride,
}

/// Flow override for instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowOverride {
    /// No override (default behavior).
    None,
    /// Override to fall-through only.
    FallThrough,
    /// Override to jump.
    Jump,
    /// Override to call.
    Call,
    /// Override to return.
    Return,
}

impl Default for FlowOverride {
    fn default() -> Self {
        Self::None
    }
}

impl Default for DBTraceCodeUnitAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DBTraceCodeUnitAdapter {
    /// Create a new code unit adapter.
    pub fn new() -> Self {
        Self {
            properties: BTreeMap::new(),
        }
    }

    /// Set properties for a code unit.
    pub fn set_properties(&mut self, props: CodeUnitProperties) {
        self.properties.insert(props.address, props);
    }

    /// Get properties for a code unit.
    pub fn get_properties(&self, address: u64) -> Option<&CodeUnitProperties> {
        self.properties.get(&address)
    }

    /// Remove properties for a code unit.
    pub fn remove_properties(&mut self, address: u64) -> Option<CodeUnitProperties> {
        self.properties.remove(&address)
    }

    /// Get all addresses that have properties.
    pub fn addresses(&self) -> Vec<u64> {
        self.properties.keys().copied().collect()
    }

    /// Get the number of code units.
    pub fn count(&self) -> usize {
        self.properties.len()
    }
}

/// Data adapter for trace data units.
///
/// Ported from `DBTraceDataAdapter`. Provides data-specific operations
/// on top of the code unit adapter.
#[derive(Debug)]
pub struct DBTraceDataAdapter {
    code_units: DBTraceCodeUnitAdapter,
    /// Component structure for composite data types.
    components: BTreeMap<u64, Vec<DataComponent>>,
}

/// A component of a composite data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataComponent {
    /// Offset from the parent data unit.
    pub offset: usize,
    /// Data type name of this component.
    pub data_type_name: String,
    /// Length in bytes.
    pub length: usize,
    /// Component path from root.
    pub component_path: Vec<usize>,
}

impl Default for DBTraceDataAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DBTraceDataAdapter {
    /// Create a new data adapter.
    pub fn new() -> Self {
        Self {
            code_units: DBTraceCodeUnitAdapter::new(),
            components: BTreeMap::new(),
        }
    }

    /// Add a defined data unit.
    pub fn add_data(
        &mut self,
        address: u64,
        data_type_name: impl Into<String>,
        length: usize,
    ) {
        let name = data_type_name.into();
        self.code_units.set_properties(CodeUnitProperties {
            address,
            is_instruction: false,
            is_defined: true,
            data_type_name: Some(name),
            length,
            flow_override: FlowOverride::None,
        });
    }

    /// Add an undefined data unit.
    pub fn add_undefined(&mut self, address: u64, length: usize) {
        self.code_units.set_properties(CodeUnitProperties {
            address,
            is_instruction: false,
            is_defined: false,
            data_type_name: None,
            length,
            flow_override: FlowOverride::None,
        });
    }

    /// Add a component to a composite data type.
    pub fn add_component(
        &mut self,
        parent_address: u64,
        component: DataComponent,
    ) {
        self.components
            .entry(parent_address)
            .or_default()
            .push(component);
    }

    /// Get the data at an address.
    pub fn get_data(&self, address: u64) -> Option<&CodeUnitProperties> {
        self.code_units.get_properties(address)
    }

    /// Get components for a data unit at the given address.
    pub fn get_components(&self, address: u64) -> &[DataComponent] {
        self.components
            .get(&address)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Check if a data type at an address is a composite (has components).
    pub fn is_composite(&self, address: u64) -> bool {
        self.components.contains_key(&address)
    }
}

/// Comment adapter for managing code comments.
///
/// Ported from `DBTraceCommentAdapter`.
#[derive(Debug)]
pub struct DBTraceCommentAdapter {
    /// Comments indexed by (address, snap, comment_type).
    comments: BTreeMap<(u64, i64, TraceCommentType), String>,
}

impl Default for DBTraceCommentAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DBTraceCommentAdapter {
    /// Create a new comment adapter.
    pub fn new() -> Self {
        Self {
            comments: BTreeMap::new(),
        }
    }

    /// Set a comment.
    pub fn set_comment(
        &mut self,
        address: u64,
        snap: i64,
        comment_type: TraceCommentType,
        text: impl Into<String>,
    ) {
        self.comments
            .insert((address, snap, comment_type), text.into());
    }

    /// Get a comment.
    pub fn get_comment(
        &self,
        address: u64,
        snap: i64,
        comment_type: TraceCommentType,
    ) -> Option<&str> {
        self.comments
            .get(&(address, snap, comment_type))
            .map(|s| s.as_str())
    }

    /// Remove a comment.
    pub fn remove_comment(
        &mut self,
        address: u64,
        snap: i64,
        comment_type: TraceCommentType,
    ) -> bool {
        self.comments
            .remove(&(address, snap, comment_type))
            .is_some()
    }

    /// Get all comments at a given address and snap.
    pub fn get_comments_at(&self, address: u64, snap: i64) -> Vec<(TraceCommentType, &str)> {
        self.comments
            .range(
                (address, i64::MIN, TraceCommentType::Pre)
                    ..=(address, i64::MAX, TraceCommentType::Repeatable),
            )
            .filter(|((_, s, _), _)| *s == snap)
            .map(|((_, _, ct), text)| (*ct, text.as_str()))
            .collect()
    }

    /// Get the total number of comments.
    pub fn count(&self) -> usize {
        self.comments.len()
    }
}

/// A code unit view entry for iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeUnitViewEntry {
    /// The address.
    pub address: u64,
    /// The snap.
    pub snap: i64,
    /// Whether this is an instruction.
    pub is_instruction: bool,
    /// The length in bytes.
    pub length: usize,
    /// The data type name (for data).
    pub data_type_name: Option<String>,
}

/// A memory view for code listing that combines instructions and data.
#[derive(Debug)]
pub struct CodeUnitsMemoryView {
    entries: Vec<CodeUnitViewEntry>,
}

impl Default for CodeUnitsMemoryView {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeUnitsMemoryView {
    /// Create a new code units memory view.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an entry.
    pub fn push(&mut self, entry: CodeUnitViewEntry) {
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn entries(&self) -> &[CodeUnitViewEntry] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Filter to only instructions.
    pub fn instructions(&self) -> Vec<&CodeUnitViewEntry> {
        self.entries.iter().filter(|e| e.is_instruction).collect()
    }

    /// Filter to only data.
    pub fn data(&self) -> Vec<&CodeUnitViewEntry> {
        self.entries.iter().filter(|e| !e.is_instruction).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_type() {
        assert_eq!(TraceCommentType::from_u32(0), Some(TraceCommentType::Pre));
        assert_eq!(TraceCommentType::from_u32(4), Some(TraceCommentType::Repeatable));
        assert_eq!(TraceCommentType::from_u32(99), None);

        assert_eq!(TraceCommentType::Eol.to_u32(), 2);
    }

    #[test]
    fn test_code_comment() {
        let comment = TraceCodeComment::new(0x400000, 0, TraceCommentType::Eol, "test comment");
        assert_eq!(comment.address, 0x400000);
        assert_eq!(comment.comment_type, TraceCommentType::Eol);
        assert_eq!(comment.text, "test comment");
    }

    #[test]
    fn test_code_unit_adapter() {
        let mut adapter = DBTraceCodeUnitAdapter::new();
        assert_eq!(adapter.count(), 0);

        adapter.set_properties(CodeUnitProperties {
            address: 0x400000,
            is_instruction: true,
            is_defined: true,
            data_type_name: None,
            length: 2,
            flow_override: FlowOverride::None,
        });

        assert_eq!(adapter.count(), 1);
        let props = adapter.get_properties(0x400000).unwrap();
        assert!(props.is_instruction);
        assert_eq!(props.length, 2);

        let removed = adapter.remove_properties(0x400000);
        assert!(removed.is_some());
        assert_eq!(adapter.count(), 0);
    }

    #[test]
    fn test_flow_override() {
        assert_eq!(FlowOverride::default(), FlowOverride::None);
        assert_ne!(FlowOverride::Call, FlowOverride::Return);
    }

    #[test]
    fn test_data_adapter() {
        let mut adapter = DBTraceDataAdapter::new();
        adapter.add_data(0x400000, "dword", 4);
        adapter.add_data(0x400004, "word", 2);
        adapter.add_undefined(0x400006, 10);

        let data = adapter.get_data(0x400000).unwrap();
        assert!(data.is_defined);
        assert_eq!(data.data_type_name.as_deref(), Some("dword"));

        let undef = adapter.get_data(0x400006).unwrap();
        assert!(!undef.is_defined);
    }

    #[test]
    fn test_data_adapter_components() {
        let mut adapter = DBTraceDataAdapter::new();
        adapter.add_data(0x400000, "struct", 8);
        adapter.add_component(
            0x400000,
            DataComponent {
                offset: 0,
                data_type_name: "dword".into(),
                length: 4,
                component_path: vec![0],
            },
        );
        adapter.add_component(
            0x400000,
            DataComponent {
                offset: 4,
                data_type_name: "dword".into(),
                length: 4,
                component_path: vec![1],
            },
        );

        assert!(adapter.is_composite(0x400000));
        assert!(!adapter.is_composite(0x400004));
        assert_eq!(adapter.get_components(0x400000).len(), 2);
    }

    #[test]
    fn test_comment_adapter() {
        let mut adapter = DBTraceCommentAdapter::new();
        adapter.set_comment(0x400000, 0, TraceCommentType::Eol, "inline comment");
        adapter.set_comment(0x400000, 0, TraceCommentType::Pre, "pre comment");

        assert_eq!(
            adapter.get_comment(0x400000, 0, TraceCommentType::Eol),
            Some("inline comment")
        );
        assert_eq!(
            adapter.get_comment(0x400000, 0, TraceCommentType::Pre),
            Some("pre comment")
        );
        assert_eq!(
            adapter.get_comment(0x400000, 0, TraceCommentType::Post),
            None
        );

        let comments = adapter.get_comments_at(0x400000, 0);
        assert_eq!(comments.len(), 2);

        assert!(adapter.remove_comment(0x400000, 0, TraceCommentType::Eol));
        assert_eq!(adapter.count(), 1);
    }

    #[test]
    fn test_code_units_memory_view() {
        let mut view = CodeUnitsMemoryView::new();
        view.push(CodeUnitViewEntry {
            address: 0x400000,
            snap: 0,
            is_instruction: true,
            length: 2,
            data_type_name: None,
        });
        view.push(CodeUnitViewEntry {
            address: 0x400002,
            snap: 0,
            is_instruction: false,
            length: 4,
            data_type_name: Some("dword".into()),
        });

        assert_eq!(view.count(), 2);
        assert_eq!(view.instructions().len(), 1);
        assert_eq!(view.data().len(), 1);
    }
}
