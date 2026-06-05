//! Adapter traits for code unit types.
//!
//! Ported from Ghidra's `DBTraceCodeUnitAdapter`, `DBTraceDataAdapter`,
//! `DBTraceDefinedDataAdapter`, `DBTraceCommentAdapter`.

use crate::db::listing::code_unit::AbstractCodeUnit;

/// Adapter trait for reading code unit properties.
pub trait CodeUnitAdapter {
    /// Get the address offset.
    fn address(&self) -> u64;

    /// Get the maximum address offset.
    fn max_address(&self) -> u64;

    /// Get the length in bytes.
    fn length(&self) -> u32;

    /// Get the thread ID (0 for global).
    fn thread_id(&self) -> u64;

    /// Get the snap.
    fn snap(&self) -> i64;

    /// Get the address space name.
    fn space_name(&self) -> &str;
}

/// Adapter trait for data-type code units.
pub trait DataAdapter: CodeUnitAdapter {
    /// Get the data type name.
    fn data_type_name(&self) -> &str;

    /// Get the data type category path.
    fn category_path(&self) -> &str;

    /// Get the number of components.
    fn num_components(&self) -> u32;

    /// Check if this is a composite (struct/union) type.
    fn is_composite(&self) -> bool {
        self.num_components() > 0
    }
}

/// Adapter trait for defined data units.
pub trait DefinedDataAdapter: DataAdapter {
    /// Get the value as raw bytes.
    fn value_bytes(&self) -> Option<&[u8]>;

    /// Check if this is user-defined (vs. inferred).
    fn is_user_defined(&self) -> bool;

    /// Get the parent offset, if this is a component.
    fn parent_offset(&self) -> Option<u64>;
}

/// Adapter trait for code units that may have comments.
pub trait CommentAdapter: CodeUnitAdapter {
    /// Get the pre-comment text.
    fn pre_comment(&self) -> Option<&str>;

    /// Get the post-comment text.
    fn post_comment(&self) -> Option<&str>;

    /// Get the end-of-line comment.
    fn eol_comment(&self) -> Option<&str>;

    /// Get the repeatable comment.
    fn repeatable_comment(&self) -> Option<&str>;

    /// Get the plate comment.
    fn plate_comment(&self) -> Option<&str>;

    /// Set the pre-comment.
    fn set_pre_comment(&mut self, comment: Option<String>);

    /// Set the post-comment.
    fn set_post_comment(&mut self, comment: Option<String>);

    /// Set the end-of-line comment.
    fn set_eol_comment(&mut self, comment: Option<String>);

    /// Set the repeatable comment.
    fn set_repeatable_comment(&mut self, comment: Option<String>);

    /// Set the plate comment.
    fn set_plate_comment(&mut self, comment: Option<String>);
}

/// Default implementation of CommentAdapter for any CodeUnitAdapter.
#[derive(Debug, Clone)]
pub struct DefaultCommentAdapter {
    /// The base code unit.
    pub base: AbstractCodeUnit,
    /// Pre-comment.
    pub pre_comment: Option<String>,
    /// Post-comment.
    pub post_comment: Option<String>,
    /// End-of-line comment.
    pub eol_comment: Option<String>,
    /// Repeatable comment.
    pub repeatable_comment: Option<String>,
    /// Plate comment.
    pub plate_comment: Option<String>,
}

impl DefaultCommentAdapter {
    /// Create a new comment adapter wrapping a code unit.
    pub fn new(base: AbstractCodeUnit) -> Self {
        Self {
            base,
            pre_comment: None,
            post_comment: None,
            eol_comment: None,
            repeatable_comment: None,
            plate_comment: None,
        }
    }
}

impl CodeUnitAdapter for DefaultCommentAdapter {
    fn address(&self) -> u64 { self.base.offset }
    fn max_address(&self) -> u64 { self.base.max_offset() }
    fn length(&self) -> u32 { self.base.length }
    fn thread_id(&self) -> u64 { self.base.thread_id }
    fn snap(&self) -> i64 { self.base.snap }
    fn space_name(&self) -> &str { &self.base.space_name }
}

impl CommentAdapter for DefaultCommentAdapter {
    fn pre_comment(&self) -> Option<&str> { self.pre_comment.as_deref() }
    fn post_comment(&self) -> Option<&str> { self.post_comment.as_deref() }
    fn eol_comment(&self) -> Option<&str> { self.eol_comment.as_deref() }
    fn repeatable_comment(&self) -> Option<&str> { self.repeatable_comment.as_deref() }
    fn plate_comment(&self) -> Option<&str> { self.plate_comment.as_deref() }

    fn set_pre_comment(&mut self, comment: Option<String>) { self.pre_comment = comment; }
    fn set_post_comment(&mut self, comment: Option<String>) { self.post_comment = comment; }
    fn set_eol_comment(&mut self, comment: Option<String>) { self.eol_comment = comment; }
    fn set_repeatable_comment(&mut self, comment: Option<String>) { self.repeatable_comment = comment; }
    fn set_plate_comment(&mut self, comment: Option<String>) { self.plate_comment = comment; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CodeUnitType;

    #[test]
    fn test_comment_adapter() {
        let base = AbstractCodeUnit {
            offset: 0x1000,
            length: 4,
            snap: 0,
            thread_id: 0,
            kind: crate::db::listing::code_unit::CodeUnitKind::Data,
            unit_type: CodeUnitType::Data,
            is_overlay: false,
            space_name: "ram".into(),
        };
        let mut adapter = DefaultCommentAdapter::new(base);
        assert!(adapter.pre_comment().is_none());

        adapter.set_eol_comment(Some("test comment".into()));
        assert_eq!(adapter.eol_comment(), Some("test comment"));

        assert_eq!(adapter.address(), 0x1000);
        assert_eq!(adapter.length(), 4);
    }
}
