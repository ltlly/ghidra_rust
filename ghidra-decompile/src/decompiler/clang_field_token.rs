//! ClangFieldToken: struct/class field access tokens.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangFieldToken`.
//! Re-exports `ClangFieldTokenData` from `clang_node` and provides
//! convenience constructors.

pub use super::clang_node::ClangFieldTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create a field token with the given name.
pub fn field_token(field_name: &str) -> ClangFieldTokenData {
    ClangFieldTokenData {
        token: ClangTokenData {
            text: Some(field_name.to_string()),
            syntax_type: SyntaxType::Field,
            ..Default::default()
        },
        datatype_name: None,
        datatype_id: None,
        offset: 0,
        op_ref: None,
        address: None,
    }
}

/// Create a field token with struct type info.
pub fn field_token_with_type(
    field_name: &str,
    datatype_name: &str,
    datatype_id: u64,
    offset: i32,
) -> ClangFieldTokenData {
    ClangFieldTokenData {
        token: ClangTokenData {
            text: Some(field_name.to_string()),
            syntax_type: SyntaxType::Field,
            ..Default::default()
        },
        datatype_name: Some(datatype_name.to_string()),
        datatype_id: Some(datatype_id),
        offset,
        op_ref: None,
        address: None,
    }
}

/// Create a field token with full references.
pub fn field_token_full(
    field_name: &str,
    datatype_name: &str,
    datatype_id: u64,
    offset: i32,
    op_ref: u32,
    address: Address,
) -> ClangFieldTokenData {
    ClangFieldTokenData {
        token: ClangTokenData {
            text: Some(field_name.to_string()),
            syntax_type: SyntaxType::Field,
            ..Default::default()
        },
        datatype_name: Some(datatype_name.to_string()),
        datatype_id: Some(datatype_id),
        offset,
        op_ref: Some(op_ref),
        address: Some(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_token() {
        let tok = field_token("x");
        assert_eq!(tok.token.text.as_deref(), Some("x"));
        assert_eq!(tok.token.syntax_type, SyntaxType::Field);
        assert_eq!(tok.offset, 0);
    }

    #[test]
    fn test_field_token_with_type() {
        let tok = field_token_with_type("y", "Point", 100, 4);
        assert_eq!(tok.datatype_name.as_deref(), Some("Point"));
        assert_eq!(tok.datatype_id, Some(100));
        assert_eq!(tok.offset, 4);
    }

    #[test]
    fn test_field_token_full() {
        let addr = Address::new(0x3000);
        let tok = field_token_full("z", "Vec3", 200, 8, 5, addr);
        assert_eq!(tok.op_ref, Some(5));
        assert_eq!(tok.address, Some(addr));
    }
}
