//! ClangBitFieldToken: bitfield tokens.
//!
//! Ports Ghidra's `ghidra.app.decompiler.ClangBitFieldToken`.
//! Re-exports `ClangBitFieldTokenData` from `clang_node`.

pub use super::clang_node::ClangBitFieldTokenData;
use super::clang_node::{ClangTokenData, SyntaxType};
use ghidra_core::addr::Address;

/// Create a bitfield token.
pub fn bit_field_token(name: &str, ident: i32) -> ClangBitFieldTokenData {
    ClangBitFieldTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Field,
            ..Default::default()
        },
        datatype_name: None,
        datatype_id: None,
        ident,
        op_ref: None,
        address: None,
    }
}

/// Create a bitfield token with struct type info.
pub fn bit_field_token_with_type(
    name: &str,
    ident: i32,
    datatype_name: &str,
    datatype_id: u64,
) -> ClangBitFieldTokenData {
    ClangBitFieldTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Field,
            ..Default::default()
        },
        datatype_name: Some(datatype_name.to_string()),
        datatype_id: Some(datatype_id),
        ident,
        op_ref: None,
        address: None,
    }
}

/// Create a bitfield token with full references.
pub fn bit_field_token_full(
    name: &str,
    ident: i32,
    datatype_name: &str,
    datatype_id: u64,
    op_ref: u32,
    address: Address,
) -> ClangBitFieldTokenData {
    ClangBitFieldTokenData {
        token: ClangTokenData {
            text: Some(name.to_string()),
            syntax_type: SyntaxType::Field,
            ..Default::default()
        },
        datatype_name: Some(datatype_name.to_string()),
        datatype_id: Some(datatype_id),
        ident,
        op_ref: Some(op_ref),
        address: Some(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_field_token() {
        let tok = bit_field_token("flags", 0);
        assert_eq!(tok.token.text.as_deref(), Some("flags"));
        assert_eq!(tok.ident, 0);
    }

    #[test]
    fn test_bit_field_token_with_type() {
        let tok = bit_field_token_with_type("is_active", 1, "Header", 100);
        assert_eq!(tok.datatype_name.as_deref(), Some("Header"));
        assert_eq!(tok.datatype_id, Some(100));
    }

    #[test]
    fn test_bit_field_token_full() {
        let addr = Address::new(0x3000);
        let tok = bit_field_token_full("type", 2, "Packet", 200, 5, addr);
        assert_eq!(tok.op_ref, Some(5));
        assert_eq!(tok.address, Some(addr));
    }
}
