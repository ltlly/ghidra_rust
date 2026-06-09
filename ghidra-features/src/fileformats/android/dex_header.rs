//! Extended Android DEX header constants and helper types.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.dex.format.DexConstants`
//! and `DexHeaderQuickMethods` packages.
//!
//! This module provides additional DEX constants (debug info opcodes,
//! value format masks, visibility codes, etc.) and quick-access helpers
//! that complement the core `DexHeader` struct in `dex_format.rs`.

// ═══════════════════════════════════════════════════════════════════════════════════
// Debug Info Opcodes
// ═══════════════════════════════════════════════════════════════════════════════════

/// End of the debug info sequence.
pub const DBG_END_SEQUENCE: u8 = 0x00;

/// Advance the PC by the given unsigned LEB128 offset.
pub const DBG_ADVANCE_PC: u8 = 0x01;

/// Advance the line register by the given signed LEB128 delta.
pub const DBG_ADVANCE_LINE: u8 = 0x02;

/// Start a new source file at the given string index.
pub const DBG_START_LOCAL: u8 = 0x03;

/// Start a new local with a type descriptor.
pub const DBG_START_LOCAL_EXTENDED: u8 = 0x04;

/// End the scope of a local register.
pub const DBG_END_LOCAL: u8 = 0x05;

/// Restart a local register (re-emit its name/type).
pub const DBG_RESTART_LOCAL: u8 = 0x06;

/// Set the prologue end flag.
pub const DBG_SET_PROLOGUE_END: u8 = 0x07;

/// Set the epilogue begin flag.
pub const DBG_SET_EPILOGUE_BEGIN: u8 = 0x08;

/// Set the source file name (unsigned LEB128 string index).
pub const DBG_SET_FILE: u8 = 0x09;

/// First special opcode (line_base + line_range * (adjusted_opcode % line_range)).
pub const DBG_FIRST_SPECIAL: u8 = 0x0a;

/// Line base for standard opcodes.
pub const DBG_LINE_BASE: i32 = -4;

/// Line range for standard opcodes.
pub const DBG_LINE_RANGE: u32 = 15;

// ═══════════════════════════════════════════════════════════════════════════════════
// Value Format Constants (for encoded_array / annotations)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Encoded value type: byte.
pub const VALUE_BYTE: u8 = 0x00;
/// Encoded value type: short.
pub const VALUE_SHORT: u8 = 0x02;
/// Encoded value type: char.
pub const VALUE_CHAR: u8 = 0x03;
/// Encoded value type: int.
pub const VALUE_INT: u8 = 0x04;
/// Encoded value type: long.
pub const VALUE_LONG: u8 = 0x06;
/// Encoded value type: float.
pub const VALUE_FLOAT: u8 = 0x10;
/// Encoded value type: double.
pub const VALUE_DOUBLE: u8 = 0x11;
/// Encoded value type: string (string_ids index).
pub const VALUE_STRING: u8 = 0x17;
/// Encoded value type: type (type_ids index).
pub const VALUE_TYPE: u8 = 0x18;
/// Encoded value type: field (field_ids index).
pub const VALUE_FIELD: u8 = 0x19;
/// Encoded value type: method (method_ids index).
pub const VALUE_METHOD: u8 = 0x1a;
/// Encoded value type: enum (field_ids index).
pub const VALUE_ENUM: u8 = 0x1b;
/// Encoded value type: array.
pub const VALUE_ARRAY: u8 = 0x1c;
/// Encoded value type: annotation.
pub const VALUE_ANNOTATION: u8 = 0x1d;
/// Encoded value type: null.
pub const VALUE_NULL: u8 = 0x1e;
/// Encoded value type: boolean.
pub const VALUE_BOOLEAN: u8 = 0x1f;

// ═══════════════════════════════════════════════════════════════════════════════════
// Annotation Visibility Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Annotation is present only at build time (not retained in the class file at runtime).
pub const VISIBILITY_BUILD: u8 = 0x00;
/// Annotation is retained at runtime and available via reflection.
pub const VISIBILITY_RUNTIME: u8 = 0x01;
/// Annotation is retained by the VM/system but not visible to application code.
pub const VISIBILITY_SYSTEM: u8 = 0x02;

/// Returns a human-readable name for an annotation visibility value.
pub fn visibility_name(visibility: u8) -> &'static str {
    match visibility {
        VISIBILITY_BUILD => "BUILD",
        VISIBILITY_RUNTIME => "RUNTIME",
        VISIBILITY_SYSTEM => "SYSTEM",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Method Handle Type Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Method handle type: static put.
pub const METHOD_HANDLE_TYPE_STATIC_PUT: u8 = 0x00;
/// Method handle type: static get.
pub const METHOD_HANDLE_TYPE_STATIC_GET: u8 = 0x01;
/// Method handle type: instance put.
pub const METHOD_HANDLE_TYPE_INSTANCE_PUT: u8 = 0x02;
/// Method handle type: instance get.
pub const METHOD_HANDLE_TYPE_INSTANCE_GET: u8 = 0x03;
/// Method handle type: invoke static.
pub const METHOD_HANDLE_TYPE_INVOKE_STATIC: u8 = 0x04;
/// Method handle type: invoke instance.
pub const METHOD_HANDLE_TYPE_INVOKE_INSTANCE: u8 = 0x05;
/// Method handle type: invoke constructor.
pub const METHOD_HANDLE_TYPE_INVOKE_CONSTRUCTOR: u8 = 0x06;
/// Method handle type: invoke direct.
pub const METHOD_HANDLE_TYPE_INVOKE_DIRECT: u8 = 0x07;
/// Method handle type: invoke interface.
pub const METHOD_HANDLE_TYPE_INVOKE_INTERFACE: u8 = 0x08;

/// Returns a human-readable name for a method handle type value.
pub fn method_handle_type_name(handle_type: u8) -> &'static str {
    match handle_type {
        METHOD_HANDLE_TYPE_STATIC_PUT => "STATIC_PUT",
        METHOD_HANDLE_TYPE_STATIC_GET => "STATIC_GET",
        METHOD_HANDLE_TYPE_INSTANCE_PUT => "INSTANCE_PUT",
        METHOD_HANDLE_TYPE_INSTANCE_GET => "INSTANCE_GET",
        METHOD_HANDLE_TYPE_INVOKE_STATIC => "INVOKE_STATIC",
        METHOD_HANDLE_TYPE_INVOKE_INSTANCE => "INVOKE_INSTANCE",
        METHOD_HANDLE_TYPE_INVOKE_CONSTRUCTOR => "INVOKE_CONSTRUCTOR",
        METHOD_HANDLE_TYPE_INVOKE_DIRECT => "INVOKE_DIRECT",
        METHOD_HANDLE_TYPE_INVOKE_INTERFACE => "INVOKE_INTERFACE",
        _ => "UNKNOWN",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Helper: compute a standard debug info opcode's line delta
// ═══════════════════════════════════════════════════════════════════════════════════

/// Compute the line delta for a standard DEX debug info opcode.
///
/// Returns `None` if the opcode is not a standard opcode (i.e., < DBG_FIRST_SPECIAL).
pub fn standard_opcode_line_delta(opcode: u8) -> Option<i32> {
    if opcode < DBG_FIRST_SPECIAL {
        return None;
    }
    let adjusted = (opcode - DBG_FIRST_SPECIAL) as i32;
    Some(DBG_LINE_BASE + (adjusted % DBG_LINE_RANGE as i32))
}

/// Compute the PC advance for a standard DEX debug info opcode.
///
/// Returns `None` if the opcode is not a standard opcode.
pub fn standard_opcode_pc_advance(opcode: u8) -> Option<u32> {
    if opcode < DBG_FIRST_SPECIAL {
        return None;
    }
    let adjusted = (opcode - DBG_FIRST_SPECIAL) as u32;
    Some(adjusted / DBG_LINE_RANGE)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_opcodes() {
        assert_eq!(DBG_END_SEQUENCE, 0x00);
        assert_eq!(DBG_ADVANCE_PC, 0x01);
        assert_eq!(DBG_SET_FILE, 0x09);
        assert_eq!(DBG_FIRST_SPECIAL, 0x0a);
    }

    #[test]
    fn test_value_types() {
        assert_eq!(VALUE_BYTE, 0x00);
        assert_eq!(VALUE_STRING, 0x17);
        assert_eq!(VALUE_BOOLEAN, 0x1f);
    }

    #[test]
    fn test_visibility_names() {
        assert_eq!(visibility_name(VISIBILITY_BUILD), "BUILD");
        assert_eq!(visibility_name(VISIBILITY_RUNTIME), "RUNTIME");
        assert_eq!(visibility_name(VISIBILITY_SYSTEM), "SYSTEM");
        assert_eq!(visibility_name(0xFF), "UNKNOWN");
    }

    #[test]
    fn test_method_handle_type_names() {
        assert_eq!(method_handle_type_name(METHOD_HANDLE_TYPE_STATIC_PUT), "STATIC_PUT");
        assert_eq!(
            method_handle_type_name(METHOD_HANDLE_TYPE_INVOKE_INTERFACE),
            "INVOKE_INTERFACE"
        );
    }

    #[test]
    fn test_standard_opcode_line_delta() {
        // First special opcode: adjusted=0, delta = -4 + (0 % 15) = -4
        assert_eq!(standard_opcode_line_delta(DBG_FIRST_SPECIAL), Some(-4));
        // Opcode 0x19: adjusted = 0x19 - 0x0a = 15, delta = -4 + (15 % 15) = -4
        assert_eq!(standard_opcode_line_delta(0x19), Some(-4));
        // Opcode 0x0a + 1: adjusted=1, delta = -4 + 1 = -3
        assert_eq!(standard_opcode_line_delta(0x0b), Some(-3));
        // Not a standard opcode
        assert_eq!(standard_opcode_line_delta(0x01), None);
    }

    #[test]
    fn test_standard_opcode_pc_advance() {
        // First special opcode: adjusted=0, pc_advance = 0 / 15 = 0
        assert_eq!(standard_opcode_pc_advance(DBG_FIRST_SPECIAL), Some(0));
        // Opcode 0x19: adjusted = 15, pc_advance = 15 / 15 = 1
        assert_eq!(standard_opcode_pc_advance(0x19), Some(1));
        // Not a standard opcode
        assert_eq!(standard_opcode_pc_advance(0x01), None);
    }
}
