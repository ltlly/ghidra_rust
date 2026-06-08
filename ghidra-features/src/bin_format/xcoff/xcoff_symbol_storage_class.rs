//! XCOFF symbol storage class constants ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffSymbolStorageClass`.
//!
//! Provides the storage class values used in XCOFF symbol table entries.

/// Symbol table entry marked for deletion.
pub const C_NULL: u8 = 0;

/// External symbol.
pub const C_EXT: u8 = 2;

/// Static symbol (unknown).
pub const C_STAT: u8 = 3;

/// Beginning or end of inner block.
pub const C_BLOCK: u8 = 100;

/// Comment section reference.
pub const C_INFO: u8 = 100;

/// Beginning or end of function.
pub const C_FCN: u8 = 101;

/// Source file name and compiler information.
pub const C_FILE: u8 = 103;

/// Unnamed external symbol.
pub const C_HIDEXT: u8 = 107;

/// Beginning of include file.
pub const C_BINCL: u8 = 108;

/// End of include file.
pub const C_EINCL: u8 = 109;

/// Weak external symbol.
pub const C_WEAKEXT: u8 = 111;

/// End of common block.
pub const C_ECOMM: u8 = 127;

/// Global variable.
pub const C_GSYM: u8 = 128;

/// Automatic variable allocated on stack.
pub const C_LSYM: u8 = 129;

/// Argument to subroutine allocated on stack.
pub const C_PSYM: u8 = 130;

/// Register variable.
pub const C_RSYM: u8 = 131;

/// Argument to function or procedure stored in register.
pub const C_RPSYM: u8 = 132;

/// Statically allocated symbol.
pub const C_STSYM: u8 = 133;

/// Reserved.
pub const C_TCSYM: u8 = 134;

/// Beginning of the common block.
pub const C_BCOMM: u8 = 135;

/// Local member of common block.
pub const C_ECOML: u8 = 136;

/// Declaration of object (type).
pub const C_DECL: u8 = 140;

/// Alternate entry.
pub const C_ENTRY: u8 = 141;

/// Function or procedure.
pub const C_FUN: u8 = 142;

/// Beginning of static block.
pub const C_BSTAT: u8 = 143;

/// End of static block.
pub const C_ESTAT: u8 = 144;
