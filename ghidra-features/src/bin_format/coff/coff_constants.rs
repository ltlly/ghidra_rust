//! COFF constants ported from Ghidra's `ghidra.app.util.bin.format.coff.CoffConstants`.

/// Max length (in bytes) of an in-place section name.
pub const SECTION_NAME_LENGTH: usize = 8;

/// Max length (in bytes) of an in-place symbol name.
pub const SYMBOL_NAME_LENGTH: usize = 8;

/// Length (in bytes) of a symbol data structure.
pub const SYMBOL_SIZEOF: usize = 18;

/// Max-length (in bytes) of a file name.
pub const FILE_NAME_LENGTH: usize = 14;

/// Number of dimensions of a symbol's auxiliary array.
pub const AUXILIARY_ARRAY_DIMENSION: usize = 4;
