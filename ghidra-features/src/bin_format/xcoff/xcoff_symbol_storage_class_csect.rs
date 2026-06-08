//! XCOFF csect storage mapping class constants ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffSymbolStorageClassCSECT`.
//!
//! Provides the `x_smclas` (storage mapping class) values used in
//! XCOFF csect auxiliary entries.

/// Program code.
pub const XMC_PR: u8 = 0;

/// Read only constant.
pub const XMC_RO: u8 = 1;

/// Debug dictionary table.
pub const XMC_DB: u8 = 2;

/// General TOC entry.
pub const XMC_TC: u8 = 3;

/// Unclassified.
pub const XMC_UA: u8 = 4;

/// Read/write data.
pub const XMC_RW: u8 = 5;

/// Global linkage.
pub const XMC_GL: u8 = 6;

/// Extended operation.
pub const XMC_XO: u8 = 7;

/// 32-bit supervisor call descriptor csect.
pub const XMC_SV: u8 = 8;

/// BSS class (uninitialized static internal).
pub const XMC_BS: u8 = 9;

/// Csect containing a function descriptor.
pub const XMC_DS: u8 = 10;

/// Unnamed FORTRAN common.
pub const XMC_UC: u8 = 11;

/// Reserved.
pub const XMC_TI: u8 = 12;

/// Reserved.
pub const XMC_TB: u8 = 13;

/// TOC anchor for TOC addressability.
pub const XMC_TC0: u8 = 15;

/// Scalar data entry in TOC.
pub const XMC_TD: u8 = 16;

/// 64-bit supervisor call descriptor csect.
pub const XMC_SV64: u8 = 17;

/// Supervisor call descriptor csect for both 32-bit and 64-bit.
pub const XMC_SV3264: u8 = 18;
