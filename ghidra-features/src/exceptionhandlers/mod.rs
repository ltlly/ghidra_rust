//! GCC Exception Handlers
//!
//! Ported from `ghidra.app.plugin.exceptionhandlers`.
//!
//! This module provides analysis and parsing of GCC/DWARF exception handling
//! structures including `.eh_frame`, `.eh_frame_hdr`, `.debug_frame`, and
//! the GCC exception table (`.gcc_except_table`).

pub mod gcc;
