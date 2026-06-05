//! EH Frame and GCC Exception Table Structures
//!
//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.structures`.
//!
//! Provides data structures for `.eh_frame` (CIE, FDE, FdeTable) and
//! `.gcc_except_table` (LSDA header, call site table, action table, type table).

pub mod eh_frame;
pub mod gcc_except_table;
