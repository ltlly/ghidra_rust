//! Memory state management for P-code emulation.
//!
//! Ported from Java: `ghidra.pcode.memstate`.
//!
//! This module provides the memory bank abstraction used by the legacy
//! emulation framework.

pub mod memory_bank;
pub mod memory_page;
pub mod memory_fault_handler;

pub use memory_bank::MemoryBank;
pub use memory_page::MemoryPage;
pub use memory_fault_handler::MemoryFaultHandler;
