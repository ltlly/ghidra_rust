//! System emulation framework for P-code based emulation.
//!
//! Ported from Ghidra's `SystemEmulation` feature.
//!
//! Provides:
//!
//! - **Syscall emulation**: OS-level syscall handlers (Linux, Windows) that
//!   can be loaded into a P-code emulator.
//! - **P-code emulation engine**: A simple CPU-emulation loop that executes
//!   P-code operations, including memory read/write, register access,
//!   and breakpoint management.
//! - **Structured SLEIGH**: A programmatic API for building SLEIGH snippets
//!   (conditional statements, loops, assignments) without writing raw
//!   SLEIGH source.
//! - **Thread model**: Basic multi-threaded emulation support.

pub mod pcode_emu;
pub mod syscall;
pub mod structured_sleigh;

pub use pcode_emu::*;
pub use syscall::*;
pub use structured_sleigh::*;
