//! Ghidra's assembler framework.
//!
//! This module ports the assembler framework from Ghidra's
//! `ghidra.app.plugin.assembler` and `ghidra.app.plugin.core.assembler`
//! Java packages.
//!
//! ## Overview
//!
//! The assembler converts textual assembly instructions into binary
//! machine code.  The primary entry point is through the
//! [`Assembler`] trait (implemented by [`sleigh::SleighAssembler`])
//! or via the [`AssemblyBuffer`] convenience wrapper.
//!
//! ## Architecture
//!
//! The framework is split into several layers:
//!
//! - **Core traits**: [`Assembler`] and [`AssemblerBuilder`] define
//!   the interface for performing and constructing assemblers.
//! - **Selection**: [`AssemblySelector`] prunes and selects from
//!   multiple candidate encodings.
//! - **Buffer**: [`AssemblyBuffer`] accumulates assembled instructions
//!   for multi-instruction sequences.
//! - **SLEIGH**: [`sleigh::`] implements the full SLEIGH-based
//!   assembler pipeline (tokenisation, parsing, resolution).
//! - **Errors**: [`errors::`] defines all error types.
//! - **Actions**: [`actions::`] provides UI action types for
//!   patching instructions and data.
//!
//! ## Quick Start
//!
//! ```ignore
//! use ghidra_features::base::assembler::*;
//! use ghidra_features::base::analyzer::core::Address;
//!
//! // Obtain an assembler (implementation-dependent)
//! let mut asm = create_assembler_for_my_lang();
//!
//! // Assemble a single instruction
//! let bytes = asm.assemble_line(Address::new(0x400000), "NOP").unwrap();
//! assert_eq!(bytes, vec![0x90]);
//!
//! // Use the buffer for multiple instructions
//! let mut buf = AssemblyBuffer::new(Box::new(asm), Address::new(0x400000));
//! buf.assemble("PUSH R0").unwrap();
//! buf.assemble("PUSH R1").unwrap();
//! let code = buf.into_bytes();
//! ```

pub mod assembler_trait;
pub mod buffer;
pub mod builder;
pub mod errors;
pub mod selector;
pub mod sleigh;
pub mod actions;

// Re-export core types for convenience.
pub use assembler_trait::{AssembledInstructions, Assembler};
pub use buffer::AssemblyBuffer;
pub use builder::AssemblerBuilder;
pub use errors::{
    AssemblerError, AssemblerResult, AssemblyError, AssemblySemanticException,
    AssemblySelectionError, AssemblySyntaxException,
};
pub use selector::{AssemblySelector, Selection};
