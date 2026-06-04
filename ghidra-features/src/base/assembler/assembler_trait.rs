//! Core assembler traits.
//!
//! Corresponds to Java's `GenericAssembler` and `Assembler` interfaces.

use super::errors::AssemblerResult;
use crate::base::analyzer::core::{Address, Language, Program};
use crate::base::assembler::sleigh::parse::AssemblyParseResult;
use crate::base::assembler::sleigh::sem::{
    AssemblyPatternBlock, AssemblyResolutionResults,
};

/// A placeholder for an instruction iterator.
///
/// In the full Ghidra this would iterate over program instructions.
/// Here we provide a simplified version that holds assembled bytes.
#[derive(Debug, Clone)]
pub struct AssembledInstructions {
    /// The starting address.
    pub address: Address,
    /// The assembled bytes.
    pub bytes: Vec<u8>,
}

/// The primary trait for performing assembly.
///
/// Corresponds to Java's `GenericAssembler<RP>`.  The type parameter
/// `RP` is the resolved-patterns type; in the SLEIGH-based
/// implementation this is `AssemblyResolvedPatterns`.
pub trait Assembler: Send + Sync {
    /// Get the language of this assembler.
    fn get_language(&self) -> &Language;

    /// If the assembler is bound to a program, get that program.
    fn get_program(&self) -> Option<&Program>;

    /// Assemble a sequence of instructions and place them at the given address.
    ///
    /// This is only valid when the assembler is bound to a program.
    fn assemble(
        &mut self,
        at: Address,
        listing: &[&str],
    ) -> AssemblerResult<AssembledInstructions>;

    /// Assemble a single line at the given address.
    ///
    /// This is valid with or without a bound program.  Even when bound,
    /// the program is not modified; the appropriate context information
    /// is taken from the bound program or the language's default context.
    fn assemble_line(&mut self, at: Address, line: &str) -> AssemblerResult<Vec<u8>>;

    /// Assemble a single line with an explicit context.
    fn assemble_line_with_context(
        &mut self,
        at: Address,
        line: &str,
        ctx: &AssemblyPatternBlock,
    ) -> AssemblerResult<Vec<u8>>;

    /// Parse a textual assembly line into one or more parse results.
    fn parse_line(&self, line: &str) -> Vec<AssemblyParseResult>;

    /// Resolve a parse tree to machine code.
    fn resolve_tree(
        &self,
        parse: &AssemblyParseResult,
        at: Address,
        ctx: &AssemblyPatternBlock,
    ) -> AssemblyResolutionResults;

    /// Resolve all parse trees for a line.
    fn resolve_line(
        &mut self,
        at: Address,
        line: &str,
        ctx: &AssemblyPatternBlock,
    ) -> AssemblerResult<AssemblyResolutionResults>;

    /// Get the assembly context at the given address.
    fn get_context_at(&self, addr: Address) -> AssemblyPatternBlock;
}
