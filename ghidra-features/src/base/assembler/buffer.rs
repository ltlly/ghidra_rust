//! Assembly buffer for multi-instruction assembly.
//!
//! Corresponds to Java's `AssemblyBuffer`.

use super::assembler_trait::Assembler;
use super::errors::AssemblerResult;
use crate::base::analyzer::core::Address;

/// A buffer that accumulates assembled instructions.
///
/// The typical use case is to assemble several instructions in sequence
/// and then retrieve the resulting byte block:
///
/// ```
/// # use ghidra_features::base::assembler::buffer::AssemblyBuffer;
/// # use ghidra_features::base::assembler::assembler_trait::Assembler;
/// # use ghidra_features::base::assembler::selector::AssemblySelector;
/// # use ghidra_features::base::assembler::sleigh::sem::AssemblyPatternBlock;
/// # use ghidra_features::base::assembler::errors::AssemblerResult;
/// # use ghidra_features::base::analyzer::core::{Address, Language, Program};
/// # use ghidra_features::base::assembler::sleigh::parse::AssemblyParseResult;
/// # use ghidra_features::base::assembler::sleigh::sem::AssemblyResolutionResults;
/// # struct MockAsm;
/// # impl Assembler for MockAsm {
/// #   fn get_language(&self) -> &Language { unimplemented!() }
/// #   fn get_program(&self) -> Option<&Program> { None }
/// #   fn assemble(&mut self, _: Address, _: &[&str]) -> AssemblerResult<AssembledInstructions> { unimplemented!() }
/// #   fn assemble_line(&mut self, _: Address, _: &str) -> AssemblerResult<Vec<u8>> { Ok(vec![0x90]) }
/// #   fn assemble_line_with_context(&mut self, _: Address, _: &str, _: &AssemblyPatternBlock) -> AssemblerResult<Vec<u8>> { Ok(vec![0x90]) }
/// #   fn parse_line(&self, _: &str) -> Vec<AssemblyParseResult> { vec![] }
/// #   fn resolve_tree(&self, _: &AssemblyParseResult, _: Address, _: &AssemblyPatternBlock) -> AssemblyResolutionResults { AssemblyResolutionResults::new() }
/// #   fn resolve_line(&mut self, _: Address, _: &str, _: &AssemblyPatternBlock) -> AssemblerResult<AssemblyResolutionResults> { Ok(AssemblyResolutionResults::new()) }
/// #   fn get_context_at(&self, _: Address) -> AssemblyPatternBlock { AssemblyPatternBlock::new_empty(0) }
/// # }
/// let entry = Address::new(0x0040_0000);
/// let mut buf = AssemblyBuffer::new(Box::new(MockAsm), entry);
/// buf.assemble("NOP").unwrap();
/// assert_eq!(buf.get_bytes(), &[0x90]);
/// ```
pub struct AssemblyBuffer {
    bytes: Vec<u8>,
    asm: Box<dyn Assembler>,
    entry: Address,
}

impl AssemblyBuffer {
    /// Create a buffer with the given assembler starting at the given entry.
    pub fn new(asm: Box<dyn Assembler>, entry: Address) -> Self {
        Self {
            bytes: Vec::new(),
            asm,
            entry,
        }
    }

    /// Get the address of the "cursor" where the next instruction will be assembled.
    pub fn next_address(&self) -> Address {
        self.entry.add(self.bytes.len() as u64)
    }

    /// Assemble a line and append the resulting bytes to the buffer.
    pub fn assemble(&mut self, line: &str) -> AssemblerResult<()> {
        let at = self.next_address();
        let ins_bytes = self.asm.assemble_line(at, line)?;
        self.bytes.extend_from_slice(&ins_bytes);
        Ok(())
    }

    /// Assemble a line and patch into the buffer at the given address.
    ///
    /// This will not grow the buffer -- the instruction being patched
    /// must already exist.  Typical use case is to fix up a forward
    /// reference.
    pub fn assemble_at(&mut self, at: Address, line: &str) -> AssemblerResult<()> {
        let ins_bytes = self.asm.assemble_line(at, line)?;
        let offset = at.offset.saturating_sub(self.entry.offset) as usize;
        if offset + ins_bytes.len() > self.bytes.len() {
            return Err(super::errors::AssemblyError(
                "Patch location extends beyond buffer".to_string(),
            )
            .into());
        }
        self.bytes[offset..offset + ins_bytes.len()].copy_from_slice(&ins_bytes);
        Ok(())
    }

    /// Retrieve a copy of all assembled bytes.
    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the buffer and return the assembled bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Return the current length of the buffer in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Get a reference to the underlying assembler.
    pub fn assembler(&self) -> &dyn Assembler {
        self.asm.as_ref()
    }

    /// Get a mutable reference to the underlying assembler.
    pub fn assembler_mut(&mut self) -> &mut dyn Assembler {
        self.asm.as_mut()
    }
}
