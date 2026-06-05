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
/// # use ghidra_features::base::assembler::assembler_trait::{Assembler, AssembledInstructions};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::core::{Language, Program};
    use crate::base::assembler::assembler_trait::{AssembledInstructions, Assembler};
    use crate::base::assembler::errors::AssemblerResult;
    use crate::base::assembler::selector::AssemblySelector;
    use crate::base::assembler::sleigh::parse::AssemblyParseResult;
    use crate::base::assembler::sleigh::sem::{AssemblyPatternBlock, AssemblyResolutionResults};

    /// A mock assembler for testing.
    struct MockAssembler {
        /// Each NOP-like instruction emits one byte (0x90).
        /// Instructions starting with "0x" emit that hex byte.
        nop_byte: u8,
    }

    impl MockAssembler {
        fn new() -> Self {
            Self { nop_byte: 0x90 }
        }
    }

    impl std::fmt::Debug for MockAssembler {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockAssembler").finish()
        }
    }

    impl Assembler for MockAssembler {
        fn get_language(&self) -> &Language {
            unimplemented!("not needed for buffer tests")
        }

        fn get_program(&self) -> Option<&Program> {
            None
        }

        fn assemble(
            &mut self,
            _addr: Address,
            _lines: &[&str],
        ) -> AssemblerResult<AssembledInstructions> {
            unimplemented!()
        }

        fn assemble_line(&mut self, _addr: Address, line: &str) -> AssemblerResult<Vec<u8>> {
            if line.starts_with("0x") {
                let byte = u8::from_str_radix(&line[2..4], 16)
                    .map_err(|e| crate::base::assembler::errors::AssemblyError(e.to_string()))?;
                Ok(vec![byte])
            } else {
                Ok(vec![self.nop_byte])
            }
        }

        fn assemble_line_with_context(
            &mut self,
            addr: Address,
            line: &str,
            _ctx: &AssemblyPatternBlock,
        ) -> AssemblerResult<Vec<u8>> {
            self.assemble_line(addr, line)
        }

        fn parse_line(&self, _line: &str) -> Vec<AssemblyParseResult> {
            vec![]
        }

        fn resolve_tree(
            &self,
            _parse: &AssemblyParseResult,
            _addr: Address,
            _ctx: &AssemblyPatternBlock,
        ) -> AssemblyResolutionResults {
            AssemblyResolutionResults::new()
        }

        fn resolve_line(
            &mut self,
            _addr: Address,
            _line: &str,
            _ctx: &AssemblyPatternBlock,
        ) -> AssemblerResult<AssemblyResolutionResults> {
            Ok(AssemblyResolutionResults::new())
        }

        fn get_context_at(&self, _addr: Address) -> AssemblyPatternBlock {
            AssemblyPatternBlock::new_empty(0)
        }
    }

    fn mock_buffer(addr: u64) -> AssemblyBuffer {
        AssemblyBuffer::new(Box::new(MockAssembler::new()), Address::new(addr))
    }

    #[test]
    fn test_new_buffer_is_empty() {
        let buf = mock_buffer(0x400000);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.get_bytes(), &[] as &[u8]);
    }

    #[test]
    fn test_next_address_initial() {
        let buf = mock_buffer(0x400000);
        assert_eq!(buf.next_address().offset, 0x400000);
    }

    #[test]
    fn test_assemble_appends_bytes() {
        let mut buf = mock_buffer(0x400000);
        buf.assemble("NOP").unwrap();
        assert_eq!(buf.get_bytes(), &[0x90]);
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_assemble_multiple() {
        let mut buf = mock_buffer(0x400000);
        buf.assemble("NOP").unwrap();
        buf.assemble("NOP").unwrap();
        buf.assemble("NOP").unwrap();
        assert_eq!(buf.get_bytes(), &[0x90, 0x90, 0x90]);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_next_address_advances() {
        let mut buf = mock_buffer(0x400000);
        buf.assemble("NOP").unwrap();
        assert_eq!(buf.next_address().offset, 0x400001);
        buf.assemble("NOP").unwrap();
        assert_eq!(buf.next_address().offset, 0x400002);
    }

    #[test]
    fn test_assemble_custom_byte() {
        let mut buf = mock_buffer(0x400000);
        buf.assemble("0xCC").unwrap();
        assert_eq!(buf.get_bytes(), &[0xCC]);
    }

    #[test]
    fn test_assemble_at_patches() {
        let mut buf = mock_buffer(0x400000);
        buf.assemble("NOP").unwrap();
        buf.assemble("NOP").unwrap();
        buf.assemble("NOP").unwrap();

        // Patch second instruction
        buf.assemble_at(Address::new(0x400001), "0xCC").unwrap();
        assert_eq!(buf.get_bytes(), &[0x90, 0xCC, 0x90]);
    }

    #[test]
    fn test_assemble_at_out_of_bounds() {
        let mut buf = mock_buffer(0x400000);
        buf.assemble("NOP").unwrap();

        // Try to patch at an address beyond the buffer
        let result = buf.assemble_at(Address::new(0x400010), "0xCC");
        assert!(result.is_err());
    }

    #[test]
    fn test_into_bytes_consumes() {
        let mut buf = mock_buffer(0x400000);
        buf.assemble("NOP").unwrap();
        buf.assemble("0xAA").unwrap();

        let bytes = buf.into_bytes();
        assert_eq!(bytes, vec![0x90, 0xAA]);
    }

    #[test]
    fn test_assembler_ref() {
        let buf = mock_buffer(0x400000);
        let _ = buf.assembler();
    }

    #[test]
    fn test_assembler_mut_ref() {
        let mut buf = mock_buffer(0x400000);
        let _ = buf.assembler_mut();
    }
}
