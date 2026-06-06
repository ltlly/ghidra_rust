//! Program examiner for analysis summary and statistics.
//!
//! Ported from `ghidra.program.examiner`.
//!
//! Provides [`ProgramExaminer`] for collecting summary statistics about
//! a program (instruction count, function count, memory layout, etc.).

// ---------------------------------------------------------------------------
// ProgramExaminer
// ---------------------------------------------------------------------------

/// Collects and reports summary statistics about a program.
#[derive(Debug, Clone, Default)]
pub struct ProgramExaminer {
    /// Program name.
    name: String,
    /// Number of memory blocks.
    block_count: usize,
    /// Total memory size in bytes.
    total_memory: u64,
    /// Number of defined functions.
    function_count: usize,
    /// Number of instructions.
    instruction_count: usize,
    /// Number of data items.
    data_count: usize,
    /// Number of symbols.
    symbol_count: usize,
    /// Number of bookmarks.
    bookmark_count: usize,
    /// Number of comments.
    comment_count: usize,
    /// Number of cross-references.
    xref_count: usize,
}

impl ProgramExaminer {
    /// Create a new examiner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the program name.
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    /// Set memory block count.
    pub fn with_block_count(mut self, count: usize) -> Self {
        self.block_count = count;
        self
    }

    /// Set total memory size.
    pub fn with_total_memory(mut self, bytes: u64) -> Self {
        self.total_memory = bytes;
        self
    }

    /// Set function count.
    pub fn with_function_count(mut self, count: usize) -> Self {
        self.function_count = count;
        self
    }

    /// Set instruction count.
    pub fn with_instruction_count(mut self, count: usize) -> Self {
        self.instruction_count = count;
        self
    }

    /// Set data item count.
    pub fn with_data_count(mut self, count: usize) -> Self {
        self.data_count = count;
        self
    }

    /// Set symbol count.
    pub fn with_symbol_count(mut self, count: usize) -> Self {
        self.symbol_count = count;
        self
    }

    /// Set bookmark count.
    pub fn with_bookmark_count(mut self, count: usize) -> Self {
        self.bookmark_count = count;
        self
    }

    /// Set comment count.
    pub fn with_comment_count(mut self, count: usize) -> Self {
        self.comment_count = count;
        self
    }

    /// Set cross-reference count.
    pub fn with_xref_count(mut self, count: usize) -> Self {
        self.xref_count = count;
        self
    }

    // -- Getters --

    /// The program name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Number of memory blocks.
    pub fn block_count(&self) -> usize {
        self.block_count
    }
    /// Total memory in bytes.
    pub fn total_memory(&self) -> u64 {
        self.total_memory
    }
    /// Number of functions.
    pub fn function_count(&self) -> usize {
        self.function_count
    }
    /// Number of instructions.
    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }
    /// Number of data items.
    pub fn data_count(&self) -> usize {
        self.data_count
    }
    /// Number of symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbol_count
    }
    /// Number of bookmarks.
    pub fn bookmark_count(&self) -> usize {
        self.bookmark_count
    }
    /// Number of comments.
    pub fn comment_count(&self) -> usize {
        self.comment_count
    }
    /// Number of cross-references.
    pub fn xref_count(&self) -> usize {
        self.xref_count
    }

    /// Generate a human-readable summary string.
    pub fn summary(&self) -> String {
        format!(
            "Program: {name}\n\
             Memory Blocks: {blocks}\n\
             Total Memory: {mem} bytes\n\
             Functions: {funcs}\n\
             Instructions: {instr}\n\
             Data Items: {data}\n\
             Symbols: {syms}\n\
             Bookmarks: {bms}\n\
             Comments: {comments}\n\
             Cross-References: {xrefs}",
            name = self.name,
            blocks = self.block_count,
            mem = self.total_memory,
            funcs = self.function_count,
            instr = self.instruction_count,
            data = self.data_count,
            syms = self.symbol_count,
            bms = self.bookmark_count,
            comments = self.comment_count,
            xrefs = self.xref_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_examiner_default() {
        let e = ProgramExaminer::new();
        assert_eq!(e.name(), "");
        assert_eq!(e.block_count(), 0);
        assert_eq!(e.function_count(), 0);
    }

    #[test]
    fn test_examiner_builder() {
        let e = ProgramExaminer::new()
            .with_name("test.exe")
            .with_block_count(3)
            .with_total_memory(0x10000)
            .with_function_count(42)
            .with_instruction_count(1000)
            .with_data_count(50)
            .with_symbol_count(200)
            .with_bookmark_count(5)
            .with_comment_count(30)
            .with_xref_count(150);

        assert_eq!(e.name(), "test.exe");
        assert_eq!(e.block_count(), 3);
        assert_eq!(e.total_memory(), 0x10000);
        assert_eq!(e.function_count(), 42);
        assert_eq!(e.instruction_count(), 1000);
        assert_eq!(e.data_count(), 50);
        assert_eq!(e.symbol_count(), 200);
        assert_eq!(e.bookmark_count(), 5);
        assert_eq!(e.comment_count(), 30);
        assert_eq!(e.xref_count(), 150);
    }

    #[test]
    fn test_examiner_summary() {
        let e = ProgramExaminer::new()
            .with_name("hello.elf")
            .with_function_count(10)
            .with_instruction_count(100);

        let summary = e.summary();
        assert!(summary.contains("hello.elf"));
        assert!(summary.contains("Functions: 10"));
        assert!(summary.contains("Instructions: 100"));
    }
}
