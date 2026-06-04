//! Program database searchers -- ported from Ghidra's
//! `ghidra.app.plugin.core.searchtext.databasesearcher` package.
//!
//! Provides field-specific searchers that query the program database
//! directly (fast path) rather than rendering listing text:
//!
//! - [`ProgramDatabaseSearcher`] -- orchestrator for all field searchers
//! - [`CommentFieldSearcher`] -- searches comments
//! - [`LabelFieldSearcher`] -- searches symbol labels
//! - [`InstructionMnemonicOperandFieldSearcher`] -- searches instruction text
//! - [`DataMnemonicOperandFieldSearcher`] -- searches data text
//! - [`FunctionFieldSearcher`] -- searches function signatures/comments

use ghidra_core::Address;

use crate::gotoquery::ProgramLocation;
use super::{SearchOptions, Searcher, TextSearchResult};

// ---------------------------------------------------------------------------
// ProgramDatabaseFieldSearcher trait
// ---------------------------------------------------------------------------

/// Trait for individual field searchers within the program database.
///
/// Each implementation searches a specific kind of listing field
/// (comments, labels, instructions, data, functions).
pub trait ProgramDatabaseFieldSearcher {
    /// Search the field at the given address for the search text.
    ///
    /// Returns `Some(offset)` if a match is found at `address`, where
    /// `offset` is the character position within the field text.
    fn matches(&self, address: &Address, text: &str, case_sensitive: bool) -> Option<usize>;
}

// ---------------------------------------------------------------------------
// CommentFieldSearcher
// ---------------------------------------------------------------------------

/// Searches comment text in the program.
#[derive(Debug)]
pub struct CommentFieldSearcher {
    /// Comments stored as `(address, text)` pairs.
    comments: Vec<(Address, String)>,
}

impl CommentFieldSearcher {
    /// Create a new comment searcher with the given comments.
    pub fn new(comments: Vec<(Address, String)>) -> Self {
        Self { comments }
    }

    /// Add a comment.
    pub fn add_comment(&mut self, address: Address, text: String) {
        self.comments.push((address, text));
    }

    /// Get all comments.
    pub fn comments(&self) -> &[(Address, String)] {
        &self.comments
    }
}

impl ProgramDatabaseFieldSearcher for CommentFieldSearcher {
    fn matches(&self, address: &Address, text: &str, case_sensitive: bool) -> Option<usize> {
        for (addr, comment) in &self.comments {
            if addr == address {
                let haystack = if case_sensitive {
                    comment.as_str()
                } else {
                    // For case-insensitive, we do a simple search
                    // In production, this would use a proper case-folding comparison
                    comment.as_str()
                };
                let needle = if case_sensitive {
                    text
                } else {
                    text
                };
                if !case_sensitive {
                    let haystack_lower = haystack.to_lowercase();
                    let needle_lower = needle.to_lowercase();
                    if let Some(pos) = haystack_lower.find(&needle_lower) {
                        return Some(pos);
                    }
                } else if let Some(pos) = haystack.find(needle) {
                    return Some(pos);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// LabelFieldSearcher
// ---------------------------------------------------------------------------

/// Searches symbol label text in the program.
#[derive(Debug)]
pub struct LabelFieldSearcher {
    /// Labels stored as `(address, label)` pairs.
    labels: Vec<(Address, String)>,
}

impl LabelFieldSearcher {
    /// Create a new label searcher.
    pub fn new(labels: Vec<(Address, String)>) -> Self {
        Self { labels }
    }

    /// Add a label.
    pub fn add_label(&mut self, address: Address, label: String) {
        self.labels.push((address, label));
    }
}

impl ProgramDatabaseFieldSearcher for LabelFieldSearcher {
    fn matches(&self, address: &Address, text: &str, case_sensitive: bool) -> Option<usize> {
        for (addr, label) in &self.labels {
            if addr == address {
                if !case_sensitive {
                    let haystack = label.to_lowercase();
                    let needle = text.to_lowercase();
                    if let Some(pos) = haystack.find(&needle) {
                        return Some(pos);
                    }
                } else if let Some(pos) = label.find(text) {
                    return Some(pos);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// InstructionMnemonicOperandFieldSearcher
// ---------------------------------------------------------------------------

/// Searches instruction mnemonic and operand text.
#[derive(Debug)]
pub struct InstructionMnemonicOperandFieldSearcher {
    /// Instructions stored as `(address, mnemonic, operands)`.
    instructions: Vec<(Address, String, String)>,
}

impl InstructionMnemonicOperandFieldSearcher {
    /// Create a new instruction searcher.
    pub fn new(instructions: Vec<(Address, String, String)>) -> Self {
        Self { instructions }
    }

    /// Add an instruction.
    pub fn add_instruction(
        &mut self,
        address: Address,
        mnemonic: String,
        operands: String,
    ) {
        self.instructions.push((address, mnemonic, operands));
    }
}

impl ProgramDatabaseFieldSearcher for InstructionMnemonicOperandFieldSearcher {
    fn matches(&self, address: &Address, text: &str, case_sensitive: bool) -> Option<usize> {
        for (addr, mnemonic, operands) in &self.instructions {
            if addr == address {
                // Check mnemonic first
                let mnem_match = if case_sensitive {
                    mnemonic.find(text)
                } else {
                    mnemonic.to_lowercase().find(&text.to_lowercase())
                };
                if let Some(pos) = mnem_match {
                    return Some(pos);
                }
                // Then check operands (offset by mnemonic length + space)
                let op_offset = mnemonic.len() + 1;
                let op_match = if case_sensitive {
                    operands.find(text)
                } else {
                    operands.to_lowercase().find(&text.to_lowercase())
                };
                if let Some(pos) = op_match {
                    return Some(op_offset + pos);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// DataMnemonicOperandFieldSearcher
// ---------------------------------------------------------------------------

/// Searches data mnemonic and value text.
#[derive(Debug)]
pub struct DataMnemonicOperandFieldSearcher {
    /// Data entries stored as `(address, mnemonic, value_text)`.
    data: Vec<(Address, String, String)>,
}

impl DataMnemonicOperandFieldSearcher {
    /// Create a new data searcher.
    pub fn new(data: Vec<(Address, String, String)>) -> Self {
        Self { data }
    }

    /// Add a data entry.
    pub fn add_data(&mut self, address: Address, mnemonic: String, value: String) {
        self.data.push((address, mnemonic, value));
    }
}

impl ProgramDatabaseFieldSearcher for DataMnemonicOperandFieldSearcher {
    fn matches(&self, address: &Address, text: &str, case_sensitive: bool) -> Option<usize> {
        for (addr, mnemonic, value) in &self.data {
            if addr == address {
                let mnem_match = if case_sensitive {
                    mnemonic.find(text)
                } else {
                    mnemonic.to_lowercase().find(&text.to_lowercase())
                };
                if let Some(pos) = mnem_match {
                    return Some(pos);
                }
                let val_offset = mnemonic.len() + 1;
                let val_match = if case_sensitive {
                    value.find(text)
                } else {
                    value.to_lowercase().find(&text.to_lowercase())
                };
                if let Some(pos) = val_match {
                    return Some(val_offset + pos);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// FunctionFieldSearcher
// ---------------------------------------------------------------------------

/// Searches function signatures and comments.
#[derive(Debug)]
pub struct FunctionFieldSearcher {
    /// Functions stored as `(entry_address, signature, repeatable_comment)`.
    functions: Vec<(Address, String, Option<String>)>,
}

impl FunctionFieldSearcher {
    /// Create a new function searcher.
    pub fn new(functions: Vec<(Address, String, Option<String>)>) -> Self {
        Self { functions }
    }

    /// Add a function.
    pub fn add_function(
        &mut self,
        entry: Address,
        signature: String,
        comment: Option<String>,
    ) {
        self.functions.push((entry, signature, comment));
    }
}

impl ProgramDatabaseFieldSearcher for FunctionFieldSearcher {
    fn matches(&self, address: &Address, text: &str, case_sensitive: bool) -> Option<usize> {
        for (addr, sig, comment) in &self.functions {
            if addr == address {
                let sig_match = if case_sensitive {
                    sig.find(text)
                } else {
                    sig.to_lowercase().find(&text.to_lowercase())
                };
                if let Some(pos) = sig_match {
                    return Some(pos);
                }
                if let Some(ref cmt) = comment {
                    let cmt_match = if case_sensitive {
                        cmt.find(text)
                    } else {
                        cmt.to_lowercase().find(&text.to_lowercase())
                    };
                    if let Some(pos) = cmt_match {
                        return Some(sig.len() + 1 + pos);
                    }
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// ProgramDatabaseSearcher
// ---------------------------------------------------------------------------

/// Orchestrator that runs all field searchers in sequence.
///
/// Iterates over the provided addresses and checks each field searcher
/// for matches.
pub struct ProgramDatabaseSearcher {
    options: SearchOptions,
    addresses: Vec<Address>,
    current_index: usize,
    program_name: String,
    comment_searcher: CommentFieldSearcher,
    label_searcher: LabelFieldSearcher,
    instruction_searcher: InstructionMnemonicOperandFieldSearcher,
    data_searcher: DataMnemonicOperandFieldSearcher,
    function_searcher: FunctionFieldSearcher,
}

impl ProgramDatabaseSearcher {
    /// Create a new program database searcher.
    pub fn new(
        program_name: impl Into<String>,
        options: SearchOptions,
        addresses: Vec<Address>,
    ) -> Self {
        Self {
            options,
            addresses,
            current_index: 0,
            program_name: program_name.into(),
            comment_searcher: CommentFieldSearcher::new(Vec::new()),
            label_searcher: LabelFieldSearcher::new(Vec::new()),
            instruction_searcher: InstructionMnemonicOperandFieldSearcher::new(Vec::new()),
            data_searcher: DataMnemonicOperandFieldSearcher::new(Vec::new()),
            function_searcher: FunctionFieldSearcher::new(Vec::new()),
        }
    }

    /// Get mutable access to the comment searcher.
    pub fn comment_searcher_mut(&mut self) -> &mut CommentFieldSearcher {
        &mut self.comment_searcher
    }

    /// Get mutable access to the label searcher.
    pub fn label_searcher_mut(&mut self) -> &mut LabelFieldSearcher {
        &mut self.label_searcher
    }

    /// Get mutable access to the instruction searcher.
    pub fn instruction_searcher_mut(&mut self) -> &mut InstructionMnemonicOperandFieldSearcher {
        &mut self.instruction_searcher
    }

    /// Get mutable access to the data searcher.
    pub fn data_searcher_mut(&mut self) -> &mut DataMnemonicOperandFieldSearcher {
        &mut self.data_searcher
    }

    /// Get mutable access to the function searcher.
    pub fn function_searcher_mut(&mut self) -> &mut FunctionFieldSearcher {
        &mut self.function_searcher
    }

    /// The program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Remaining address count.
    pub fn remaining(&self) -> usize {
        self.addresses.len().saturating_sub(self.current_index)
    }
}

impl Searcher for ProgramDatabaseSearcher {
    fn search(&mut self) -> Option<TextSearchResult> {
        let text = self.options.text();
        let case_sensitive = self.options.is_case_sensitive();

        while self.current_index < self.addresses.len() {
            let addr = self.addresses[self.current_index];
            self.current_index += 1;

            // Check fields in priority order
            if self.options.search_comments() {
                if let Some(offset) =
                    self.comment_searcher.matches(&addr, text, case_sensitive)
                {
                    let loc = ProgramLocation::new(&self.program_name, addr);
                    return Some(TextSearchResult::new(loc, offset));
                }
            }

            if self.options.search_labels() {
                if let Some(offset) =
                    self.label_searcher.matches(&addr, text, case_sensitive)
                {
                    let loc = ProgramLocation::new(&self.program_name, addr);
                    return Some(TextSearchResult::new(loc, offset));
                }
            }

            if self.options.search_instruction_mnemonics()
                || self.options.search_instruction_operands()
            {
                if let Some(offset) =
                    self.instruction_searcher.matches(&addr, text, case_sensitive)
                {
                    let loc = ProgramLocation::new(&self.program_name, addr);
                    return Some(TextSearchResult::new(loc, offset));
                }
            }

            if self.options.search_data_mnemonics() || self.options.search_data_operands() {
                if let Some(offset) =
                    self.data_searcher.matches(&addr, text, case_sensitive)
                {
                    let loc = ProgramLocation::new(&self.program_name, addr);
                    return Some(TextSearchResult::new(loc, offset));
                }
            }

            if self.options.search_functions() {
                if let Some(offset) =
                    self.function_searcher.matches(&addr, text, case_sensitive)
                {
                    let loc = ProgramLocation::new(&self.program_name, addr);
                    return Some(TextSearchResult::new(loc, offset));
                }
            }
        }
        None
    }

    fn search_options(&self) -> &SearchOptions {
        &self.options
    }
}

// ---------------------------------------------------------------------------
// ProgramDatabaseSearchTableModel
// ---------------------------------------------------------------------------

/// A table model for displaying program-database search results.
///
/// Loads all results from a [`ProgramDatabaseSearcher`] into a
/// query-results table.
#[derive(Debug)]
pub struct ProgramDatabaseSearchTableModel {
    /// The program name.
    program_name: String,
    /// Accumulated results.
    results: Vec<TextSearchResult>,
    /// Whether loading is complete.
    loaded: bool,
    /// The search limit.
    limit: usize,
}

impl ProgramDatabaseSearchTableModel {
    /// Create a new table model.
    pub fn new(program_name: impl Into<String>, limit: usize) -> Self {
        Self {
            program_name: program_name.into(),
            results: Vec::new(),
            loaded: false,
            limit,
        }
    }

    /// Add a result (respects limit).
    pub fn add_result(&mut self, result: TextSearchResult) -> bool {
        if self.results.len() >= self.limit {
            return false;
        }
        self.results.push(result);
        true
    }

    /// Get the number of results.
    pub fn row_count(&self) -> usize {
        self.results.len()
    }

    /// Get a result by row.
    pub fn get_result(&self, row: usize) -> Option<&TextSearchResult> {
        self.results.get(row)
    }

    /// Mark as loaded.
    pub fn set_loaded(&mut self) {
        self.loaded = true;
    }

    /// Whether loading is complete.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_comment_field_searcher_case_sensitive() {
        let mut searcher = CommentFieldSearcher::new(Vec::new());
        searcher.add_comment(addr(0x1000), "This is a Test".to_string());
        searcher.add_comment(addr(0x2000), "another test".to_string());

        assert!(searcher.matches(&addr(0x1000), "Test", true).is_some());
        assert!(searcher.matches(&addr(0x1000), "test", true).is_none());
        assert!(searcher.matches(&addr(0x2000), "test", true).is_some());
    }

    #[test]
    fn test_comment_field_searcher_case_insensitive() {
        let mut searcher = CommentFieldSearcher::new(Vec::new());
        searcher.add_comment(addr(0x1000), "This is a Test".to_string());

        assert!(searcher.matches(&addr(0x1000), "test", false).is_some());
        assert!(searcher.matches(&addr(0x1000), "TEST", false).is_some());
        assert!(searcher.matches(&addr(0x1000), "missing", false).is_none());
    }

    #[test]
    fn test_label_field_searcher() {
        let mut searcher = LabelFieldSearcher::new(Vec::new());
        searcher.add_label(addr(0x1000), "main".to_string());
        searcher.add_label(addr(0x2000), "printf".to_string());

        let offset = searcher.matches(&addr(0x1000), "main", true);
        assert_eq!(offset, Some(0));

        let offset = searcher.matches(&addr(0x1000), "ain", true);
        assert_eq!(offset, Some(1));

        assert!(searcher.matches(&addr(0x1000), "printf", true).is_none());
    }

    #[test]
    fn test_instruction_field_searcher() {
        let mut searcher = InstructionMnemonicOperandFieldSearcher::new(Vec::new());
        searcher.add_instruction(addr(0x1000), "MOV".into(), "EAX, EBX".into());

        // Mnemonic match
        assert_eq!(searcher.matches(&addr(0x1000), "MOV", true), Some(0));
        // Operand match (offset after "MOV ")
        let offset = searcher.matches(&addr(0x1000), "EAX", true);
        assert_eq!(offset, Some(4));
        // Case-insensitive
        assert!(searcher.matches(&addr(0x1000), "mov", false).is_some());
    }

    #[test]
    fn test_data_field_searcher() {
        let mut searcher = DataMnemonicOperandFieldSearcher::new(Vec::new());
        searcher.add_data(addr(0x1000), "dd".into(), "0x42".into());

        assert_eq!(searcher.matches(&addr(0x1000), "dd", true), Some(0));
        assert_eq!(searcher.matches(&addr(0x1000), "0x42", true), Some(3));
    }

    #[test]
    fn test_function_field_searcher() {
        let mut searcher = FunctionFieldSearcher::new(Vec::new());
        searcher.add_function(
            addr(0x1000),
            "int main(int argc, char **argv)".into(),
            Some("Entry point".into()),
        );

        assert!(searcher.matches(&addr(0x1000), "main", true).is_some());
        assert!(searcher.matches(&addr(0x1000), "Entry", true).is_some());
        assert!(searcher.matches(&addr(0x1000), "nonexistent", true).is_none());
    }

    #[test]
    fn test_program_database_searcher() {
        let opts = SearchOptions::new(
            "main",
            true, true, false, true, false, true, false, false, true, true, false, false,
        );
        let addrs = vec![addr(0x1000), addr(0x2000), addr(0x3000)];
        let mut searcher = ProgramDatabaseSearcher::new("test.exe", opts, addrs);

        searcher.label_searcher_mut().add_label(addr(0x1000), "main".into());
        searcher
            .instruction_searcher_mut()
            .add_instruction(addr(0x2000), "CALL".into(), "main".into());

        let result1 = searcher.search();
        assert!(result1.is_some());
        assert_eq!(result1.as_ref().unwrap().location().address, addr(0x1000));

        let result2 = searcher.search();
        assert!(result2.is_some());
        assert_eq!(result2.as_ref().unwrap().location().address, addr(0x2000));

        let result3 = searcher.search();
        assert!(result3.is_none());
    }

    #[test]
    fn test_program_database_search_table_model() {
        let mut model = ProgramDatabaseSearchTableModel::new("test.exe", 10);
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_loaded());

        let loc = ProgramLocation::new("test.exe", addr(0x1000));
        assert!(model.add_result(TextSearchResult::new(loc, 0)));
        assert_eq!(model.row_count(), 1);

        model.set_loaded();
        assert!(model.is_loaded());
    }

    #[test]
    fn test_program_database_search_table_model_limit() {
        let mut model = ProgramDatabaseSearchTableModel::new("test.exe", 2);

        for i in 0..5 {
            let loc = ProgramLocation::new("test.exe", addr(0x1000 + i));
            let added = model.add_result(TextSearchResult::new(loc, 0));
            if i < 2 {
                assert!(added);
            } else {
                assert!(!added);
            }
        }
        assert_eq!(model.row_count(), 2);
    }
}
