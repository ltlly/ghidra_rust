//! `CodeUnitFilter` -- filters results by code unit type.
//!
//! Ported from `ghidra.features.base.memsearch.searcher.CodeUnitFilter`.

use crate::memsearch::searcher::MemoryMatch;

/// The type of code unit at a match address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeUnitType {
    /// An instruction.
    Instruction,
    /// Defined data (e.g., DWORD, STRING).
    DefinedData,
    /// Undefined data.
    UndefinedData,
}

/// Filter that accepts matches based on the type of code unit at the match address.
///
/// Ported from `CodeUnitFilter.java`.
#[derive(Debug, Clone)]
pub struct CodeUnitFilter {
    include_instructions: bool,
    include_defined_data: bool,
    include_undefined_data: bool,
}

impl CodeUnitFilter {
    /// Create a new code unit filter.
    pub fn new(
        include_instructions: bool,
        include_defined_data: bool,
        include_undefined_data: bool,
    ) -> Self {
        Self {
            include_instructions,
            include_defined_data,
            include_undefined_data,
        }
    }

    /// Create a filter that accepts everything.
    pub fn all() -> Self {
        Self {
            include_instructions: true,
            include_defined_data: true,
            include_undefined_data: true,
        }
    }

    /// Create a filter for instructions only.
    pub fn instructions_only() -> Self {
        Self {
            include_instructions: true,
            include_defined_data: false,
            include_undefined_data: false,
        }
    }

    /// Test if a code unit type is accepted by this filter.
    pub fn accepts_type(&self, code_unit_type: CodeUnitType) -> bool {
        match code_unit_type {
            CodeUnitType::Instruction => self.include_instructions,
            CodeUnitType::DefinedData => self.include_defined_data,
            CodeUnitType::UndefinedData => self.include_undefined_data,
        }
    }

    /// Filter matches by their code unit type.
    ///
    /// The `type_lookup` function determines the code unit type at each match address.
    pub fn filter(
        &self,
        matches: &[MemoryMatch],
        type_lookup: impl Fn(u64) -> CodeUnitType,
    ) -> Vec<MemoryMatch> {
        if self.include_instructions && self.include_defined_data && self.include_undefined_data {
            return matches.to_vec();
        }
        matches
            .iter()
            .filter(|m| self.accepts_type(type_lookup(m.address())))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_filter() {
        let filter = CodeUnitFilter::all();
        assert!(filter.accepts_type(CodeUnitType::Instruction));
        assert!(filter.accepts_type(CodeUnitType::DefinedData));
        assert!(filter.accepts_type(CodeUnitType::UndefinedData));
    }

    #[test]
    fn test_instructions_only() {
        let filter = CodeUnitFilter::instructions_only();
        assert!(filter.accepts_type(CodeUnitType::Instruction));
        assert!(!filter.accepts_type(CodeUnitType::DefinedData));
        assert!(!filter.accepts_type(CodeUnitType::UndefinedData));
    }

    #[test]
    fn test_filter_matches() {
        let filter = CodeUnitFilter::instructions_only();
        let matches = vec![
            MemoryMatch::new(0x1000, vec![0x55]),
            MemoryMatch::new(0x2000, vec![0x89]),
            MemoryMatch::new(0x3000, vec![0xE5]),
        ];
        let filtered = filter.filter(&matches, |addr| match addr {
            0x1000 => CodeUnitType::Instruction,
            0x2000 => CodeUnitType::DefinedData,
            _ => CodeUnitType::UndefinedData,
        });
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].address(), 0x1000);
    }
}
