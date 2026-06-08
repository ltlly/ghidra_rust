//! Wildcard Sleigh assembler implementation.
//!
//! Ported from Ghidra's `WildSleighAssembler` and `WildSleighAssemblerBuilder` Java classes.

/// Information about a wildcard operand.
#[derive(Debug, Clone)]
pub struct WildOperandInfo {
    /// Index of the operand.
    pub operand_index: usize,
    /// Whether this operand is a wildcard (accepts any value).
    pub is_wildcard: bool,
    /// The fixed value if not a wildcard.
    pub fixed_value: Option<u64>,
    /// Display name of the operand.
    pub name: String,
}

impl WildOperandInfo {
    pub fn wildcard(index: usize, name: String) -> Self {
        Self { operand_index: index, is_wildcard: true, fixed_value: None, name }
    }

    pub fn fixed(index: usize, name: String, value: u64) -> Self {
        Self { operand_index: index, is_wildcard: false, fixed_value: Some(value), name }
    }
}

/// Builder for constructing a wildcard Sleigh assembler.
#[derive(Debug)]
pub struct WildSleighAssemblerBuilder {
    /// Language ID (processor + endian + size).
    pub language_id: String,
    /// Whether to enable debug output.
    pub debug: bool,
}

impl WildSleighAssemblerBuilder {
    pub fn new(language_id: &str) -> Self {
        Self { language_id: language_id.to_string(), debug: false }
    }

    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    pub fn build(self) -> WildSleighAssembler {
        WildSleighAssembler {
            language_id: self.language_id,
            debug: self.debug,
            operand_info: Vec::new(),
        }
    }
}

/// A wildcard-aware assembler for Sleigh-defined processors.
#[derive(Debug)]
pub struct WildSleighAssembler {
    /// The target language ID.
    pub language_id: String,
    /// Whether debug output is enabled.
    pub debug: bool,
    /// Operand information.
    pub operand_info: Vec<WildOperandInfo>,
}

impl WildSleighAssembler {
    pub fn builder(language_id: &str) -> WildSleighAssemblerBuilder {
        WildSleighAssemblerBuilder::new(language_id)
    }

    /// Add operand info.
    pub fn add_operand(&mut self, info: WildOperandInfo) {
        self.operand_info.push(info);
    }

    /// Get the number of operands.
    pub fn operand_count(&self) -> usize {
        self.operand_info.len()
    }

    /// Check if any operand is a wildcard.
    pub fn has_wildcards(&self) -> bool {
        self.operand_info.iter().any(|o| o.is_wildcard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let asm = WildSleighAssembler::builder("x86:LE:64:default")
            .with_debug(true)
            .build();
        assert_eq!(asm.language_id, "x86:LE:64:default");
        assert!(asm.debug);
    }

    #[test]
    fn test_operand_info() {
        let wc = WildOperandInfo::wildcard(0, "reg".into());
        assert!(wc.is_wildcard);
        assert!(wc.fixed_value.is_none());

        let fixed = WildOperandInfo::fixed(1, "imm".into(), 42);
        assert!(!fixed.is_wildcard);
        assert_eq!(fixed.fixed_value, Some(42));
    }

    #[test]
    fn test_assembler_operands() {
        let mut asm = WildSleighAssembler::builder("x86:LE:64:default").build();
        assert!(!asm.has_wildcards());
        asm.add_operand(WildOperandInfo::wildcard(0, "dst".into()));
        assert!(asm.has_wildcards());
        assert_eq!(asm.operand_count(), 1);
    }
}
