//! Symbolic Summary Z3 Analyzer.
//!
//! Ported from `SymbolicSummaryZ3Analyzer.java` in the SymbolicSummaryZ3
//! extension.
//!
//! This analyzer performs symbolic execution of functions using Z3
//! bit-vector expressions, producing symbolic summaries that capture
//! register valuations, memory writes, and path conditions.

use super::lib_z3::{Z3InfixPrinter, Z3MemoryWitness};
use super::state::{
    SymZ3MemorySpace, SymZ3PcodeEmulator, SymZ3PcodeExecutorState, SymZ3Preconditions,
    SymZ3RegisterSpace,
};
use super::{SymValueZ3, SymZ3PcodeArithmetic};

// ---------------------------------------------------------------------------
// SymbolicSummaryZ3AnalyzerConfig
// ---------------------------------------------------------------------------

/// Configuration for the symbolic summary Z3 analyzer.
#[derive(Debug, Clone)]
pub struct SymbolicSummaryZ3AnalyzerConfig {
    /// Maximum number of instructions to execute symbolically.
    pub max_instructions: usize,
    /// Maximum number of p-code operations to execute.
    pub max_pcode_ops: usize,
    /// Whether to record the instruction log.
    pub record_instruction_log: bool,
    /// Whether to record the p-code operation log.
    pub record_pcode_log: bool,
    /// Whether to generate infix-notation summaries.
    pub use_infix_notation: bool,
    /// Whether to track memory witnesses (reads/writes).
    pub track_memory_witness: bool,
}

impl Default for SymbolicSummaryZ3AnalyzerConfig {
    fn default() -> Self {
        Self {
            max_instructions: 1000,
            max_pcode_ops: 10000,
            record_instruction_log: true,
            record_pcode_log: true,
            use_infix_notation: true,
            track_memory_witness: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolicSummaryZ3AnalyzerResult
// ---------------------------------------------------------------------------

/// Result of a symbolic summary Z3 analysis.
#[derive(Debug)]
pub struct SymbolicSummaryZ3AnalyzerResult {
    /// The symbolic state summary text.
    pub state_summary: String,
    /// Memory witness tracking reads and writes.
    pub memory_witness: Z3MemoryWitness,
    /// Instruction log entries.
    pub instruction_log: Vec<String>,
    /// P-code operation log entries.
    pub pcode_log: Vec<String>,
    /// The symbolic summary text.
    pub summary_text: String,
    /// Number of instructions executed.
    pub instructions_executed: usize,
    /// Number of p-code operations executed.
    pub pcode_ops_executed: usize,
    /// Whether execution was truncated due to limits.
    pub truncated: bool,
    /// Preconditions (path conditions) discovered during execution.
    pub preconditions: Vec<String>,
}

impl SymbolicSummaryZ3AnalyzerResult {
    /// Get the summary text in infix notation.
    pub fn infix_summary(&self) -> String {
        Z3InfixPrinter::infix(&self.summary_text)
    }

    /// Get a human-readable report.
    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Symbolic Summary Z3 Analysis Report ===\n\n");

        out.push_str(&format!(
            "Instructions executed: {}\n",
            self.instructions_executed
        ));
        out.push_str(&format!(
            "P-code ops executed: {}\n",
            self.pcode_ops_executed
        ));
        if self.truncated {
            out.push_str("*** Execution was truncated ***\n");
        }
        out.push('\n');

        // Register state
        out.push_str(&self.state_summary);
        out.push('\n');

        // Memory witness
        if self.memory_witness.read_count() > 0 || self.memory_witness.write_count() > 0 {
            out.push_str(&self.memory_witness.printable_summary());
            out.push('\n');
        }

        // Preconditions
        if !self.preconditions.is_empty() {
            out.push_str("=== Preconditions ===\n");
            for (i, p) in self.preconditions.iter().enumerate() {
                out.push_str(&format!("  [{i}] {p}\n"));
            }
        }

        out
    }
}

// ---------------------------------------------------------------------------
// SymbolicSummaryZ3Analyzer
// ---------------------------------------------------------------------------

/// Analyzer that performs symbolic execution using Z3 bit-vector expressions.
///
/// This analyzer runs a p-code emulator with symbolic Z3 summarization,
/// translating each p-code operation into Z3 constraints and recording
/// the resulting symbolic state.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::symbolic_z3::symbolic_summary_z3_analyzer::{
///     SymbolicSummaryZ3Analyzer, SymbolicSummaryZ3AnalyzerConfig,
/// };
///
/// let config = SymbolicSummaryZ3AnalyzerConfig::default();
/// let mut analyzer = SymbolicSummaryZ3Analyzer::new("x86:LE:64:default", false, config);
///
/// // Simulate executing some p-code operations
/// analyzer.record_instruction(0x401000, "MOV RAX, 42");
/// analyzer.set_register("RAX", 0x42, 64);
///
/// let result = analyzer.finish();
/// assert!(result.summary_text.contains("RAX"));
/// ```
pub struct SymbolicSummaryZ3Analyzer {
    /// The p-code emulator.
    emulator: SymZ3PcodeEmulator,
    /// The p-code arithmetic engine.
    arithmetic: SymZ3PcodeArithmetic,
    /// Memory witness for tracking reads/writes.
    memory_witness: Z3MemoryWitness,
    /// Instruction log.
    instruction_log: Vec<String>,
    /// P-code operation log.
    pcode_log: Vec<String>,
    /// Analysis configuration.
    config: SymbolicSummaryZ3AnalyzerConfig,
    /// Number of instructions processed.
    instructions_executed: usize,
    /// Number of p-code operations processed.
    pcode_ops_executed: usize,
    /// Whether execution was truncated.
    truncated: bool,
}

impl SymbolicSummaryZ3Analyzer {
    /// Create a new symbolic summary Z3 analyzer.
    pub fn new(
        language: impl Into<String>,
        big_endian: bool,
        config: SymbolicSummaryZ3AnalyzerConfig,
    ) -> Self {
        Self {
            emulator: SymZ3PcodeEmulator::new(language, big_endian),
            arithmetic: SymZ3PcodeArithmetic::for_endian(big_endian),
            memory_witness: Z3MemoryWitness::new(),
            instruction_log: Vec::new(),
            pcode_log: Vec::new(),
            config,
            instructions_executed: 0,
            pcode_ops_executed: 0,
            truncated: false,
        }
    }

    /// Record an instruction at the given address.
    ///
    /// Returns `false` if the instruction limit has been reached.
    pub fn record_instruction(&mut self, address: u64, mnemonic: &str) -> bool {
        if self.instructions_executed >= self.config.max_instructions {
            self.truncated = true;
            return false;
        }

        if self.config.record_instruction_log {
            self.instruction_log
                .push(format!("0x{address:08x}: {mnemonic}"));
        }
        self.instructions_executed += 1;
        true
    }

    /// Record a p-code operation.
    ///
    /// Returns `false` if the p-code op limit has been reached.
    pub fn record_pcode_op(
        &mut self,
        mnemonic: &str,
        output: Option<&str>,
        inputs: &[&str],
    ) -> bool {
        if self.pcode_ops_executed >= self.config.max_pcode_ops {
            self.truncated = true;
            return false;
        }

        if self.config.record_pcode_log {
            let inputs_str = inputs.join(", ");
            let output_str = output.unwrap_or("none");
            self.pcode_log
                .push(format!("{mnemonic}({inputs_str}) -> {output_str}"));
        }
        self.pcode_ops_executed += 1;
        true
    }

    /// Set a register to a symbolic value.
    pub fn set_register(&mut self, _name: &str, value: u64, size_bits: u32) {
        let sym_val = self.arithmetic.from_const_u64(value, size_bits / 8);
        self.emulator
            .shared_state_mut()
            .registers_mut()
            .set_register(0, size_bits, sym_val);
    }

    /// Set a register to a symbolic variable.
    pub fn set_register_symbolic(&mut self, name: &str, size_bits: u32) {
        let sym_val = SymValueZ3::from_variable(name, size_bits);
        self.emulator
            .shared_state_mut()
            .registers_mut()
            .set_register(0, size_bits, sym_val);
    }

    /// Store a value to symbolic memory.
    pub fn store_memory(&mut self, address: u64, value: u64, size_bits: u32) {
        let sym_val = self.arithmetic.from_const_u64(value, size_bits / 8);
        if self.config.track_memory_witness {
            self.memory_witness.record_write(
                format!("0x{address:08x}"),
                format!("{sym_val}"),
                size_bits / 8,
            );
        }
        self.emulator
            .shared_state_mut()
            .memory_mut()
            .store(address, sym_val);
    }

    /// Record a memory read.
    pub fn record_memory_read(&mut self, address: u64, value: &SymValueZ3, size_bytes: u32) {
        if self.config.track_memory_witness {
            self.memory_witness.record_read(
                format!("0x{address:08x}"),
                format!("{value}"),
                size_bytes,
            );
        }
    }

    /// Add a precondition (path condition).
    pub fn add_precondition(&mut self, condition: impl Into<String>) {
        self.emulator
            .shared_state_mut()
            .preconditions_mut()
            .add(condition);
    }

    /// Execute a symbolic binary operation.
    ///
    /// Applies the p-code operation to the given symbolic inputs and
    /// returns the result.
    pub fn execute_binary_op(
        &self,
        opcode: u32,
        sizeout: u32,
        in1: &SymValueZ3,
        in2: &SymValueZ3,
    ) -> SymValueZ3 {
        self.arithmetic.binary_op(opcode, sizeout, in1, in2)
    }

    /// Execute a symbolic unary operation.
    pub fn execute_unary_op(
        &self,
        opcode: u32,
        sizeout: u32,
        in1: &SymValueZ3,
    ) -> SymValueZ3 {
        self.arithmetic.unary_op(opcode, sizeout, in1)
    }

    /// Get the current shared state.
    pub fn shared_state(&self) -> &SymZ3PcodeExecutorState {
        self.emulator.shared_state()
    }

    /// Get the current shared state (mutable).
    pub fn shared_state_mut(&mut self) -> &mut SymZ3PcodeExecutorState {
        self.emulator.shared_state_mut()
    }

    /// Finalize the analysis and produce the result.
    pub fn finish(self) -> SymbolicSummaryZ3AnalyzerResult {
        let summary_text = self.emulator.shared_state().printable_summary();

        SymbolicSummaryZ3AnalyzerResult {
            state_summary: self.emulator.shared_state().printable_summary(),
            memory_witness: self.memory_witness,
            instruction_log: self.instruction_log,
            pcode_log: self.pcode_log,
            summary_text,
            instructions_executed: self.instructions_executed,
            pcode_ops_executed: self.pcode_ops_executed,
            truncated: self.truncated,
            preconditions: self
                .emulator
                .shared_state()
                .preconditions()
                .get_all()
                .to_vec(),
        }
    }

    /// Get the language name.
    pub fn language(&self) -> &str {
        self.emulator.language()
    }

    /// Whether the analyzer uses big-endian arithmetic.
    pub fn is_big_endian(&self) -> bool {
        self.emulator.is_big_endian()
    }

    /// Get the number of instructions executed so far.
    pub fn instructions_executed(&self) -> usize {
        self.instructions_executed
    }

    /// Get the number of p-code operations executed so far.
    pub fn pcode_ops_executed(&self) -> usize {
        self.pcode_ops_executed
    }

    /// Whether execution was truncated.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl std::fmt::Debug for SymbolicSummaryZ3Analyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolicSummaryZ3Analyzer")
            .field("language", &self.emulator.language())
            .field("big_endian", &self.emulator.is_big_endian())
            .field("instructions_executed", &self.instructions_executed)
            .field("pcode_ops_executed", &self.pcode_ops_executed)
            .field("truncated", &self.truncated)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::state::SymZ3Space;

    fn make_analyzer() -> SymbolicSummaryZ3Analyzer {
        SymbolicSummaryZ3Analyzer::new(
            "x86:LE:64:default",
            false,
            SymbolicSummaryZ3AnalyzerConfig::default(),
        )
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = make_analyzer();
        assert_eq!(analyzer.language(), "x86:LE:64:default");
        assert!(!analyzer.is_big_endian());
        assert_eq!(analyzer.instructions_executed(), 0);
        assert_eq!(analyzer.pcode_ops_executed(), 0);
        assert!(!analyzer.is_truncated());
    }

    #[test]
    fn test_analyzer_big_endian() {
        let analyzer = SymbolicSummaryZ3Analyzer::new(
            "PowerPC:BE:64:default",
            true,
            SymbolicSummaryZ3AnalyzerConfig::default(),
        );
        assert!(analyzer.is_big_endian());
    }

    #[test]
    fn test_record_instruction() {
        let mut analyzer = make_analyzer();
        assert!(analyzer.record_instruction(0x401000, "MOV RAX, 42"));
        assert_eq!(analyzer.instructions_executed(), 1);
        assert!(analyzer.record_instruction(0x401004, "ADD RBX, RAX"));
        assert_eq!(analyzer.instructions_executed(), 2);
    }

    #[test]
    fn test_record_instruction_limit() {
        let config = SymbolicSummaryZ3AnalyzerConfig {
            max_instructions: 2,
            ..Default::default()
        };
        let mut analyzer = SymbolicSummaryZ3Analyzer::new("x86:LE:64:default", false, config);
        assert!(analyzer.record_instruction(0x1000, "NOP"));
        assert!(analyzer.record_instruction(0x1001, "NOP"));
        assert!(!analyzer.record_instruction(0x1002, "NOP"));
        assert!(analyzer.is_truncated());
    }

    #[test]
    fn test_record_pcode_op() {
        let mut analyzer = make_analyzer();
        assert!(analyzer.record_pcode_op("INT_ADD", Some("RAX"), &["RBX", "RCX"]));
        assert_eq!(analyzer.pcode_ops_executed(), 1);
    }

    #[test]
    fn test_record_pcode_op_limit() {
        let config = SymbolicSummaryZ3AnalyzerConfig {
            max_pcode_ops: 1,
            ..Default::default()
        };
        let mut analyzer = SymbolicSummaryZ3Analyzer::new("x86:LE:64:default", false, config);
        assert!(analyzer.record_pcode_op("COPY", Some("RAX"), &["RBX"]));
        assert!(!analyzer.record_pcode_op("COPY", Some("RAX"), &["RBX"]));
        assert!(analyzer.is_truncated());
    }

    #[test]
    fn test_set_register() {
        let mut analyzer = make_analyzer();
        analyzer.set_register("RAX", 0x42, 64);
        let state = analyzer.shared_state();
        assert_eq!(state.registers().entry_count(), 1);
    }

    #[test]
    fn test_set_register_symbolic() {
        let mut analyzer = make_analyzer();
        analyzer.set_register_symbolic("RAX", 64);
        let state = analyzer.shared_state();
        assert_eq!(state.registers().entry_count(), 1);
    }

    #[test]
    fn test_store_memory() {
        let mut analyzer = make_analyzer();
        analyzer.store_memory(0x1000, 0xFF, 8);
        let state = analyzer.shared_state();
        assert_eq!(state.memory().entry_count(), 1);
    }

    #[test]
    fn test_add_precondition() {
        let mut analyzer = make_analyzer();
        analyzer.add_precondition("RAX != 0");
        analyzer.add_precondition("RBX > 10");
        let preconditions = analyzer.shared_state().preconditions();
        assert_eq!(preconditions.get_all().len(), 2);
    }

    #[test]
    fn test_execute_binary_op() {
        let analyzer = make_analyzer();
        let a = SymValueZ3::from_constant(10, 32);
        let b = SymValueZ3::from_constant(20, 32);
        let result = analyzer.execute_binary_op(24, 4, &a, &b); // INT_ADD
        assert!(result.bitvec_expr.unwrap().contains("bvadd"));
    }

    #[test]
    fn test_execute_unary_op() {
        let analyzer = make_analyzer();
        let val = SymValueZ3::from_constant(0xFF, 8);
        let result = analyzer.execute_unary_op(37, 4, &val); // INT_ZEXT
        assert_eq!(result.size_bits, 32);
    }

    #[test]
    fn test_finish() {
        let mut analyzer = make_analyzer();
        analyzer.set_register("RAX", 0x42, 64);
        analyzer.add_precondition("RAX != 0");
        analyzer.record_instruction(0x401000, "MOV RAX, 42");

        let result = analyzer.finish();
        assert!(result.summary_text.contains("Register Space"));
        assert_eq!(result.instructions_executed, 1);
        assert!(!result.truncated);
    }

    #[test]
    fn test_result_report() {
        let mut analyzer = make_analyzer();
        analyzer.set_register("RAX", 0x42, 64);
        let result = analyzer.finish();
        let report = result.report();
        assert!(report.contains("Symbolic Summary Z3 Analysis Report"));
        assert!(report.contains("Instructions executed"));
    }

    #[test]
    fn test_result_infix_summary() {
        let mut analyzer = make_analyzer();
        analyzer.set_register("RAX", 0x42, 64);
        let result = analyzer.finish();
        let _infix = result.infix_summary();
        // Should not panic
    }

    #[test]
    fn test_memory_witness_tracking() {
        let mut analyzer = make_analyzer();
        analyzer.store_memory(0x1000, 0xFF, 8);
        let result = analyzer.finish();
        assert_eq!(result.memory_witness.write_count(), 1);
    }

    #[test]
    fn test_no_memory_witness_tracking() {
        let config = SymbolicSummaryZ3AnalyzerConfig {
            track_memory_witness: false,
            ..Default::default()
        };
        let mut analyzer = SymbolicSummaryZ3Analyzer::new("x86:LE:64:default", false, config);
        analyzer.store_memory(0x1000, 0xFF, 8);
        let result = analyzer.finish();
        assert_eq!(result.memory_witness.write_count(), 0);
    }

    #[test]
    fn test_no_instruction_log() {
        let config = SymbolicSummaryZ3AnalyzerConfig {
            record_instruction_log: false,
            ..Default::default()
        };
        let mut analyzer = SymbolicSummaryZ3Analyzer::new("x86:LE:64:default", false, config);
        analyzer.record_instruction(0x401000, "NOP");
        let result = analyzer.finish();
        assert!(result.instruction_log.is_empty());
    }

    #[test]
    fn test_no_pcode_log() {
        let config = SymbolicSummaryZ3AnalyzerConfig {
            record_pcode_log: false,
            ..Default::default()
        };
        let mut analyzer = SymbolicSummaryZ3Analyzer::new("x86:LE:64:default", false, config);
        analyzer.record_pcode_op("COPY", Some("RAX"), &["RBX"]);
        let result = analyzer.finish();
        assert!(result.pcode_log.is_empty());
    }

    #[test]
    fn test_debug_format() {
        let analyzer = make_analyzer();
        let debug = format!("{:?}", analyzer);
        assert!(debug.contains("SymbolicSummaryZ3Analyzer"));
        assert!(debug.contains("x86:LE:64:default"));
    }

    #[test]
    fn test_config_defaults() {
        let config = SymbolicSummaryZ3AnalyzerConfig::default();
        assert_eq!(config.max_instructions, 1000);
        assert_eq!(config.max_pcode_ops, 10000);
        assert!(config.record_instruction_log);
        assert!(config.record_pcode_log);
        assert!(config.use_infix_notation);
        assert!(config.track_memory_witness);
    }
}
