//! PcodeStepper - p-code step-by-step execution model.
//!
//! Ported from Ghidra's `DebuggerPcodeStepperPlugin` and `PcodeStepperProvider`
//! in `ghidra.app.plugin.core.debug.gui.pcode`.
//!
//! Provides the data model for stepping through individual p-code operations
//! during emulation, displaying p-code row details and tracking execution state.

use serde::{Deserialize, Serialize};

/// The type of a p-code operation in the stepper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcodeStepperOpType {
    /// A standard p-code operation.
    Normal,
    /// A branch operation.
    Branch,
    /// A call/return operation.
    Call,
    /// A load/store memory operation.
    Memory,
    /// A register operation.
    Register,
    /// A conditional branch.
    ConditionalBranch,
    /// An interrupt/trap.
    Interrupt,
}

/// A p-code operation step with full detail for the stepper UI.
///
/// Ported from Ghidra's p-code stepper display types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeStepperEntry {
    /// The sequential index of this p-code operation.
    pub index: u64,
    /// The p-code operation mnemonic (e.g., "INT_ADD", "STORE").
    pub mnemonic: String,
    /// The input varnodes (serialized as hex strings).
    pub inputs: Vec<String>,
    /// The output varnode (serialized as hex string), if any.
    pub output: Option<String>,
    /// The address of the instruction this p-code belongs to.
    pub instruction_address: u64,
    /// The sequence number within the instruction.
    pub sequence_number: u32,
    /// The operation type category.
    pub op_type: PcodeStepperOpType,
    /// Whether this operation has been executed.
    pub executed: bool,
    /// The result value after execution, if available.
    pub result_value: Option<Vec<u8>>,
}

impl PcodeStepperEntry {
    /// Create a new p-code stepper entry.
    pub fn new(
        index: u64,
        mnemonic: impl Into<String>,
        instruction_address: u64,
        sequence_number: u32,
    ) -> Self {
        Self {
            index,
            mnemonic: mnemonic.into(),
            inputs: Vec::new(),
            output: None,
            instruction_address,
            sequence_number,
            op_type: PcodeStepperOpType::Normal,
            executed: false,
            result_value: None,
        }
    }

    /// Add an input varnode description.
    pub fn with_input(mut self, input: impl Into<String>) -> Self {
        self.inputs.push(input.into());
        self
    }

    /// Set the output varnode description.
    pub fn with_output(mut self, output: impl Into<String>) -> Self {
        self.output = Some(output.into());
        self
    }

    /// Set the operation type.
    pub fn with_op_type(mut self, op_type: PcodeStepperOpType) -> Self {
        self.op_type = op_type;
        self
    }

    /// Mark as executed with a result.
    pub fn mark_executed(&mut self, result: Vec<u8>) {
        self.executed = true;
        self.result_value = Some(result);
    }

    /// Format the p-code operation as a string.
    pub fn format_operation(&self) -> String {
        let out = self.output.as_deref().unwrap_or("-");
        let inputs = self.inputs.join(", ");
        format!("{} = {}({})", out, self.mnemonic, inputs)
    }
}

/// The state of the p-code stepper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum StepperState {
    /// Stepper is idle (not running).
    #[default]
    Idle,
    /// Stepper is running (single-step mode).
    Stepping,
    /// Stepper is running (continuous run mode).
    Running,
    /// Stepper is paused (breakpoint hit).
    Paused,
    /// Stepper has finished (execution complete).
    Finished,
}

/// Extended p-code stepper model with full execution tracking.
///
/// Ported from Ghidra's `DebuggerPcodeStepperProvider`.
/// This complements the simpler `PcodeStepperExecutionModel` in `gui_pcode` by adding
/// execution state tracking, navigation, and result recording.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcodeStepperExecutionModel {
    /// All p-code entries for the current instruction.
    pub entries: Vec<PcodeStepperEntry>,
    /// The currently focused entry index.
    pub current_index: usize,
    /// The stepper state.
    pub state: StepperState,
    /// Total number of p-code operations executed so far.
    pub total_executed: u64,
    /// The current instruction address.
    pub current_instruction: u64,
}

impl PcodeStepperExecutionModel {
    /// Create a new stepper model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a p-code entry.
    pub fn add_entry(&mut self, entry: PcodeStepperEntry) {
        self.entries.push(entry);
    }

    /// Get the current entry.
    pub fn current_entry(&self) -> Option<&PcodeStepperEntry> {
        self.entries.get(self.current_index)
    }

    /// Advance to the next entry.
    pub fn step_forward(&mut self) -> bool {
        if self.current_index + 1 < self.entries.len() {
            self.current_index += 1;
            self.total_executed += 1;
            true
        } else {
            false
        }
    }

    /// Go back to the previous entry.
    pub fn step_back(&mut self) -> bool {
        if self.current_index > 0 {
            self.current_index -= 1;
            true
        } else {
            false
        }
    }

    /// Reset the stepper.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.current_index = 0;
        self.state = StepperState::Idle;
        self.total_executed = 0;
    }

    /// Start stepping.
    pub fn start(&mut self) {
        self.state = StepperState::Stepping;
    }

    /// Pause the stepper.
    pub fn pause(&mut self) {
        self.state = StepperState::Paused;
    }

    /// Finish the stepper.
    pub fn finish(&mut self) {
        self.state = StepperState::Finished;
    }

    /// Whether there are entries to navigate.
    pub fn has_entries(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Get total entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the stepper is running.
    pub fn is_running(&self) -> bool {
        matches!(self.state, StepperState::Stepping | StepperState::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stepper_entry_new() {
        let entry = PcodeStepperEntry::new(0, "INT_ADD", 0x400000, 0)
            .with_input("register:RAX")
            .with_input("register:RBX")
            .with_output("register:RAX");
        assert_eq!(entry.mnemonic, "INT_ADD");
        assert_eq!(entry.inputs.len(), 2);
        assert!(entry.output.is_some());
    }

    #[test]
    fn test_stepper_entry_format() {
        let entry = PcodeStepperEntry::new(0, "INT_ADD", 0x400000, 0)
            .with_input("RAX")
            .with_input("RBX")
            .with_output("RCX");
        let s = entry.format_operation();
        assert!(s.contains("INT_ADD"));
        assert!(s.contains("RCX"));
    }

    #[test]
    fn test_stepper_entry_mark_executed() {
        let mut entry = PcodeStepperEntry::new(0, "STORE", 0x400000, 1);
        assert!(!entry.executed);
        entry.mark_executed(vec![0x42]);
        assert!(entry.executed);
        assert_eq!(entry.result_value, Some(vec![0x42]));
    }

    #[test]
    fn test_stepper_model_navigation() {
        let mut model = PcodeStepperExecutionModel::new();
        model.add_entry(PcodeStepperEntry::new(0, "COPY", 0x400000, 0));
        model.add_entry(PcodeStepperEntry::new(1, "INT_ADD", 0x400000, 1));
        model.add_entry(PcodeStepperEntry::new(2, "STORE", 0x400000, 2));

        assert_eq!(model.current_entry().unwrap().mnemonic, "COPY");
        assert!(model.step_forward());
        assert_eq!(model.current_entry().unwrap().mnemonic, "INT_ADD");
        assert!(model.step_forward());
        assert_eq!(model.current_entry().unwrap().mnemonic, "STORE");
        assert!(!model.step_forward()); // at end
    }

    #[test]
    fn test_stepper_model_step_back() {
        let mut model = PcodeStepperExecutionModel::new();
        model.add_entry(PcodeStepperEntry::new(0, "COPY", 0x400000, 0));
        model.add_entry(PcodeStepperEntry::new(1, "STORE", 0x400000, 1));
        model.current_index = 1;

        assert!(model.step_back());
        assert_eq!(model.current_index, 0);
        assert!(!model.step_back()); // at beginning
    }

    #[test]
    fn test_stepper_model_state() {
        let mut model = PcodeStepperExecutionModel::new();
        assert_eq!(model.state, StepperState::Idle);
        assert!(!model.is_running());

        model.start();
        assert!(model.is_running());
        assert_eq!(model.state, StepperState::Stepping);

        model.pause();
        assert!(!model.is_running());

        model.finish();
        assert_eq!(model.state, StepperState::Finished);
    }

    #[test]
    fn test_stepper_model_reset() {
        let mut model = PcodeStepperExecutionModel::new();
        model.add_entry(PcodeStepperEntry::new(0, "COPY", 0x400000, 0));
        model.step_forward();
        model.start();

        model.reset();
        assert!(model.entries.is_empty());
        assert_eq!(model.current_index, 0);
        assert_eq!(model.state, StepperState::Idle);
    }

    #[test]
    fn test_stepper_op_types() {
        let entry = PcodeStepperEntry::new(0, "CBRANCH", 0x400000, 0)
            .with_op_type(PcodeStepperOpType::ConditionalBranch);
        assert_eq!(entry.op_type, PcodeStepperOpType::ConditionalBranch);
    }

    #[test]
    fn test_stepper_model_serde() {
        let mut model = PcodeStepperExecutionModel::new();
        model.add_entry(PcodeStepperEntry::new(0, "COPY", 0x400000, 0));
        model.start();

        let json = serde_json::to_string(&model).unwrap();
        let back: PcodeStepperExecutionModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert!(back.is_running());
    }

    #[test]
    fn test_stepper_no_output() {
        let entry = PcodeStepperEntry::new(0, "STORE", 0x400000, 0)
            .with_input("addr:0x1000");
        let s = entry.format_operation();
        assert!(s.starts_with('-'));
    }
}
