//! Stack frame data model for the debugger GUI.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.stack` package.
//! Provides the data model for displaying call stacks in the debugger,
//! including frame information, register values at each frame, and
//! unwinding data.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The type of a stack frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StackFrameType {
    /// A normal function frame.
    Normal,
    /// A signal handler frame.
    Signal,
    /// An inline frame.
    Inline,
    /// A synthetic frame (e.g., trampoline).
    Synthetic,
    /// A frame that could not be unwound.
    Unknown,
}

/// A register value at a specific stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameRegisterValue {
    /// The register name.
    pub name: String,
    /// The register value as bytes (big-endian).
    pub value: Vec<u8>,
    /// Whether this register's value is known.
    pub known: bool,
}

impl FrameRegisterValue {
    /// Create a new register value.
    pub fn new(name: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            value,
            known: true,
        }
    }

    /// Create an unknown register value.
    pub fn unknown(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Vec::new(),
            known: false,
        }
    }

    /// Get the value as a u64 (little-endian interpretation).
    pub fn as_u64_le(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            Some(u64::from_le_bytes(self.value[..8].try_into().unwrap()))
        } else if self.value.len() >= 4 {
            Some(u32::from_le_bytes(self.value[..4].try_into().unwrap()) as u64)
        } else {
            None
        }
    }
}

/// A single frame in a call stack.
///
/// Ported from Ghidra's stack frame display model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameEntry {
    /// The frame level (0 = innermost).
    pub level: usize,
    /// The program counter for this frame.
    pub pc: u64,
    /// The stack pointer for this frame.
    pub sp: u64,
    /// The frame pointer (if available).
    pub fp: Option<u64>,
    /// The return address.
    pub return_address: Option<u64>,
    /// The function name at this frame.
    pub function_name: String,
    /// The function offset from start.
    pub function_offset: u64,
    /// The frame type.
    pub frame_type: StackFrameType,
    /// Register values at this frame.
    pub registers: BTreeMap<String, FrameRegisterValue>,
    /// Whether the frame information is trusted.
    pub trusted: bool,
}

impl StackFrameEntry {
    /// Create a new stack frame entry.
    pub fn new(level: usize, pc: u64, sp: u64) -> Self {
        Self {
            level,
            pc,
            sp,
            fp: None,
            return_address: None,
            function_name: String::new(),
            function_offset: 0,
            frame_type: StackFrameType::Normal,
            registers: BTreeMap::new(),
            trusted: true,
        }
    }

    /// Set the function name.
    pub fn with_function(mut self, name: impl Into<String>, offset: u64) -> Self {
        self.function_name = name.into();
        self.function_offset = offset;
        self
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = Some(fp);
        self
    }

    /// Set the return address.
    pub fn with_return_address(mut self, ra: u64) -> Self {
        self.return_address = Some(ra);
        self
    }

    /// Set the frame type.
    pub fn with_type(mut self, frame_type: StackFrameType) -> Self {
        self.frame_type = frame_type;
        self
    }

    /// Add a register value.
    pub fn with_register(mut self, reg: FrameRegisterValue) -> Self {
        self.registers.insert(reg.name.clone(), reg);
        self
    }

    /// Get a register value by name.
    pub fn get_register(&self, name: &str) -> Option<&FrameRegisterValue> {
        self.registers.get(name)
    }

    /// Get the display string for the function.
    pub fn function_display(&self) -> String {
        if self.function_name.is_empty() {
            format!("0x{:x}", self.pc)
        } else if self.function_offset == 0 {
            self.function_name.clone()
        } else {
            format!("{}+0x{:x}", self.function_name, self.function_offset)
        }
    }
}

/// A complete call stack representation.
///
/// Ported from Ghidra's stack display model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameModel {
    /// The thread ID.
    pub thread_id: u64,
    /// The process ID.
    pub process_id: u64,
    /// The frames in the stack (innermost first).
    pub frames: Vec<StackFrameEntry>,
    /// Whether the stack is fully unwound.
    pub fully_unwound: bool,
    /// The depth limit applied during unwinding.
    pub depth_limit: Option<usize>,
}

impl StackFrameModel {
    /// Create a new stack frame model.
    pub fn new(thread_id: u64, process_id: u64) -> Self {
        Self {
            thread_id,
            process_id,
            frames: Vec::new(),
            fully_unwound: true,
            depth_limit: None,
        }
    }

    /// Add a frame to the stack.
    pub fn add_frame(&mut self, frame: StackFrameEntry) {
        self.frames.push(frame);
    }

    /// Get the innermost frame.
    pub fn current_frame(&self) -> Option<&StackFrameEntry> {
        self.frames.first()
    }

    /// Get a frame by level.
    pub fn frame_at_level(&self, level: usize) -> Option<&StackFrameEntry> {
        self.frames.iter().find(|f| f.level == level)
    }

    /// Get the total number of frames.
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Set the depth limit.
    pub fn set_depth_limit(&mut self, limit: usize) {
        self.depth_limit = Some(limit);
    }

    /// Get the display representation of the stack.
    pub fn display_frames(&self) -> Vec<String> {
        self.frames
            .iter()
            .map(|f| {
                format!(
                    "#{:2} 0x{:016x} {}  sp=0x{:016x}",
                    f.level,
                    f.pc,
                    f.function_display(),
                    f.sp,
                )
            })
            .collect()
    }
}

/// Utility for analyzing stack memory patterns.
#[derive(Debug)]
pub struct StackAnalyzer {
    /// The word size (4 or 8).
    pub word_size: usize,
    /// Known saved register names for the architecture.
    pub saved_registers: Vec<String>,
}

impl StackAnalyzer {
    /// Create an analyzer for the given architecture.
    pub fn new(word_size: usize) -> Self {
        Self {
            word_size,
            saved_registers: Vec::new(),
        }
    }

    /// Analyze a block of stack memory for potential return addresses.
    pub fn find_return_addresses(&self, stack_data: &[u8], base_addr: u64) -> Vec<u64> {
        let mut results = Vec::new();
        let step = self.word_size;
        for i in (0..stack_data.len()).step_by(step) {
            if i + step > stack_data.len() {
                break;
            }
            let value = if self.word_size == 8 {
                u64::from_le_bytes(stack_data[i..i + 8].try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(stack_data[i..i + 4].try_into().unwrap_or([0; 4])) as u64
            };

            // Heuristic: addresses in the range 0x400000 - 0x80000000 are
            // likely code addresses on most platforms.
            if (0x400000..0x80000000).contains(&value) && value % 2 == 0 {
                results.push(value);
            }
        }
        results
    }

    /// Estimate the frame size from the stack pointer change.
    pub fn estimate_frame_size(&self, sp_outer: u64, sp_inner: u64) -> Option<u64> {
        if sp_inner > sp_outer {
            Some(sp_inner - sp_outer)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_register_value() {
        let reg = FrameRegisterValue::new("RAX", vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00]);
        assert!(reg.known);
        assert_eq!(reg.as_u64_le(), Some(0x0000000012345678));

        let unknown = FrameRegisterValue::unknown("RBX");
        assert!(!unknown.known);
        assert!(unknown.as_u64_le().is_none());
    }

    #[test]
    fn test_stack_frame_entry() {
        let frame = StackFrameEntry::new(0, 0x400100, 0x7FFE0000)
            .with_function("main", 0x10)
            .with_fp(0x7FFE0080)
            .with_return_address(0x400200)
            .with_register(FrameRegisterValue::new("RAX", vec![0x42; 8]));

        assert_eq!(frame.level, 0);
        assert_eq!(frame.function_display(), "main+0x10");
        assert!(frame.get_register("RAX").is_some());
    }

    #[test]
    fn test_stack_frame_entry_display() {
        let frame = StackFrameEntry::new(0, 0x400000, 0x7FFE0000);
        assert_eq!(frame.function_display(), "0x400000");

        let frame = StackFrameEntry::new(0, 0x400000, 0x7FFE0000)
            .with_function("main", 0);
        assert_eq!(frame.function_display(), "main");
    }

    #[test]
    fn test_stack_frame_model() {
        let mut model = StackFrameModel::new(1, 100);
        assert!(model.is_empty());

        model.add_frame(StackFrameEntry::new(0, 0x400100, 0x7FFE0000).with_function("foo", 5));
        model.add_frame(StackFrameEntry::new(1, 0x400200, 0x7FFE0080).with_function("bar", 0));

        assert_eq!(model.depth(), 2);
        assert_eq!(model.current_frame().unwrap().function_name, "foo");
        assert_eq!(model.frame_at_level(1).unwrap().function_name, "bar");

        let display = model.display_frames();
        assert_eq!(display.len(), 2);
        assert!(display[0].contains("foo"));
    }

    #[test]
    fn test_stack_frame_model_depth_limit() {
        let mut model = StackFrameModel::new(1, 100);
        model.set_depth_limit(64);
        assert_eq!(model.depth_limit, Some(64));
    }

    #[test]
    fn test_stack_analyzer() {
        let analyzer = StackAnalyzer::new(8);

        // Create some stack data with potential return addresses
        let mut data = vec![0u8; 64];
        // Place a potential return address at offset 8
        data[8..16].copy_from_slice(&0x400100u64.to_le_bytes());
        // Place another at offset 24
        data[24..32].copy_from_slice(&0x400200u64.to_le_bytes());

        let results = analyzer.find_return_addresses(&data, 0x7FFE0000);
        assert!(results.contains(&0x400100));
        assert!(results.contains(&0x400200));
    }

    #[test]
    fn test_stack_analyzer_frame_size() {
        let analyzer = StackAnalyzer::new(8);
        assert_eq!(analyzer.estimate_frame_size(0x7FFE0000, 0x7FFE0080), Some(0x80));
        assert_eq!(analyzer.estimate_frame_size(0x7FFE0080, 0x7FFE0000), None);
    }

    #[test]
    fn test_stack_frame_type() {
        assert_ne!(StackFrameType::Normal, StackFrameType::Signal);
        assert_ne!(StackFrameType::Inline, StackFrameType::Synthetic);
    }

    #[test]
    fn test_stack_frame_model_serde() {
        let mut model = StackFrameModel::new(1, 100);
        model.add_frame(StackFrameEntry::new(0, 0x400000, 0x7FFE0000));

        let json = serde_json::to_string(&model).unwrap();
        let back: StackFrameModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.frames.len(), 1);
        assert_eq!(back.thread_id, 1);
    }
}
