//! Stack analysis plugin types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.stack` package.
//! Provides types for analyzing and displaying the call stack.

use serde::{Deserialize, Serialize};

/// A stack frame in the call stack.
///
/// Ported from Ghidra's stack analysis types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    /// The frame level (0 = innermost/leaf).
    pub level: u32,
    /// The program counter at this frame.
    pub pc: u64,
    /// The return address (where execution will continue after this frame).
    pub return_address: Option<u64>,
    /// The function name, if known.
    pub function_name: Option<String>,
    /// The frame pointer value.
    pub frame_pointer: Option<u64>,
    /// The stack pointer value at this frame.
    pub stack_pointer: Option<u64>,
    /// Whether this is a signal handler frame.
    pub is_signal_frame: bool,
    /// Source file path, if known.
    pub source_file: Option<String>,
    /// Source line number, if known.
    pub source_line: Option<u32>,
}

impl StackFrame {
    /// Create a new stack frame.
    pub fn new(level: u32, pc: u64) -> Self {
        Self {
            level,
            pc,
            return_address: None,
            function_name: None,
            frame_pointer: None,
            stack_pointer: None,
            is_signal_frame: false,
            source_file: None,
            source_line: None,
        }
    }

    /// Set the function name.
    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Set the return address.
    pub fn with_return_address(mut self, addr: u64) -> Self {
        self.return_address = Some(addr);
        self
    }

    /// Set the frame pointer.
    pub fn with_frame_pointer(mut self, fp: u64) -> Self {
        self.frame_pointer = Some(fp);
        self
    }

    /// Set the stack pointer.
    pub fn with_stack_pointer(mut self, sp: u64) -> Self {
        self.stack_pointer = Some(sp);
        self
    }

    /// Set source location.
    pub fn with_source(mut self, file: impl Into<String>, line: u32) -> Self {
        self.source_file = Some(file.into());
        self.source_line = Some(line);
        self
    }
}

/// A complete call stack for a thread at a given snap.
///
/// Ported from Ghidra's stack analysis output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStack {
    /// The thread key.
    pub thread_key: i64,
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The frames (from innermost to outermost).
    pub frames: Vec<StackFrame>,
}

impl CallStack {
    /// Create a new empty call stack.
    pub fn new(trace_id: impl Into<String>, thread_key: i64, snap: i64) -> Self {
        Self {
            thread_key,
            trace_id: trace_id.into(),
            snap,
            frames: Vec::new(),
        }
    }

    /// Add a frame.
    pub fn push_frame(&mut self, frame: StackFrame) {
        self.frames.push(frame);
    }

    /// Get the number of frames.
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Get the innermost frame (frame 0).
    pub fn innermost(&self) -> Option<&StackFrame> {
        self.frames.first()
    }

    /// Get the outermost frame.
    pub fn outermost(&self) -> Option<&StackFrame> {
        self.frames.last()
    }

    /// Find the frame for a given function name.
    pub fn find_function(&self, name: &str) -> Option<&StackFrame> {
        self.frames
            .iter()
            .find(|f| f.function_name.as_deref() == Some(name))
    }

    /// Get all function names in the call stack.
    pub fn function_names(&self) -> Vec<Option<&str>> {
        self.frames
            .iter()
            .map(|f| f.function_name.as_deref())
            .collect()
    }
}

/// Variables in a stack frame.
///
/// Ported from Ghidra's stack variables analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackVariable {
    /// The variable name.
    pub name: String,
    /// The storage type.
    pub storage: VariableStorage,
    /// The data type name.
    pub data_type: String,
    /// The size in bytes.
    pub size: u32,
    /// The current value as bytes.
    pub value: Option<Vec<u8>>,
}

/// Where a stack variable is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableStorage {
    /// Stored at a stack offset relative to the frame pointer.
    StackOffset(i32),
    /// Stored in a register.
    Register(String),
    /// Stored at a memory address.
    Memory(u64),
}

impl StackVariable {
    /// Create a stack-local variable.
    pub fn stack_local(
        name: impl Into<String>,
        offset: i32,
        data_type: impl Into<String>,
        size: u32,
    ) -> Self {
        Self {
            name: name.into(),
            storage: VariableStorage::StackOffset(offset),
            data_type: data_type.into(),
            size,
            value: None,
        }
    }

    /// Create a register variable.
    pub fn register(
        name: impl Into<String>,
        reg: impl Into<String>,
        data_type: impl Into<String>,
        size: u32,
    ) -> Self {
        Self {
            name: name.into(),
            storage: VariableStorage::Register(reg.into()),
            data_type: data_type.into(),
            size,
            value: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frame() {
        let frame = StackFrame::new(0, 0x400080)
            .with_function("main")
            .with_return_address(0x400100)
            .with_frame_pointer(0x7fff0000)
            .with_source("main.c", 42);
        assert_eq!(frame.level, 0);
        assert_eq!(frame.pc, 0x400080);
        assert_eq!(frame.function_name.as_deref(), Some("main"));
        assert_eq!(frame.source_line, Some(42));
    }

    #[test]
    fn test_call_stack() {
        let mut stack = CallStack::new("trace1", 1, 0);
        stack.push_frame(StackFrame::new(0, 0x400080).with_function("foo"));
        stack.push_frame(StackFrame::new(1, 0x400100).with_function("bar"));
        stack.push_frame(StackFrame::new(2, 0x400200).with_function("main"));

        assert_eq!(stack.depth(), 3);
        assert_eq!(stack.innermost().unwrap().function_name.as_deref(), Some("foo"));
        assert_eq!(stack.outermost().unwrap().function_name.as_deref(), Some("main"));

        assert!(stack.find_function("bar").is_some());
        assert!(stack.find_function("missing").is_none());
    }

    #[test]
    fn test_call_stack_function_names() {
        let mut stack = CallStack::new("trace1", 1, 0);
        stack.push_frame(StackFrame::new(0, 0x100).with_function("a"));
        stack.push_frame(StackFrame::new(1, 0x200));

        let names = stack.function_names();
        assert_eq!(names[0], Some("a"));
        assert_eq!(names[1], None);
    }

    #[test]
    fn test_stack_variable() {
        let var = StackVariable::stack_local("buf", -0x20, "char[64]", 64);
        assert_eq!(var.name, "buf");
        match &var.storage {
            VariableStorage::StackOffset(offset) => assert_eq!(*offset, -0x20),
            _ => panic!("expected stack offset"),
        }

        let var = StackVariable::register("ret", "RAX", "long", 8);
        match &var.storage {
            VariableStorage::Register(reg) => assert_eq!(reg, "RAX"),
            _ => panic!("expected register"),
        }
    }

    #[test]
    fn test_signal_frame() {
        let mut frame = StackFrame::new(3, 0x7f000000);
        frame.is_signal_frame = true;
        assert!(frame.is_signal_frame);
    }

    #[test]
    fn test_call_stack_serde() {
        let mut stack = CallStack::new("trace1", 1, 0);
        stack.push_frame(StackFrame::new(0, 0x100).with_function("main"));
        let json = serde_json::to_string(&stack).unwrap();
        let back: CallStack = serde_json::from_str(&json).unwrap();
        assert_eq!(back.depth(), 1);
    }

    #[test]
    fn test_empty_call_stack() {
        let stack = CallStack::new("trace1", 1, 0);
        assert_eq!(stack.depth(), 0);
        assert!(stack.innermost().is_none());
        assert!(stack.outermost().is_none());
    }
}
