//! Extended stack analysis types ported from Java.
//!
//! Ported from the Debugger module's `stack` package. Provides
//! stack unwinding, call stack analysis, and frame data structures
//! for the debugger.

use std::collections::BTreeMap;

/// Represents a single stack frame in a call stack.
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Frame level (0 = innermost/current).
    pub level: u32,
    /// Program counter at this frame.
    pub pc: u64,
    /// Stack pointer at this frame.
    pub sp: u64,
    /// Frame pointer at this frame (if available).
    pub fp: Option<u64>,
    /// Return address (if available).
    pub return_address: Option<u64>,
    /// Function name (if known).
    pub function_name: Option<String>,
    /// The thread this frame belongs to.
    pub thread_id: u64,
    /// Register values saved in this frame.
    pub saved_registers: BTreeMap<String, Vec<u8>>,
}

impl StackFrame {
    /// Create a new stack frame.
    pub fn new(level: u32, pc: u64, sp: u64, thread_id: u64) -> Self {
        Self {
            level,
            pc,
            sp,
            fp: None,
            return_address: None,
            function_name: None,
            thread_id,
            saved_registers: BTreeMap::new(),
        }
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = Some(fp);
        self
    }

    /// Set the return address.
    pub fn with_return_address(mut self, addr: u64) -> Self {
        self.return_address = Some(addr);
        self
    }

    /// Set the function name.
    pub fn with_function_name(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Add a saved register value.
    pub fn save_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.saved_registers.insert(name.into(), value);
    }

    /// Get a saved register value.
    pub fn get_saved_register(&self, name: &str) -> Option<&[u8]> {
        self.saved_registers.get(name).map(|v| v.as_slice())
    }
}

/// A complete call stack for a thread.
#[derive(Debug, Clone)]
pub struct CallStack {
    /// The thread ID.
    pub thread_id: u64,
    /// The frames, ordered from innermost (level 0) to outermost.
    pub frames: Vec<StackFrame>,
}

impl CallStack {
    /// Create a new empty call stack.
    pub fn new(thread_id: u64) -> Self {
        Self {
            thread_id,
            frames: Vec::new(),
        }
    }

    /// Add a frame to the call stack.
    pub fn push_frame(&mut self, frame: StackFrame) {
        self.frames.push(frame);
    }

    /// Get the innermost frame (current frame).
    pub fn current_frame(&self) -> Option<&StackFrame> {
        self.frames.first()
    }

    /// Get a frame by level.
    pub fn frame_at_level(&self, level: u32) -> Option<&StackFrame> {
        self.frames.iter().find(|f| f.level == level)
    }

    /// Get the depth of the call stack.
    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Check if the call stack is empty.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

/// Stack unwinding configuration.
#[derive(Debug, Clone)]
pub struct StackUnwindConfig {
    /// Maximum number of frames to unwind.
    pub max_frames: u32,
    /// Whether to use debug symbols for unwinding.
    pub use_debug_symbols: bool,
    /// Whether to use frame pointer for unwinding.
    pub use_frame_pointer: bool,
    /// Custom unwind rules.
    pub custom_rules: Vec<UnwindRule>,
}

impl Default for StackUnwindConfig {
    fn default() -> Self {
        Self {
            max_frames: 100,
            use_debug_symbols: true,
            use_frame_pointer: true,
            custom_rules: Vec::new(),
        }
    }
}

/// A custom unwind rule for specific function/region patterns.
#[derive(Debug, Clone)]
pub struct UnwindRule {
    /// Address range this rule applies to.
    pub address_range: (u64, u64),
    /// The register containing the return address.
    pub return_register: String,
    /// The register containing the stack pointer.
    pub stack_pointer_register: String,
    /// Stack adjustment for this frame.
    pub stack_adjustment: i64,
}

/// Result of a stack unwind operation.
#[derive(Debug, Clone)]
pub struct StackUnwindResult {
    /// The unwound call stack.
    pub call_stack: CallStack,
    /// Whether unwinding was truncated due to max_frames.
    pub truncated: bool,
    /// Any errors encountered during unwinding.
    pub errors: Vec<String>,
}

/// Trait for stack unwinders.
pub trait StackUnwinder: Send + Sync {
    /// Unwind the stack for the given thread.
    fn unwind(
        &self,
        thread_id: u64,
        initial_pc: u64,
        initial_sp: u64,
        config: &StackUnwindConfig,
    ) -> StackUnwindResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frame() {
        let mut frame = StackFrame::new(0, 0x400000, 0x7fff0000, 1)
            .with_fp(0x7fff0010)
            .with_return_address(0x400050)
            .with_function_name("main");
        frame.save_register("rbp", vec![0x10, 0x00, 0xff, 0x7f, 0, 0, 0, 0]);

        assert_eq!(frame.level, 0);
        assert_eq!(frame.pc, 0x400000);
        assert_eq!(frame.function_name.as_deref(), Some("main"));
        assert_eq!(frame.get_saved_register("rbp"), Some([0x10, 0x00, 0xff, 0x7f, 0, 0, 0, 0].as_slice()));
    }

    #[test]
    fn test_call_stack() {
        let mut cs = CallStack::new(1);
        cs.push_frame(StackFrame::new(0, 0x400100, 0x7fff0000, 1).with_function_name("foo"));
        cs.push_frame(StackFrame::new(1, 0x400200, 0x7fff0020, 1).with_function_name("bar"));
        cs.push_frame(StackFrame::new(2, 0x400300, 0x7fff0040, 1).with_function_name("main"));

        assert_eq!(cs.depth(), 3);
        assert_eq!(cs.current_frame().unwrap().function_name.as_deref(), Some("foo"));
        assert_eq!(cs.frame_at_level(2).unwrap().function_name.as_deref(), Some("main"));
        assert!(cs.frame_at_level(5).is_none());
    }

    #[test]
    fn test_unwind_config() {
        let config = StackUnwindConfig::default();
        assert_eq!(config.max_frames, 100);
        assert!(config.use_debug_symbols);
    }
}
