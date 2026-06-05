//! UnwoundFrame - a frame produced by stack unwinding.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.stack.UnwoundFrame`
//! and related types.

use serde::{Deserialize, Serialize};

/// A register value at a specific stack frame level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameRegisterValue {
    /// The register name.
    pub register: String,
    /// The value of the register.
    pub value: u64,
}

/// The result of unwinding a single stack frame.
///
/// Ported from Ghidra's `UnwoundFrame` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwoundFrame {
    /// The frame level (0 = innermost).
    pub level: u32,
    /// The program counter for this frame.
    pub pc: u64,
    /// The stack pointer for this frame.
    pub sp: u64,
    /// Register values saved by the callee.
    pub saved_registers: Vec<FrameRegisterValue>,
    /// The function name if known.
    pub function_name: Option<String>,
    /// Whether this frame is a signal/trap frame.
    pub is_signal_frame: bool,
    /// Source file path if available.
    pub source_file: Option<String>,
    /// Source line number if available.
    pub source_line: Option<u32>,
}

impl UnwoundFrame {
    /// Create a new unwound frame.
    pub fn new(level: u32, pc: u64, sp: u64) -> Self {
        Self {
            level,
            pc,
            sp,
            saved_registers: Vec::new(),
            function_name: None,
            is_signal_frame: false,
            source_file: None,
            source_line: None,
        }
    }

    /// Set the function name.
    pub fn with_function_name(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Mark as a signal frame.
    pub fn with_signal_frame(mut self) -> Self {
        self.is_signal_frame = true;
        self
    }

    /// Add a saved register value.
    pub fn with_register(mut self, register: impl Into<String>, value: u64) -> Self {
        self.saved_registers.push(FrameRegisterValue {
            register: register.into(),
            value,
        });
        self
    }

    /// Set source location.
    pub fn with_source(mut self, file: impl Into<String>, line: u32) -> Self {
        self.source_file = Some(file.into());
        self.source_line = Some(line);
        self
    }

    /// Get a saved register value by name.
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.saved_registers
            .iter()
            .find(|r| r.register == name)
            .map(|r| r.value)
    }
}

/// Analysis result for stack unwinding.
///
/// Ported from Ghidra's `UnwindAnalysis`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnwindAnalysis {
    /// Unwinding was successful.
    Success,
    /// Unwinding failed with a message.
    Failed(String),
    /// The frame is a signal/trap frame.
    SignalFrame,
    /// Unwinding is not supported for this architecture.
    Unsupported,
    /// The unwind info was not available.
    NoUnwindInfo,
}

/// An exception during stack unwinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindException {
    /// The error message.
    pub message: String,
    /// The frame level at which the error occurred.
    pub frame_level: Option<u32>,
    /// The program counter at which the error occurred.
    pub pc: Option<u64>,
}

impl std::fmt::Display for UnwindException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnwindException: {}", self.message)?;
        if let Some(level) = self.frame_level {
            write!(f, " at frame {}", level)?;
        }
        if let Some(pc) = self.pc {
            write!(f, " at PC 0x{:x}", pc)?;
        }
        Ok(())
    }
}

impl std::error::Error for UnwindException {}

impl UnwindException {
    /// Create a new unwind exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            frame_level: None,
            pc: None,
        }
    }

    /// Set the frame level.
    pub fn with_frame(mut self, level: u32) -> Self {
        self.frame_level = Some(level);
        self
    }

    /// Set the PC.
    pub fn with_pc(mut self, pc: u64) -> Self {
        self.pc = Some(pc);
        self
    }
}

/// A complete stack unwind result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackUnwindResult {
    /// The frames from innermost (level 0) to outermost.
    pub frames: Vec<UnwoundFrame>,
    /// Any warnings generated during unwinding.
    pub warnings: Vec<UnwindWarning>,
    /// The analysis result.
    pub analysis: UnwindAnalysis,
}

/// A warning generated during stack unwinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindWarning {
    /// The warning message.
    pub message: String,
    /// The frame level at which the warning occurred.
    pub frame_level: u32,
    /// Severity level.
    pub severity: WarningSeverity,
}

/// Warning severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WarningSeverity {
    /// Informational only.
    Info,
    /// A warning that may affect accuracy.
    Warning,
    /// An error that definitely affects results.
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwound_frame_basic() {
        let f = UnwoundFrame::new(0, 0x400000, 0x7fff00);
        assert_eq!(f.level, 0);
        assert_eq!(f.pc, 0x400000);
        assert_eq!(f.sp, 0x7fff00);
        assert!(!f.is_signal_frame);
    }

    #[test]
    fn test_unwound_frame_builder() {
        let f = UnwoundFrame::new(1, 0x401000, 0x7ffe00)
            .with_function_name("main")
            .with_register("rbp", 0x7fff00)
            .with_register("rbx", 0)
            .with_source("main.c", 42);
        assert_eq!(f.function_name.as_deref(), Some("main"));
        assert_eq!(f.get_register("rbp"), Some(0x7fff00));
        assert_eq!(f.get_register("rbx"), Some(0));
        assert_eq!(f.get_register("missing"), None);
        assert_eq!(f.source_file.as_deref(), Some("main.c"));
        assert_eq!(f.source_line, Some(42));
    }

    #[test]
    fn test_signal_frame() {
        let f = UnwoundFrame::new(2, 0x7f0000, 0x7ffd00).with_signal_frame();
        assert!(f.is_signal_frame);
    }

    #[test]
    fn test_unwind_analysis() {
        assert_eq!(UnwindAnalysis::Success, UnwindAnalysis::Success);
        assert_ne!(
            UnwindAnalysis::Success,
            UnwindAnalysis::Failed("err".into())
        );
    }

    #[test]
    fn test_unwind_exception_display() {
        let e = UnwindException::new("bad unwind").with_frame(3).with_pc(0x500);
        let s = format!("{}", e);
        assert!(s.contains("bad unwind"));
        assert!(s.contains("frame 3"));
        assert!(s.contains("0x500"));
    }

    #[test]
    fn test_stack_unwind_result() {
        let result = StackUnwindResult {
            frames: vec![
                UnwoundFrame::new(0, 0x100, 0x200),
                UnwoundFrame::new(1, 0x300, 0x400),
            ],
            warnings: vec![UnwindWarning {
                message: "approximate".into(),
                frame_level: 1,
                severity: WarningSeverity::Warning,
            }],
            analysis: UnwindAnalysis::Success,
        };
        assert_eq!(result.frames.len(), 2);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_warning_severity_order() {
        assert!(WarningSeverity::Info < WarningSeverity::Warning);
        assert!(WarningSeverity::Warning < WarningSeverity::Error);
    }

    #[test]
    fn test_serde() {
        let f = UnwoundFrame::new(0, 0x100, 0x200).with_function_name("foo");
        let json = serde_json::to_string(&f).unwrap();
        let back: UnwoundFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back.function_name.as_deref(), Some("foo"));
    }
}
