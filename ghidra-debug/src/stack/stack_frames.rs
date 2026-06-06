//! Stack frame types for stack unwinding results.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.stack` package.
//! Provides concrete implementations of unwound frames (analysis, listing,
//! fake), unwind warning tracking, and evaluation exceptions for the
//! stack unwinding framework.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};


// ---------------------------------------------------------------------------
// StackUnwindWarning / StackUnwindWarningSet
// ---------------------------------------------------------------------------

/// Severity of a stack unwind warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum UnwindWarningSeverity {
    /// Informational message.
    Info,
    /// Warning that may affect accuracy.
    Warning,
    /// Error that prevented unwinding from completing.
    Error,
}

impl fmt::Display for UnwindWarningSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// A single warning produced during stack unwinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackUnwindWarning {
    /// The severity of this warning.
    pub severity: UnwindWarningSeverity,
    /// Human-readable message describing the warning.
    pub message: String,
    /// Optional address where the warning occurred (offset).
    pub address: Option<u64>,
    /// Optional frame depth at which the warning was produced.
    pub frame_depth: Option<usize>,
}

impl StackUnwindWarning {
    /// Create a new info-level warning.
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            severity: UnwindWarningSeverity::Info,
            message: message.into(),
            address: None,
            frame_depth: None,
        }
    }

    /// Create a new warning-level warning.
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: UnwindWarningSeverity::Warning,
            message: message.into(),
            address: None,
            frame_depth: None,
        }
    }

    /// Create a new error-level warning.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: UnwindWarningSeverity::Error,
            message: message.into(),
            address: None,
            frame_depth: None,
        }
    }

    /// Set the address where the warning occurred.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the frame depth.
    pub fn with_frame_depth(mut self, depth: usize) -> Self {
        self.frame_depth = Some(depth);
        self
    }
}

impl fmt::Display for StackUnwindWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.severity)?;
        if let Some(depth) = self.frame_depth {
            write!(f, " frame {}", depth)?;
        }
        if let Some(addr) = self.address {
            write!(f, " @ 0x{:x}", addr)?;
        }
        write!(f, " {}", self.message)
    }
}

/// A collection of warnings produced during stack unwinding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackUnwindWarningSet {
    /// The collected warnings.
    warnings: Vec<StackUnwindWarning>,
}

impl StackUnwindWarningSet {
    /// Create an empty warning set.
    pub fn new() -> Self {
        Self {
            warnings: Vec::new(),
        }
    }

    /// Add a warning to the set.
    pub fn add(&mut self, warning: StackUnwindWarning) {
        self.warnings.push(warning);
    }

    /// Get all warnings.
    pub fn warnings(&self) -> &[StackUnwindWarning] {
        &self.warnings
    }

    /// Get the number of warnings.
    pub fn len(&self) -> usize {
        self.warnings.len()
    }

    /// Whether there are any warnings.
    pub fn is_empty(&self) -> bool {
        self.warnings.is_empty()
    }

    /// Whether there are any errors.
    pub fn has_errors(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w.severity == UnwindWarningSeverity::Error)
    }

    /// Whether there are any warnings or errors.
    pub fn has_warnings(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w.severity >= UnwindWarningSeverity::Warning)
    }

    /// Get only the error-level warnings.
    pub fn errors(&self) -> Vec<&StackUnwindWarning> {
        self.warnings
            .iter()
            .filter(|w| w.severity == UnwindWarningSeverity::Error)
            .collect()
    }

    /// Get only the warning-level and error-level warnings.
    pub fn warnings_and_errors(&self) -> Vec<&StackUnwindWarning> {
        self.warnings
            .iter()
            .filter(|w| w.severity >= UnwindWarningSeverity::Warning)
            .collect()
    }

    /// Merge another warning set into this one.
    pub fn merge(&mut self, other: &StackUnwindWarningSet) {
        self.warnings.extend(other.warnings.iter().cloned());
    }
}

impl fmt::Display for StackUnwindWarningSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "(no warnings)");
        }
        for (i, w) in self.warnings.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{}", w)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UnwindFailure -- detailed unwind failure info (extends base UnwindException)
// ---------------------------------------------------------------------------

/// Detailed unwind failure information.
///
/// Extends the basic `UnwindException` (defined in the parent module) with
/// frame depth and address context for better diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindFailure {
    /// The error message.
    pub message: String,
    /// Optional source cause description.
    pub cause: Option<String>,
    /// The frame depth at which unwinding failed.
    pub frame_depth: Option<usize>,
    /// The address at which unwinding failed.
    pub address: Option<u64>,
}

impl UnwindFailure {
    /// Create a new unwind failure.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
            frame_depth: None,
            address: None,
        }
    }

    /// Create with a cause.
    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(cause.into());
        self
    }

    /// Set the frame depth where the error occurred.
    pub fn with_frame_depth(mut self, depth: usize) -> Self {
        self.frame_depth = Some(depth);
        self
    }

    /// Set the address where the error occurred.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }
}

impl fmt::Display for UnwindFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Stack unwind failed: {}", self.message)?;
        if let Some(depth) = self.frame_depth {
            write!(f, " (frame {})", depth)?;
        }
        if let Some(addr) = self.address {
            write!(f, " at 0x{:x}", addr)?;
        }
        if let Some(cause) = &self.cause {
            write!(f, " [cause: {}]", cause)?;
        }
        Ok(())
    }
}

impl std::error::Error for UnwindFailure {}

// ---------------------------------------------------------------------------
// StackEvalFailure -- evaluation failure with operation context
// ---------------------------------------------------------------------------

/// Detailed evaluation failure during stack unwinding.
///
/// Extends the basic `EvaluationException` (defined in the parent module)
/// with operation and register context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackEvalFailure {
    /// The error message.
    pub message: String,
    /// The operation that failed.
    pub operation: Option<String>,
    /// The register involved, if applicable.
    pub register: Option<String>,
}

impl StackEvalFailure {
    /// Create a new evaluation failure.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            operation: None,
            register: None,
        }
    }

    /// Set the failed operation.
    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    /// Set the register involved.
    pub fn with_register(mut self, reg: impl Into<String>) -> Self {
        self.register = Some(reg.into());
        self
    }
}

impl fmt::Display for StackEvalFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Evaluation error: {}", self.message)?;
        if let Some(op) = &self.operation {
            write!(f, " during {}", op)?;
        }
        if let Some(reg) = &self.register {
            write!(f, " (register: {})", reg)?;
        }
        Ok(())
    }
}

impl std::error::Error for StackEvalFailure {}

// ---------------------------------------------------------------------------
// DynamicMappingFailure
// ---------------------------------------------------------------------------

/// Failure when dynamic-to-static address mapping fails during unwinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicMappingFailure {
    /// The error message.
    pub message: String,
    /// The dynamic address that failed to map.
    pub dynamic_address: Option<u64>,
}

impl DynamicMappingFailure {
    /// Create a new dynamic mapping failure.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            dynamic_address: None,
        }
    }

    /// Set the dynamic address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.dynamic_address = Some(addr);
        self
    }
}

impl fmt::Display for DynamicMappingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Dynamic mapping failed: {}", self.message)?;
        if let Some(addr) = self.dynamic_address {
            write!(f, " (address: 0x{:x})", addr)?;
        }
        Ok(())
    }
}

impl std::error::Error for DynamicMappingFailure {}

// ---------------------------------------------------------------------------
// AbstractUnwoundFrame -- base for all unwound frame types
// ---------------------------------------------------------------------------

/// The source of unwind information for a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnwindSource {
    /// Unwound using DWARF unwind info.
    Dwarf,
    /// Unwound using Windows SEH unwind info.
    Seh,
    /// Unwound using analysis heuristics.
    Analysis,
    /// Unwound from listing/program metadata.
    Listing,
    /// A fake/synthetic frame (e.g., for entry point).
    Fake,
    /// Frame from the target directly.
    Target,
}

/// A register value in an unwound frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameRegisterValue {
    /// Register name (e.g., "RSP", "RBP").
    pub name: String,
    /// The value of the register.
    pub value: u64,
    /// Whether this value was explicitly set (vs. inherited).
    pub is_explicit: bool,
    /// Whether this is a known value or just the previous frame's value.
    pub is_known: bool,
}

impl FrameRegisterValue {
    /// Create a new explicit register value.
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            is_explicit: true,
            is_known: true,
        }
    }

    /// Create an inherited (not explicitly set) register value.
    pub fn inherited(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            is_explicit: false,
            is_known: true,
        }
    }

    /// Create a register with unknown value.
    pub fn unknown(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: 0,
            is_explicit: false,
            is_known: false,
        }
    }
}

/// Base data shared by all unwound frame types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwoundFrameData {
    /// The frame depth (0 = innermost frame).
    pub depth: usize,
    /// The program counter (return address for this frame).
    pub pc: u64,
    /// The stack pointer.
    pub sp: u64,
    /// The frame pointer (if available).
    pub fp: Option<u64>,
    /// Register values known in this frame.
    pub registers: Vec<FrameRegisterValue>,
    /// The source of unwind information.
    pub source: UnwindSource,
    /// Whether this frame represents a signal handler.
    pub is_signal_frame: bool,
    /// The function name, if known.
    pub function_name: Option<String>,
}

impl UnwoundFrameData {
    /// Create a new frame data.
    pub fn new(depth: usize, pc: u64, sp: u64, source: UnwindSource) -> Self {
        Self {
            depth,
            pc,
            sp,
            fp: None,
            registers: Vec::new(),
            source,
            is_signal_frame: false,
            function_name: None,
        }
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = Some(fp);
        self
    }

    /// Add a register value.
    pub fn with_register(mut self, reg: FrameRegisterValue) -> Self {
        self.registers.push(reg);
        self
    }

    /// Set the function name.
    pub fn with_function_name(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Mark as a signal frame.
    pub fn as_signal_frame(mut self) -> Self {
        self.is_signal_frame = true;
        self
    }

    /// Look up a register value by name.
    pub fn register_value(&self, name: &str) -> Option<u64> {
        self.registers
            .iter()
            .find(|r| r.name == name && r.is_known)
            .map(|r| r.value)
    }

    /// Get all explicit register values as a map.
    pub fn explicit_registers(&self) -> HashMap<String, u64> {
        self.registers
            .iter()
            .filter(|r| r.is_explicit && r.is_known)
            .map(|r| (r.name.clone(), r.value))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AnalysisUnwoundFrame -- frame from analysis-based unwinding
// ---------------------------------------------------------------------------

/// A frame unwound using analysis heuristics.
///
/// This is produced when DWARF/SEH unwind info is not available and
/// the unwinder must fall back to pattern-matching and heuristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisUnwoundFrame {
    /// Base frame data.
    pub data: UnwoundFrameData,
    /// Confidence score (0.0 = guess, 1.0 = certain).
    pub confidence: f64,
    /// Which heuristics were used.
    pub heuristics_used: Vec<String>,
    /// Whether the stack pointer adjustment was detected.
    pub has_sp_adjustment: bool,
    /// Size of the detected stack frame in bytes.
    pub frame_size: Option<u64>,
}

impl AnalysisUnwoundFrame {
    /// Create a new analysis unwound frame.
    pub fn new(data: UnwoundFrameData, confidence: f64) -> Self {
        Self {
            data,
            confidence,
            heuristics_used: Vec::new(),
            has_sp_adjustment: false,
            frame_size: None,
        }
    }

    /// Add a heuristic that was used.
    pub fn add_heuristic(&mut self, name: impl Into<String>) {
        self.heuristics_used.push(name.into());
    }

    /// Whether the confidence is high enough to trust.
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.7
    }
}

// ---------------------------------------------------------------------------
// ListingUnwoundFrame -- frame from listing-based unwinding
// ---------------------------------------------------------------------------

/// A frame unwound using program listing metadata.
///
/// This uses information from the static analysis of the program, such
/// as function signatures and stack frame definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingUnwoundFrame {
    /// Base frame data.
    pub data: UnwoundFrameData,
    /// The program URL.
    pub program_url: Option<String>,
    /// The static mapping from program to trace.
    pub mapping_applied: bool,
    /// Function entry address in the program.
    pub function_entry: Option<u64>,
    /// Stack parameter size in bytes.
    pub param_size: Option<u64>,
    /// Local variable area size in bytes.
    pub local_size: Option<u64>,
}

impl ListingUnwoundFrame {
    /// Create a new listing unwound frame.
    pub fn new(data: UnwoundFrameData) -> Self {
        Self {
            data,
            program_url: None,
            mapping_applied: false,
            function_entry: None,
            param_size: None,
            local_size: None,
        }
    }

    /// Set the program URL.
    pub fn with_program_url(mut self, url: impl Into<String>) -> Self {
        self.program_url = Some(url.into());
        self
    }

    /// Set whether mapping was applied.
    pub fn with_mapping_applied(mut self, applied: bool) -> Self {
        self.mapping_applied = applied;
        self
    }

    /// Set the function entry address.
    pub fn with_function_entry(mut self, entry: u64) -> Self {
        self.function_entry = Some(entry);
        self
    }

    /// Set the parameter and local sizes.
    pub fn with_frame_sizes(mut self, param_size: u64, local_size: u64) -> Self {
        self.param_size = Some(param_size);
        self.local_size = Some(local_size);
        self
    }

    /// Total frame size (params + locals + saved registers).
    pub fn total_frame_size(&self) -> Option<u64> {
        match (self.param_size, self.local_size) {
            (Some(p), Some(l)) => Some(p + l),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// FakeUnwoundFrame -- synthetic frame for special purposes
// ---------------------------------------------------------------------------

/// A synthetic/fake unwound frame.
///
/// This is used for frames that are not the result of actual unwinding,
/// such as the entry point frame, or when the user manually creates a
/// frame to start the unwinding process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeUnwoundFrame {
    /// Base frame data.
    pub data: UnwoundFrameData,
    /// Reason this frame was created.
    pub reason: String,
    /// Whether this is a "bottom" frame (innermost, e.g., entry point).
    pub is_bottom: bool,
}

impl FakeUnwoundFrame {
    /// Create a new fake frame.
    pub fn new(data: UnwoundFrameData, reason: impl Into<String>) -> Self {
        Self {
            data,
            reason: reason.into(),
            is_bottom: false,
        }
    }

    /// Mark this as a bottom frame.
    pub fn as_bottom(mut self) -> Self {
        self.is_bottom = true;
        self
    }
}

// ---------------------------------------------------------------------------
// UnwoundFrame -- unified enum of all frame types
// ---------------------------------------------------------------------------

/// A unified enum representing any type of unwound frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnwoundFrame {
    /// Frame from analysis heuristics.
    Analysis(AnalysisUnwoundFrame),
    /// Frame from program listing metadata.
    Listing(ListingUnwoundFrame),
    /// Synthetic/fake frame.
    Fake(FakeUnwoundFrame),
}

impl UnwoundFrame {
    /// Get the frame depth.
    pub fn depth(&self) -> usize {
        self.data().depth
    }

    /// Get the program counter.
    pub fn pc(&self) -> u64 {
        self.data().pc
    }

    /// Get the stack pointer.
    pub fn sp(&self) -> u64 {
        self.data().sp
    }

    /// Get the frame pointer, if available.
    pub fn fp(&self) -> Option<u64> {
        self.data().fp
    }

    /// Get a reference to the underlying frame data.
    pub fn data(&self) -> &UnwoundFrameData {
        match self {
            Self::Analysis(f) => &f.data,
            Self::Listing(f) => &f.data,
            Self::Fake(f) => &f.data,
        }
    }

    /// Get the unwind source.
    pub fn source(&self) -> UnwindSource {
        self.data().source
    }

    /// Whether this is a signal frame.
    pub fn is_signal_frame(&self) -> bool {
        self.data().is_signal_frame
    }

    /// Look up a register value by name.
    pub fn register_value(&self, name: &str) -> Option<u64> {
        self.data().register_value(name)
    }

    /// Whether this frame is an analysis frame.
    pub fn is_analysis(&self) -> bool {
        matches!(self, Self::Analysis(_))
    }

    /// Whether this frame is a listing frame.
    pub fn is_listing(&self) -> bool {
        matches!(self, Self::Listing(_))
    }

    /// Whether this frame is a fake frame.
    pub fn is_fake(&self) -> bool {
        matches!(self, Self::Fake(_))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwind_warning_creation() {
        let w = StackUnwindWarning::info("test info");
        assert_eq!(w.severity, UnwindWarningSeverity::Info);
        assert_eq!(w.message, "test info");
        assert!(w.address.is_none());

        let w = StackUnwindWarning::warning("test warn").with_address(0x400000);
        assert_eq!(w.severity, UnwindWarningSeverity::Warning);
        assert_eq!(w.address, Some(0x400000));

        let w = StackUnwindWarning::error("test error").with_frame_depth(3);
        assert_eq!(w.severity, UnwindWarningSeverity::Error);
        assert_eq!(w.frame_depth, Some(3));
    }

    #[test]
    fn test_unwind_warning_display() {
        let w = StackUnwindWarning::warning("missing unwind info")
            .with_address(0x401000)
            .with_frame_depth(2);
        let s = format!("{}", w);
        assert!(s.contains("WARN"));
        assert!(s.contains("frame 2"));
        assert!(s.contains("0x401000"));
        assert!(s.contains("missing unwind info"));
    }

    #[test]
    fn test_unwind_warning_severity_ordering() {
        assert!(UnwindWarningSeverity::Info < UnwindWarningSeverity::Warning);
        assert!(UnwindWarningSeverity::Warning < UnwindWarningSeverity::Error);
    }

    #[test]
    fn test_warning_set_basics() {
        let mut ws = StackUnwindWarningSet::new();
        assert!(ws.is_empty());
        assert!(!ws.has_errors());
        assert!(!ws.has_warnings());

        ws.add(StackUnwindWarning::info("info msg"));
        assert_eq!(ws.len(), 1);
        assert!(!ws.has_errors());
        assert!(!ws.has_warnings()); // info is not a warning

        ws.add(StackUnwindWarning::warning("warn msg"));
        assert_eq!(ws.len(), 2);
        assert!(!ws.has_errors());
        assert!(ws.has_warnings());

        ws.add(StackUnwindWarning::error("error msg"));
        assert_eq!(ws.len(), 3);
        assert!(ws.has_errors());
        assert!(ws.has_warnings());
    }

    #[test]
    fn test_warning_set_errors_filter() {
        let mut ws = StackUnwindWarningSet::new();
        ws.add(StackUnwindWarning::info("info"));
        ws.add(StackUnwindWarning::warning("warn"));
        ws.add(StackUnwindWarning::error("err1"));
        ws.add(StackUnwindWarning::error("err2"));

        assert_eq!(ws.errors().len(), 2);
        assert_eq!(ws.warnings_and_errors().len(), 3);
    }

    #[test]
    fn test_warning_set_merge() {
        let mut ws1 = StackUnwindWarningSet::new();
        ws1.add(StackUnwindWarning::info("info1"));

        let mut ws2 = StackUnwindWarningSet::new();
        ws2.add(StackUnwindWarning::warning("warn2"));
        ws2.add(StackUnwindWarning::error("err2"));

        ws1.merge(&ws2);
        assert_eq!(ws1.len(), 3);
        assert!(ws1.has_errors());
    }

    #[test]
    fn test_warning_set_display_empty() {
        let ws = StackUnwindWarningSet::new();
        assert_eq!(format!("{}", ws), "(no warnings)");
    }

    #[test]
    fn test_unwind_failure() {
        let e = UnwindFailure::new("no unwind info")
            .with_cause("DWARF missing")
            .with_frame_depth(5)
            .with_address(0x7fff0000);
        assert_eq!(e.frame_depth, Some(5));
        assert_eq!(e.address, Some(0x7fff0000));
        assert!(e.cause.is_some());

        let s = format!("{}", e);
        assert!(s.contains("no unwind info"));
        assert!(s.contains("DWARF missing"));
        assert!(s.contains("frame 5"));
    }

    #[test]
    fn test_stack_eval_failure() {
        let e = StackEvalFailure::new("cannot resolve")
            .with_operation("read_register")
            .with_register("RIP");
        let s = format!("{}", e);
        assert!(s.contains("cannot resolve"));
        assert!(s.contains("read_register"));
        assert!(s.contains("RIP"));
    }

    #[test]
    fn test_dynamic_mapping_failure() {
        let e = DynamicMappingFailure::new("no static mapping").with_address(0x123456);
        let s = format!("{}", e);
        assert!(s.contains("no static mapping"));
        assert!(s.contains("0x123456"));
    }

    #[test]
    fn test_frame_register_value() {
        let rv = FrameRegisterValue::new("RSP", 0x7fff0000);
        assert!(rv.is_explicit);
        assert!(rv.is_known);
        assert_eq!(rv.value, 0x7fff0000);

        let rv = FrameRegisterValue::inherited("RBP", 0x7fff0010);
        assert!(!rv.is_explicit);
        assert!(rv.is_known);

        let rv = FrameRegisterValue::unknown("R15");
        assert!(!rv.is_explicit);
        assert!(!rv.is_known);
        assert_eq!(rv.value, 0);
    }

    #[test]
    fn test_unwound_frame_data() {
        let data = UnwoundFrameData::new(0, 0x401000, 0x7fff0000, UnwindSource::Dwarf)
            .with_fp(0x7fff0020)
            .with_register(FrameRegisterValue::new("RSP", 0x7fff0000))
            .with_register(FrameRegisterValue::new("RBP", 0x7fff0020))
            .with_function_name("main");

        assert_eq!(data.depth, 0);
        assert_eq!(data.pc, 0x401000);
        assert_eq!(data.sp, 0x7fff0000);
        assert_eq!(data.fp, Some(0x7fff0020));
        assert_eq!(data.function_name.as_deref(), Some("main"));

        assert_eq!(data.register_value("RSP"), Some(0x7fff0000));
        assert_eq!(data.register_value("RBP"), Some(0x7fff0020));
        assert_eq!(data.register_value("R15"), None);

        let explicit = data.explicit_registers();
        assert_eq!(explicit.len(), 2);
    }

    #[test]
    fn test_analysis_unwound_frame() {
        let data = UnwoundFrameData::new(1, 0x401100, 0x7fff0010, UnwindSource::Analysis);
        let mut frame = AnalysisUnwoundFrame::new(data, 0.85);
        frame.add_heuristic("prologue_pattern");
        frame.add_heuristic("epilogue_scan");

        assert!(frame.is_confident());
        assert_eq!(frame.heuristics_used.len(), 2);
    }

    #[test]
    fn test_analysis_frame_low_confidence() {
        let data = UnwoundFrameData::new(2, 0x401200, 0x7fff0020, UnwindSource::Analysis);
        let frame = AnalysisUnwoundFrame::new(data, 0.3);
        assert!(!frame.is_confident());
    }

    #[test]
    fn test_listing_unwound_frame() {
        let data = UnwoundFrameData::new(0, 0x401000, 0x7fff0000, UnwindSource::Listing);
        let frame = ListingUnwoundFrame::new(data)
            .with_program_url("file:///tmp/test")
            .with_mapping_applied(true)
            .with_function_entry(0x401000)
            .with_frame_sizes(16, 64);

        assert_eq!(frame.program_url.as_deref(), Some("file:///tmp/test"));
        assert!(frame.mapping_applied);
        assert_eq!(frame.function_entry, Some(0x401000));
        assert_eq!(frame.total_frame_size(), Some(80));
    }

    #[test]
    fn test_fake_unwound_frame() {
        let data = UnwoundFrameData::new(0, 0x400000, 0x7fff0000, UnwindSource::Fake);
        let frame = FakeUnwoundFrame::new(data, "entry point").as_bottom();
        assert_eq!(frame.reason, "entry point");
        assert!(frame.is_bottom);
    }

    #[test]
    fn test_unwound_frame_enum() {
        let data = UnwoundFrameData::new(0, 0x401000, 0x7fff0000, UnwindSource::Dwarf);
        let frame = UnwoundFrame::Analysis(AnalysisUnwoundFrame::new(data, 0.95));

        assert_eq!(frame.depth(), 0);
        assert_eq!(frame.pc(), 0x401000);
        assert_eq!(frame.sp(), 0x7fff0000);
        assert!(frame.is_analysis());
        assert!(!frame.is_listing());
        assert!(!frame.is_fake());
        assert_eq!(frame.source(), UnwindSource::Dwarf);
    }

    #[test]
    fn test_unwound_frame_listing_type() {
        let data = UnwoundFrameData::new(1, 0x401100, 0x7fff0010, UnwindSource::Listing);
        let frame = UnwoundFrame::Listing(ListingUnwoundFrame::new(data));
        assert!(frame.is_listing());
        assert!(!frame.is_analysis());
    }

    #[test]
    fn test_unwound_frame_fake_type() {
        let data = UnwoundFrameData::new(0, 0x400000, 0x7fff0000, UnwindSource::Fake);
        let frame = UnwoundFrame::Fake(
            FakeUnwoundFrame::new(data, "manual").as_bottom(),
        );
        assert!(frame.is_fake());
        assert!(!frame.is_signal_frame());
    }

    #[test]
    fn test_unwind_source_variants() {
        assert_ne!(UnwindSource::Dwarf, UnwindSource::Seh);
        assert_ne!(UnwindSource::Analysis, UnwindSource::Fake);
        assert_eq!(UnwindSource::Target, UnwindSource::Target);
    }

    #[test]
    fn test_signal_frame() {
        let data = UnwoundFrameData::new(0, 0x401000, 0x7fff0000, UnwindSource::Dwarf)
            .as_signal_frame();
        assert!(data.is_signal_frame);
    }

    #[test]
    fn test_errors_are_display() {
        let e = UnwindFailure::new("test");
        let _: &dyn std::error::Error = &e;

        let e = StackEvalFailure::new("test");
        let _: &dyn std::error::Error = &e;

        let e = DynamicMappingFailure::new("test");
        let _: &dyn std::error::Error = &e;
    }
}
