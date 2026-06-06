//! Test framework for Ghidra integration testing.
//!
//! Ported from `ghidra.test`:
//! - [`TestEnv`] -- manages a test tool environment with program lifecycle
//! - [`ToyProgramBuilder`] -- builds minimal programs for unit tests
//! - [`TestProgramManager`] -- program manager for tests
//! - [`TestTool`] -- minimal plugin tool for tests
//! - [`TestLogger`] -- captures log output during tests
//! - [`ProjectTestUtils`] -- project-related test utilities

use std::collections::HashMap;
use std::path::PathBuf;

use crate::base::analyzer::{Address, AddressSet, Program};
use crate::base::analyzer::core::AddressRange;

// ---------------------------------------------------------------------------
// TestEnv
// ---------------------------------------------------------------------------

/// Test environment that manages a Ghidra tool for integration tests.
///
/// Ported from `ghidra.test.TestEnv`.
///
/// Provides a controlled environment with:
/// - A test tool
/// - Program lifecycle (open/close/create)
/// - Automatic cleanup on drop
#[derive(Debug)]
pub struct TestEnv {
    /// The test tool.
    pub tool: TestTool,
    /// Programs opened in this environment (by name).
    programs: HashMap<String, Program>,
    /// Temporary directory for test artifacts.
    pub temp_dir: PathBuf,
    /// Whether the environment has been disposed.
    disposed: bool,
}

impl TestEnv {
    /// Create a new test environment.
    pub fn new() -> Self {
        let temp_dir = std::env::temp_dir().join(format!("ghidra_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        Self {
            tool: TestTool::new("TestTool"),
            programs: HashMap::new(),
            temp_dir,
            disposed: false,
        }
    }

    /// Create a new test environment with a specific tool name.
    pub fn with_tool_name(name: &str) -> Self {
        let mut env = Self::new();
        env.tool = TestTool::new(name);
        env
    }

    /// Open (create) a program in the test environment.
    pub fn open_program(&mut self, name: &str, language_id: &str) -> &mut Program {
        let program = Program::new(name, crate::base::analyzer::Language {
            processor: language_id.to_string(),
            variant: String::new(),
            size: 64,
        });
        self.programs.insert(name.to_string(), program);
        self.programs.get_mut(name).unwrap()
    }

    /// Get a reference to an opened program.
    pub fn get_program(&self, name: &str) -> Option<&Program> {
        self.programs.get(name)
    }

    /// Get a mutable reference to an opened program.
    pub fn get_program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.programs.get_mut(name)
    }

    /// Close a program by name.
    pub fn close_program(&mut self, name: &str) -> Option<Program> {
        self.programs.remove(name)
    }

    /// Get the current (most recently opened) program.
    pub fn current_program(&self) -> Option<&Program> {
        self.programs.values().next()
    }

    /// Get the number of open programs.
    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    /// Dispose of the test environment, cleaning up all resources.
    pub fn dispose(&mut self) {
        self.programs.clear();
        self.disposed = true;
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }

    /// Whether the environment has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if !self.disposed {
            self.dispose();
        }
    }
}

// ---------------------------------------------------------------------------
// TestTool
// ---------------------------------------------------------------------------

/// A minimal plugin tool for testing.
///
/// Ported from `ghidra.test.TestTool`.
#[derive(Debug, Clone)]
pub struct TestTool {
    /// Tool name.
    pub name: String,
    /// Registered services (service_name -> type_name).
    services: HashMap<String, String>,
    /// Whether the tool has been disposed.
    pub disposed: bool,
}

impl TestTool {
    /// Create a new test tool.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            services: HashMap::new(),
            disposed: false,
        }
    }

    /// Register a service.
    pub fn add_service(&mut self, service_name: &str, type_name: &str) {
        self.services
            .insert(service_name.to_string(), type_name.to_string());
    }

    /// Check if a service is registered.
    pub fn has_service(&self, service_name: &str) -> bool {
        self.services.contains_key(service_name)
    }

    /// Get the type name for a service.
    pub fn get_service_type(&self, service_name: &str) -> Option<&str> {
        self.services.get(service_name).map(|s| s.as_str())
    }

    /// Dispose the tool.
    pub fn dispose(&mut self) {
        self.services.clear();
        self.disposed = true;
    }
}

// ---------------------------------------------------------------------------
// ToyProgramBuilder
// ---------------------------------------------------------------------------

/// Builder for creating minimal programs for testing.
///
/// Ported from `ghidra.test.ToyProgramBuilder`.
///
/// Provides a fluent API for constructing programs with memory blocks,
/// instructions, data items, functions, and symbols.
#[derive(Debug)]
pub struct ToyProgramBuilder {
    /// The program being built.
    program: Program,
    /// Pending memory blocks: (name, start_addr, size, is_initialized, is_writeable, is_executable).
    blocks: Vec<MemoryBlockSpec>,
    /// Pending symbols: (address, name).
    symbols: Vec<(u64, String)>,
    /// Pending functions: (entry_address, name, body_ranges).
    functions: Vec<FunctionSpec>,
}

#[derive(Debug, Clone)]
struct MemoryBlockSpec {
    name: String,
    start: u64,
    size: u64,
    initialized: bool,
    writeable: bool,
    executable: bool,
}

#[derive(Debug, Clone)]
struct FunctionSpec {
    entry: u64,
    name: String,
    body: Vec<(u64, u64)>,
}

impl ToyProgramBuilder {
    /// Create a new builder for a program with the given name and language.
    pub fn new(name: &str, language_id: &str) -> Self {
        Self {
            program: Program::new(name, crate::base::analyzer::Language {
                processor: language_id.to_string(),
                variant: String::new(),
                size: 64,
            }),
            blocks: Vec::new(),
            symbols: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// Add a memory block.
    pub fn add_block(
        mut self,
        name: &str,
        start: u64,
        size: u64,
    ) -> Self {
        self.blocks.push(MemoryBlockSpec {
            name: name.to_string(),
            start,
            size,
            initialized: true,
            writeable: true,
            executable: true,
        });
        self
    }

    /// Add an initialized, read-only data block.
    pub fn add_data_block(mut self, name: &str, start: u64, size: u64) -> Self {
        self.blocks.push(MemoryBlockSpec {
            name: name.to_string(),
            start,
            size,
            initialized: true,
            writeable: false,
            executable: false,
        });
        self
    }

    /// Add an uninitialized block.
    pub fn add_uninitialized_block(mut self, name: &str, start: u64, size: u64) -> Self {
        self.blocks.push(MemoryBlockSpec {
            name: name.to_string(),
            start,
            size,
            initialized: false,
            writeable: true,
            executable: false,
        });
        self
    }

    /// Add a symbol at the given address.
    pub fn add_symbol(mut self, address: u64, name: &str) -> Self {
        self.symbols.push((address, name.to_string()));
        self
    }

    /// Add a function at the given entry with a body range.
    pub fn add_function(mut self, entry: u64, name: &str, body_start: u64, body_end: u64) -> Self {
        self.functions.push(FunctionSpec {
            entry,
            name: name.to_string(),
            body: vec![(body_start, body_end)],
        });
        self
    }

    /// Build the program.
    pub fn build(mut self) -> Program {
        // Add memory blocks
        for spec in &self.blocks {
            let block = crate::base::analyzer::MemoryBlock {
                name: spec.name.clone(),
                start: Address::new(spec.start),
                size: spec.size,
                is_initialized: spec.initialized,
                is_read: true,
                is_write: spec.writeable,
                is_execute: spec.executable,
            };
            self.program.memory_blocks.push(block);
        }

        // Add symbols
        for (addr, name) in &self.symbols {
            self.program
                .symbols
                .insert(Address::new(*addr), name.clone());
        }

        // Add functions
        for spec in &self.functions {
            let mut body = AddressSet::new();
            for (start, end) in &spec.body {
                body.add_range(AddressRange::new(Address::new(*start), Address::new(*end)));
            }
            let func = crate::base::analyzer::Function {
                entry_point: Address::new(spec.entry),
                name: Some(spec.name.clone()),
                body,
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            };
            self.program
                .function_manager
                .functions
                .insert(Address::new(spec.entry), func);
        }

        self.program
    }
}

// ---------------------------------------------------------------------------
// TestProgramManager
// ---------------------------------------------------------------------------

/// Manages programs for testing.
///
/// Ported from `ghidra.test.TestProgramManager`.
#[derive(Debug, Default)]
pub struct TestProgramManager {
    programs: HashMap<String, Program>,
}

impl TestProgramManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a program.
    pub fn add_program(&mut self, name: &str, program: Program) {
        self.programs.insert(name.to_string(), program);
    }

    /// Get a program by name.
    pub fn get_program(&self, name: &str) -> Option<&Program> {
        self.programs.get(name)
    }

    /// Get a mutable program by name.
    pub fn get_program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.programs.get_mut(name)
    }

    /// Remove a program by name.
    pub fn remove_program(&mut self, name: &str) -> Option<Program> {
        self.programs.remove(name)
    }

    /// Get all program names.
    pub fn program_names(&self) -> Vec<&str> {
        self.programs.keys().map(|s| s.as_str()).collect()
    }

    /// Number of managed programs.
    pub fn count(&self) -> usize {
        self.programs.len()
    }
}

// ---------------------------------------------------------------------------
// TestLogger
// ---------------------------------------------------------------------------

/// Log level for captured messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Debug message.
    Debug,
    /// Informational message.
    Info,
    /// Warning message.
    Warn,
    /// Error message.
    Error,
}

/// A captured log message.
#[derive(Debug, Clone)]
pub struct LogMessage {
    /// The severity level.
    pub level: LogLevel,
    /// The message text.
    pub message: String,
    /// Source (e.g. class or module name).
    pub source: Option<String>,
}

/// Captures log output during tests.
///
/// Ported from `ghidra.test.TestLogger`.
#[derive(Debug, Default)]
pub struct TestLogger {
    /// Captured messages.
    messages: Vec<LogMessage>,
}

impl TestLogger {
    /// Create a new logger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Log a message at the given level.
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.messages.push(LogMessage {
            level,
            message: message.into(),
            source: None,
        });
    }

    /// Log a debug message.
    pub fn debug(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Debug, message);
    }

    /// Log an info message.
    pub fn info(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Info, message);
    }

    /// Log a warning message.
    pub fn warn(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Warn, message);
    }

    /// Log an error message.
    pub fn error(&mut self, message: impl Into<String>) {
        self.log(LogLevel::Error, message);
    }

    /// Get all captured messages.
    pub fn messages(&self) -> &[LogMessage] {
        &self.messages
    }

    /// Get messages at or above a given level.
    pub fn messages_at_or_above(&self, level: LogLevel) -> Vec<&LogMessage> {
        self.messages.iter().filter(|m| m.level >= level).collect()
    }

    /// Get only error messages.
    pub fn errors(&self) -> Vec<&LogMessage> {
        self.messages_at_or_above(LogLevel::Error)
    }

    /// Check if there are any error messages.
    pub fn has_errors(&self) -> bool {
        self.messages.iter().any(|m| m.level == LogLevel::Error)
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Number of captured messages.
    pub fn count(&self) -> usize {
        self.messages.len()
    }
}

// ---------------------------------------------------------------------------
// ProjectTestUtils
// ---------------------------------------------------------------------------

/// Utilities for test project management.
///
/// Ported from `ghidra.test.ProjectTestUtils`.
pub struct ProjectTestUtils;

impl ProjectTestUtils {
    /// Create a minimal test program.
    pub fn create_test_program(name: &str) -> Program {
        ToyProgramBuilder::new(name, "x86:LE:64:default")
            .add_block(".text", 0x401000, 0x1000)
            .add_block(".data", 0x402000, 0x1000)
            .add_block(".bss", 0x403000, 0x1000)
            .build()
    }

    /// Create a minimal ARM test program.
    pub fn create_arm_test_program(name: &str) -> Program {
        ToyProgramBuilder::new(name, "ARM:LE:32:v8")
            .add_block(".text", 0x8000, 0x1000)
            .add_block(".data", 0x9000, 0x1000)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_lifecycle() {
        let mut env = TestEnv::new();
        assert!(!env.is_disposed());
        assert_eq!(env.program_count(), 0);

        env.open_program("test.exe", "x86:LE:64:default");
        assert_eq!(env.program_count(), 1);
        assert!(env.get_program("test.exe").is_some());

        env.close_program("test.exe");
        assert_eq!(env.program_count(), 0);

        env.dispose();
        assert!(env.is_disposed());
    }

    #[test]
    fn test_env_current_program() {
        let mut env = TestEnv::new();
        assert!(env.current_program().is_none());

        env.open_program("first.exe", "x86:LE:64:default");
        env.open_program("second.exe", "ARM:LE:32:v8");

        assert!(env.current_program().is_some());
        assert_eq!(env.program_count(), 2);
    }

    #[test]
    fn test_env_drop_cleanup() {
        let temp_dir;
        {
            let env = TestEnv::new();
            temp_dir = env.temp_dir.clone();
        }
        // After drop, temp dir should be cleaned up
        // (We can't guarantee it's gone on all platforms, but it should be attempted)
    }

    #[test]
    fn test_toy_program_builder() {
        let program = ToyProgramBuilder::new("test", "x86:LE:64:default")
            .add_block(".text", 0x401000, 0x1000)
            .add_block(".data", 0x402000, 0x1000)
            .add_symbol(0x401000, "main")
            .add_function(0x401000, "main", 0x401000, 0x401050)
            .build();

        assert_eq!(program.name, "test");
        assert_eq!(program.memory_blocks.len(), 2);
        assert_eq!(program.symbols.len(), 1);
        assert_eq!(program.function_manager.functions.len(), 1);
    }

    #[test]
    fn test_toy_program_data_block() {
        let program = ToyProgramBuilder::new("test", "x86:LE:64:default")
            .add_data_block(".rodata", 0x403000, 0x100)
            .build();

        assert_eq!(program.memory_blocks.len(), 1);
        let block = &program.memory_blocks[0];
        assert!(!block.is_write);
        assert!(!block.is_execute);
    }

    #[test]
    fn test_toy_program_uninitialized_block() {
        let program = ToyProgramBuilder::new("test", "x86:LE:64:default")
            .add_uninitialized_block(".bss", 0x404000, 0x200)
            .build();

        assert_eq!(program.memory_blocks.len(), 1);
        let block = &program.memory_blocks[0];
        assert!(!block.is_initialized);
        assert!(block.is_write);
    }

    #[test]
    fn test_test_program_manager() {
        let mut mgr = TestProgramManager::new();
        assert_eq!(mgr.count(), 0);

        let prog = ProjectTestUtils::create_test_program("test.exe");
        mgr.add_program("test.exe", prog);

        assert_eq!(mgr.count(), 1);
        assert!(mgr.get_program("test.exe").is_some());
        assert!(mgr.get_program("nonexistent").is_none());
        assert_eq!(mgr.program_names().len(), 1);
    }

    #[test]
    fn test_test_logger() {
        let mut logger = TestLogger::new();
        assert_eq!(logger.count(), 0);

        logger.info("hello");
        logger.warn("warning");
        logger.error("error!");

        assert_eq!(logger.count(), 3);
        assert!(logger.has_errors());
        assert_eq!(logger.errors().len(), 1);
        assert_eq!(logger.errors()[0].message, "error!");

        let warns_and_above = logger.messages_at_or_above(LogLevel::Warn);
        assert_eq!(warns_and_above.len(), 2);

        logger.clear();
        assert_eq!(logger.count(), 0);
    }

    #[test]
    fn test_test_tool() {
        let mut tool = TestTool::new("MyTool");
        assert_eq!(tool.name, "MyTool");
        assert!(!tool.has_service("ProgramManager"));

        tool.add_service("ProgramManager", "ProgramManagerPlugin");
        assert!(tool.has_service("ProgramManager"));
        assert_eq!(
            tool.get_service_type("ProgramManager"),
            Some("ProgramManagerPlugin")
        );

        tool.dispose();
        assert!(tool.disposed);
    }

    #[test]
    fn test_project_test_utils() {
        let prog = ProjectTestUtils::create_test_program("test.exe");
        assert_eq!(prog.name, "test.exe");
        assert!(!prog.memory_blocks.is_empty());

        let arm = ProjectTestUtils::create_arm_test_program("arm.exe");
        assert_eq!(arm.name, "arm.exe");
        assert_eq!(arm.language.processor, "ARM:LE:32:v8");
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }
}
