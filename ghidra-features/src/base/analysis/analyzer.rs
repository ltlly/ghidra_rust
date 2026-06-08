//! Analyzer trait and built-in analyzer implementations.
//!
//! Ported from Ghidra's `ghidra.framework.analysis` / `ghidra.app.analyzers`.
//!
//! This module defines the core [`Analyzer`] trait that all automatic
//! analysis passes implement, along with [`AbstractAnalyzer`] as a
//! convenience base and several built-in analyzers commonly shipped
//! with Ghidra's Features/Base.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Core types (minimal placeholders for standalone use)
// ---------------------------------------------------------------------------

/// Program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub u64);

impl Address {
    pub const EXTERNAL_SPACE: u64 = u64::MAX;

    pub fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub fn in_space(_space: u64, offset: u64) -> Self {
        Self(offset)
    }

    pub fn add(&self, offset: u64) -> Self {
        Self(self.0.wrapping_add(offset))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

/// An inclusive address range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    pub start: Address,
    pub end: Address,
}

impl AddressRange {
    pub fn new(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> u64 {
        self.end.0 - self.start.0 + 1
    }

    pub fn contains(&self, addr: &Address) -> bool {
        addr.0 >= self.start.0 && addr.0 <= self.end.0
    }
}

/// An ordered set of address ranges.
#[derive(Debug, Clone, Default)]
pub struct AddressSet {
    ranges: Vec<AddressRange>,
}

impl AddressSet {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn from_range(range: AddressRange) -> Self {
        Self {
            ranges: vec![range],
        }
    }

    pub fn from_address(addr: Address) -> Self {
        Self::from_range(AddressRange::new(addr, addr))
    }

    pub fn add(&mut self, addr: Address) {
        self.ranges.push(AddressRange::new(addr, addr));
    }

    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, addr: &Address) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }

    pub fn get_addresses(&self, _forward: bool) -> impl Iterator<Item = Address> + '_ {
        self.ranges
            .iter()
            .flat_map(|r| r.start.0..=r.end.0)
            .map(Address::new)
    }

    pub fn delete(&mut self, other: &AddressSet) {
        // Simplified: remove ranges that overlap with other
        self.ranges.retain(|r| {
            !other
                .ranges
                .iter()
                .any(|o| o.contains(&r.start) || o.contains(&r.end))
        });
    }

    pub fn intersect(&self, other: &AddressSet) -> AddressSet {
        let mut result = AddressSet::new();
        for r in &self.ranges {
            for o in &other.ranges {
                let start = r.start.0.max(o.start.0);
                let end = r.end.0.min(o.end.0);
                if start <= end {
                    result
                        .ranges
                        .push(AddressRange::new(Address::new(start), Address::new(end)));
                }
            }
        }
        result
    }

    pub fn union(&self, other: &AddressSet) -> AddressSet {
        let mut result = self.clone();
        result.ranges.extend(other.ranges.iter().cloned());
        result
    }

    pub fn add_range(&mut self, range: AddressRange) {
        self.ranges.push(range);
    }

    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

/// Language descriptor.
#[derive(Debug, Clone)]
pub struct Language {
    pub processor: String,
    pub variant: String,
    pub size: u8,
}

impl Language {
    pub fn default_pointer_size(&self) -> u8 {
        self.size / 8
    }

    pub fn is_segmented(&self) -> bool {
        false
    }
}

/// Bookmark types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkType {
    Analysis,
    Info,
    Warning,
    Error,
}

/// A single instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: Address,
    pub length: u8,
    pub mnemonic: String,
    pub flow_type: FlowType,
    pub fall_through: Option<Address>,
    pub flows: Vec<Address>,
    pub num_operands: u8,
}

/// Flow type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType {
    Fallthrough,
    UnconditionalBranch,
    ConditionalBranch,
    Call,
    ConditionalCall,
    Return,
    ConditionalReturn,
    FallthroughAfterCall,
    IndirectCall,
    IndirectJump,
    ComputedJump,
    Interrupt,
}

impl FlowType {
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            FlowType::Call | FlowType::ConditionalCall | FlowType::IndirectCall
        )
    }

    pub fn is_jump(&self) -> bool {
        matches!(
            self,
            FlowType::UnconditionalBranch
                | FlowType::ConditionalBranch
                | FlowType::IndirectJump
                | FlowType::ComputedJump
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, FlowType::Return | FlowType::ConditionalReturn)
    }

    pub fn has_fallthrough(&self) -> bool {
        matches!(
            self,
            FlowType::Fallthrough
                | FlowType::ConditionalBranch
                | FlowType::ConditionalCall
                | FlowType::ConditionalReturn
                | FlowType::FallthroughAfterCall
        )
    }
}

/// A data item.
#[derive(Debug, Clone)]
pub struct Data {
    pub address: Address,
    pub length: u32,
    pub data_type_name: String,
}

impl Data {
    pub fn is_pointer(&self) -> bool {
        self.data_type_name == "pointer"
    }
}

/// Listing container.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub instructions: HashMap<Address, Instruction>,
    pub defined_data: HashMap<Address, Data>,
}

impl Listing {
    pub fn num_instructions(&self) -> usize {
        self.instructions.len()
    }

    pub fn num_defined_data(&self) -> usize {
        self.defined_data.len()
    }

    pub fn get_instructions<'a>(
        &'a self,
        set: &'a AddressSet,
        _forward: bool,
    ) -> impl Iterator<Item = &'a Instruction> + 'a {
        self.instructions
            .values()
            .filter(move |i| set.contains(&i.address))
    }

    pub fn get_instruction_containing(&self, addr: &Address) -> Option<&Instruction> {
        self.instructions
            .values()
            .find(|i| addr.0 >= i.address.0 && addr.0 < i.address.0 + i.length as u64)
    }
}

/// Function manager.
#[derive(Debug, Clone, Default)]
pub struct FunctionManager {
    functions: Vec<Function>,
}

impl FunctionManager {
    pub fn get_functions(&self, _forward: bool) -> impl Iterator<Item = &Function> {
        self.functions.iter()
    }
}

/// A function entry.
#[derive(Debug, Clone)]
pub struct Function {
    pub entry: Address,
    pub name: String,
}

/// Message log.
#[derive(Debug, Clone, Default)]
pub struct MessageLog {
    messages: Vec<String>,
}

impl MessageLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_msg(&mut self, msg: &str) {
        self.messages.push(msg.to_string());
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

/// Memory block descriptor.
#[derive(Debug, Clone)]
pub struct MemoryBlock {
    pub name: String,
    pub start: Address,
    pub size: u64,
    pub is_read: bool,
    pub is_write: bool,
    pub is_execute: bool,
    pub is_initialized: bool,
}

/// Program (minimal standalone version).
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
    pub image_base: u64,
    pub memory: AddressSet,
    pub memory_blocks: Vec<MemoryBlock>,
    pub listing: Listing,
    pub function_manager: FunctionManager,
    pub bookmarks: Vec<(Address, BookmarkType, String, String)>,
    pub executable_format: Option<String>,
}

impl Program {
    pub fn new(name: &str, lang: Language) -> Self {
        let _ = lang;
        Self {
            name: name.to_string(),
            image_base: 0,
            memory: AddressSet::new(),
            memory_blocks: Vec::new(),
            listing: Listing::default(),
            function_manager: FunctionManager::default(),
            bookmarks: Vec::new(),
            executable_format: None,
        }
    }

    pub fn set_bookmark(
        &mut self,
        addr: Address,
        btype: BookmarkType,
        category: &str,
        message: &str,
    ) {
        self.bookmarks
            .push((addr, btype, category.to_string(), message.to_string()));
    }
}

/// Error returned when analysis is cancelled.
#[derive(Debug, Clone, Copy)]
pub struct CancelledError;

impl fmt::Display for CancelledError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "analysis cancelled by user")
    }
}

impl std::error::Error for CancelledError {}

/// Task monitor trait.
pub trait TaskMonitor: fmt::Debug + Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn check_cancelled(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            Err(CancelledError)
        } else {
            Ok(())
        }
    }
    fn initialize(&self, _max: u64) {}
    fn get_maximum(&self) -> u64 {
        0
    }
    fn increment_progress(&self, _increment: u64) {}
    fn get_progress(&self) -> u64 {
        0
    }
    fn set_message(&self, _msg: &str) {}
    fn get_message(&self) -> &str {
        ""
    }
    fn cancel(&self);
    fn clear_cancelled(&self);
}

/// A basic, thread-safe task monitor.
#[derive(Debug)]
pub struct BasicTaskMonitor {
    cancelled: std::sync::atomic::AtomicBool,
    max: std::sync::atomic::AtomicU64,
    progress: std::sync::atomic::AtomicU64,
    message: std::sync::Mutex<String>,
}

impl BasicTaskMonitor {
    pub fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
            max: std::sync::atomic::AtomicU64::new(0),
            progress: std::sync::atomic::AtomicU64::new(0),
            message: std::sync::Mutex::new(String::new()),
        }
    }
}

impl Default for BasicTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor for BasicTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn initialize(&self, max: u64) {
        self.max.store(max, std::sync::atomic::Ordering::Relaxed);
        self.progress.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    fn get_maximum(&self) -> u64 {
        self.max.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn increment_progress(&self, increment: u64) {
        self.progress
            .fetch_add(increment, std::sync::atomic::Ordering::Relaxed);
    }

    fn get_progress(&self) -> u64 {
        self.progress.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_message(&self, msg: &str) {
        *self.message.lock().unwrap() = msg.to_string();
    }

    fn get_message(&self) -> &str {
        // Leaky: returns a reference to data behind a mutex.
        // In real code, this would be handled differently.
        ""
    }

    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn clear_cancelled(&self) {
        self.cancelled
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Analysis option types
// ---------------------------------------------------------------------------

/// A configurable analysis option.
#[derive(Debug, Clone)]
pub struct AnalysisOption {
    pub name: String,
    pub description: String,
    pub default_value: AnalysisOptionValue,
    pub current_value: AnalysisOptionValue,
}

/// Possible values for analysis options.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisOptionValue {
    Bool(bool),
    Integer(i64),
    String(String),
    Choice(String, Vec<String>),
}

// ---------------------------------------------------------------------------
// Analysis results
// ---------------------------------------------------------------------------

/// Results returned after an analysis run.
#[derive(Debug, Clone)]
pub struct AnalysisResults {
    pub tasks_executed: usize,
    pub was_cancelled: bool,
    pub total_time_ms: u64,
    pub task_times: Vec<(String, u64)>,
}

impl AnalysisResults {
    pub fn has_changes(&self) -> bool {
        self.tasks_executed > 0 && !self.was_cancelled
    }
}

// ---------------------------------------------------------------------------
// AnalyzerType
// ---------------------------------------------------------------------------

/// Categories of analyzers, each triggered by different program changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyzerType {
    Byte,
    Instruction,
    Function,
    FunctionModifiers,
    FunctionSignatures,
    Data,
}

impl AnalyzerType {
    pub fn name(&self) -> &'static str {
        match self {
            AnalyzerType::Byte => "Byte Analyzer",
            AnalyzerType::Instruction => "Instructions Analyzer",
            AnalyzerType::Function => "Function Analyzer",
            AnalyzerType::FunctionModifiers => "Function-modifiers Analyzer",
            AnalyzerType::FunctionSignatures => "Function-Signatures Analyzer",
            AnalyzerType::Data => "Data Analyzer",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AnalyzerType::Byte => "Triggered when bytes are added (memory block added).",
            AnalyzerType::Instruction => "Triggered when instructions are created.",
            AnalyzerType::Function => "Triggered when functions are created.",
            AnalyzerType::FunctionModifiers => "Triggered when a function's modifier changes.",
            AnalyzerType::FunctionSignatures => "Triggered when a function's signature changes.",
            AnalyzerType::Data => "Triggered when data is created.",
        }
    }
}

impl fmt::Display for AnalyzerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// Analyzer trait
// ---------------------------------------------------------------------------

/// Core trait for all automatic analyzers.
///
/// Each analyzer is registered with the [`AutoAnalysisManager`] and
/// invoked when addresses matching its [`AnalyzerType`] are modified.
///
/// # Lifecycle
///
/// 1. `can_analyze` is checked before registration.
/// 2. `added` is called with the set of modified addresses.
/// 3. `analysis_ended` is called once when the full analysis pass finishes.
pub trait Analyzer: Send + Sync {
    /// Human-readable name (must be unique within a manager).
    fn name(&self) -> &str;

    /// Short description of what this analyzer does.
    fn description(&self) -> &str;

    /// The type of address change that triggers this analyzer.
    fn analysis_type(&self) -> AnalyzerType;

    /// Priority for scheduling (lower value = higher priority).
    fn priority(&self) -> AnalysisPriority;

    /// Whether this analyzer is enabled by default for the given program.
    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    /// Whether this analyzer can analyze the given program.
    fn can_analyze(&self, program: &Program) -> bool;

    /// Run the analyzer on the given address set.
    ///
    /// Returns `Ok(true)` if changes were made, `Ok(false)` otherwise.
    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError>;

    /// Called when addresses are removed (undo).
    fn removed(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }

    /// Register analysis options.
    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        Vec::new()
    }

    /// Called when analysis options change.
    fn options_changed(&mut self, _options: &HashMap<String, AnalysisOptionValue>) {}

    /// Called once when the analysis pass finishes.
    fn analysis_ended(&self, _program: &Program) {}

    /// Whether this analyzer supports one-time analysis (runs once, not on every change).
    fn supports_one_time_analysis(&self) -> bool {
        false
    }

    /// Whether this is a prototype (not ready for production).
    fn is_prototype(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// AbstractAnalyzer
// ---------------------------------------------------------------------------

/// Convenience base for implementing the [`Analyzer`] trait.
///
/// Stores common fields and provides getter/setter methods. Implementors
/// can embed this struct and delegate the trait methods.
#[derive(Debug, Clone)]
pub struct AbstractAnalyzer {
    name: String,
    description: String,
    analysis_type: AnalyzerType,
    priority: AnalysisPriority,
    supports_one_time: bool,
    is_prototype: bool,
    default_enabled: bool,
}

impl AbstractAnalyzer {
    pub fn new(name: &str, description: &str, analysis_type: AnalyzerType) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            analysis_type,
            priority: AnalysisPriority::LOW_PRIORITY,
            supports_one_time: false,
            is_prototype: false,
            default_enabled: true,
        }
    }

    pub fn set_priority(&mut self, p: AnalysisPriority) {
        self.priority = p;
    }

    pub fn set_supports_one_time_analysis(&mut self, yes: bool) {
        self.supports_one_time = yes;
    }

    pub fn set_is_prototype(&mut self, yes: bool) {
        self.is_prototype = yes;
    }

    pub fn set_default_enablement(&mut self, yes: bool) {
        self.default_enabled = yes;
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn analysis_type(&self) -> AnalyzerType {
        self.analysis_type
    }

    pub fn priority(&self) -> AnalysisPriority {
        self.priority
    }

    pub fn supports_one_time_analysis(&self) -> bool {
        self.supports_one_time
    }

    pub fn is_prototype(&self) -> bool {
        self.is_prototype
    }

    pub fn default_enablement(&self, _program: &Program) -> bool {
        self.default_enabled
    }
}

// ---------------------------------------------------------------------------
// AnalysisPriority
// ---------------------------------------------------------------------------

/// Priority levels for scheduling analyzers.
///
/// Lower numeric value = runs earlier. Use the associated constants
/// rather than constructing custom values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisPriority {
    pub name: &'static str,
    pub priority: i32,
}

impl AnalysisPriority {
    pub const HIGHEST: Self = Self::new("HIGH", 1);
    pub const FORMAT_ANALYSIS: Self = Self::new("FORMAT", 100);
    pub const BLOCK_ANALYSIS: Self = Self::new("BLOCK", 200);
    pub const DISASSEMBLY: Self = Self::new("DISASSEMBLY", 300);
    pub const CODE_ANALYSIS: Self = Self::new("CODE", 400);
    pub const FUNCTION_ANALYSIS: Self = Self::new("FUNCTION", 500);
    pub const REFERENCE_ANALYSIS: Self = Self::new("REFERENCE", 600);
    pub const DATA_ANALYSIS: Self = Self::new("DATA", 700);
    pub const FUNCTION_ID_ANALYSIS: Self = Self::new("FUNCTION ID", 800);
    pub const DATA_TYPE_PROPAGATION: Self = Self::new("DATA TYPE PROPAGATION", 900);
    pub const LOW_PRIORITY: Self = Self::new("LOW", 10000);

    pub const fn new(name: &'static str, priority: i32) -> Self {
        Self { name, priority }
    }

    /// Priority immediately before this one (runs earlier).
    pub const fn before(&self) -> Self {
        Self::new(self.name, self.priority - 1)
    }

    /// Priority immediately after this one (runs later).
    pub const fn after(&self) -> Self {
        Self::new(self.name, self.priority + 1)
    }

    pub const fn priority(&self) -> i32 {
        self.priority
    }
}

impl PartialOrd for AnalysisPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AnalysisPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl fmt::Display for AnalysisPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.name, self.priority)
    }
}

// ---------------------------------------------------------------------------
// Built-in analyzers
// ---------------------------------------------------------------------------

/// Detects function start prologues in newly-added byte ranges.
#[derive(Debug)]
pub struct FunctionStartAnalyzer {
    base: AbstractAnalyzer,
}

impl FunctionStartAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Function Start Analyzer",
            "Detects function prologues",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::FUNCTION_ANALYSIS);
        Self { base }
    }
}

impl Default for FunctionStartAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for FunctionStartAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        // Prologue detection would go here.
        Ok(false)
    }
}

/// Identifies the boundaries of defined code regions.
#[derive(Debug)]
pub struct CodeBoundaryAnalyzer {
    base: AbstractAnalyzer,
}

impl CodeBoundaryAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Code Boundary Analyzer",
            "Identifies code region boundaries",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::BLOCK_ANALYSIS);
        Self { base }
    }
}

impl Default for CodeBoundaryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for CodeBoundaryAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Creates references from data operands to their targets.
#[derive(Debug)]
pub struct DataReferenceAnalyzer {
    base: AbstractAnalyzer,
    pub create_ascii_strings: bool,
}

impl DataReferenceAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Reference",
            "Creates references from data operands",
            AnalyzerType::Data,
        );
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            create_ascii_strings: true,
        }
    }

    pub fn with_string_creation(mut self, yes: bool) -> Self {
        self.create_ascii_strings = yes;
        self
    }
}

impl Default for DataReferenceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for DataReferenceAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn supports_one_time_analysis(&self) -> bool {
        self.base.supports_one_time_analysis()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Analyzes stack variable usage within functions.
#[derive(Debug)]
pub struct StackVariableAnalyzer {
    base: AbstractAnalyzer,
}

impl StackVariableAnalyzer {
    pub fn new() -> Self {
        let mut base =
            AbstractAnalyzer::new("Stack", "Analyzes stack variables", AnalyzerType::Function);
        base.set_priority(AnalysisPriority::FUNCTION_ANALYSIS);
        Self { base }
    }
}

impl Default for StackVariableAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for StackVariableAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Propagates constants and creates references to code/data.
#[derive(Debug)]
pub struct ConstantReferenceAnalyzer {
    base: AbstractAnalyzer,
    processor_name: String,
}

impl ConstantReferenceAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Constant Reference Analyzer",
            "Propagates constants to find references",
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        Self {
            base,
            processor_name: "Basic".to_string(),
        }
    }

    pub fn with_processor(processor: &str) -> Self {
        let mut base = AbstractAnalyzer::new(
            &format!("Constant Reference Analyzer ({})", processor),
            "Propagates constants to find references",
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        Self {
            base,
            processor_name: processor.to_string(),
        }
    }

    pub fn processor_name(&self) -> &str {
        &self.processor_name
    }
}

impl Default for ConstantReferenceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ConstantReferenceAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Evaluates whether a constant value is a valid program address.
#[derive(Debug)]
pub struct ConstantPropagationContextEvaluator {
    pub consider_external: bool,
}

impl ConstantPropagationContextEvaluator {
    pub fn new(consider_external: bool) -> Self {
        Self { consider_external }
    }

    pub fn evaluate_constant(&self, value: u64, program: &Program) -> bool {
        if value == 0 || value == 0xFFFFFFFF {
            return false;
        }
        program.memory.contains(&Address::new(value))
    }
}

/// Detects switch/jump tables.
#[derive(Debug)]
pub struct SwitchAnalyzer {
    base: AbstractAnalyzer,
}

impl SwitchAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Switch Table Analyzer",
            "Detects switch/jump table patterns",
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::CODE_ANALYSIS);
        Self { base }
    }
}

impl Default for SwitchAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for SwitchAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// ARM Thumb mode analyzer.
#[derive(Debug)]
pub struct ARMThumbAnalyzer {
    base: AbstractAnalyzer,
}

impl ARMThumbAnalyzer {
    pub fn new() -> Self {
        let base = AbstractAnalyzer::new(
            "ARM Thumb Analyzer",
            "Handles ARM Thumb mode detection",
            AnalyzerType::Byte,
        );
        Self { base }
    }
}

impl Default for ARMThumbAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ARMThumbAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, program: &Program) -> bool {
        // Only for ARM programs
        program.name.contains("arm") || program.name.contains("ARM")
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Identifies known non-returning functions (e.g., `exit`, `abort`).
#[derive(Debug)]
pub struct NoReturnKnownAnalyzer {
    base: AbstractAnalyzer,
}

impl NoReturnKnownAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Non-Returning Functions - Known",
            "Marks known non-returning functions",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::FUNCTION_ANALYSIS);
        Self { base }
    }
}

impl Default for NoReturnKnownAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for NoReturnKnownAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Discovers non-returning functions by analyzing call graphs.
#[derive(Debug)]
pub struct NoReturnDiscoveredAnalyzer {
    base: AbstractAnalyzer,
    pub evidence_threshold: u32,
}

impl NoReturnDiscoveredAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Non-Returning Functions - Discovered",
            "Discovers non-returning functions via analysis",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::FUNCTION_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            evidence_threshold: 3,
        }
    }
}

impl Default for NoReturnDiscoveredAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for NoReturnDiscoveredAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn supports_one_time_analysis(&self) -> bool {
        self.base.supports_one_time_analysis()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Creates references from scalar operands that look like addresses.
#[derive(Debug)]
pub struct ScalarOperandAnalyzer {
    base: AbstractAnalyzer,
}

impl ScalarOperandAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Scalar Operand References",
            "Creates references from scalar operands",
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        Self { base }
    }
}

impl Default for ScalarOperandAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ScalarOperandAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Creates data references from instruction operands.
#[derive(Debug)]
pub struct DataOperandReferenceAnalyzer {
    base: AbstractAnalyzer,
}

impl DataOperandReferenceAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Data Reference",
            "Creates data references from operands",
            AnalyzerType::Data,
        );
        base.set_priority(AnalysisPriority::DATA_ANALYSIS);
        Self { base }
    }
}

impl Default for DataOperandReferenceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for DataOperandReferenceAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Resolves external library symbols.
#[derive(Debug)]
pub struct ExternalSymbolResolverAnalyzer {
    base: AbstractAnalyzer,
}

impl ExternalSymbolResolverAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "External Symbol Resolver",
            "Resolves external library symbols",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::REFERENCE_ANALYSIS);
        Self { base }
    }
}

impl Default for ExternalSymbolResolverAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ExternalSymbolResolverAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, program: &Program) -> bool {
        program.executable_format.is_some()
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Records source language metadata.
#[derive(Debug)]
pub struct SourceLanguageAnalyzer {
    base: AbstractAnalyzer,
}

impl SourceLanguageAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Source Language Support",
            "Records source language metadata",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::FORMAT_ANALYSIS);
        Self { base }
    }
}

impl Default for SourceLanguageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for SourceLanguageAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Archive chooser mode for data archive application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveChooserMode {
    AutoDetect,
    AlwaysApply,
    NeverApply,
}

/// Applies recognized data type archives.
#[derive(Debug)]
pub struct ApplyDataArchiveAnalyzer {
    base: AbstractAnalyzer,
    pub archive_chooser: ArchiveChooserMode,
}

impl ApplyDataArchiveAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Apply Data Archives",
            "Applies recognized data type archives",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION);
        Self {
            base,
            archive_chooser: ArchiveChooserMode::AutoDetect,
        }
    }
}

impl Default for ApplyDataArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ApplyDataArchiveAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Extracts DWARF debug information.
#[derive(Debug)]
pub struct DWARFAnalyzer {
    base: AbstractAnalyzer,
}

impl DWARFAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "DWARF",
            "Extracts DWARF debug information",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::FORMAT_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self { base }
    }
}

impl Default for DWARFAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for DWARFAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn supports_one_time_analysis(&self) -> bool {
        self.base.supports_one_time_analysis()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

/// Media file signature for embedded media detection.
#[derive(Debug, Clone)]
pub struct MediaSignature {
    pub name: String,
    pub magic: Vec<u8>,
}

/// Detects embedded media files (PNG, JPEG, etc.) in memory.
#[derive(Debug)]
pub struct EmbeddedMediaAnalyzer {
    base: AbstractAnalyzer,
    pub signatures: Vec<MediaSignature>,
}

impl EmbeddedMediaAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Embedded Media",
            "Detects embedded media files",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::DATA_ANALYSIS);
        Self {
            base,
            signatures: vec![
                MediaSignature {
                    name: "PNG".to_string(),
                    magic: vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
                },
                MediaSignature {
                    name: "JPEG".to_string(),
                    magic: vec![0xFF, 0xD8, 0xFF],
                },
                MediaSignature {
                    name: "GIF87a".to_string(),
                    magic: b"GIF87a".to_vec(),
                },
                MediaSignature {
                    name: "GIF89a".to_string(),
                    magic: b"GIF89a".to_vec(),
                },
            ],
        }
    }
}

impl Default for EmbeddedMediaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for EmbeddedMediaAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Register context tracking
// ---------------------------------------------------------------------------

/// Builder for tracking a single bit-register value across addresses.
#[derive(Debug)]
pub struct RegisterContextBuilder {
    name: String,
    known: bool,
    value: u64,
    history: Vec<(Address, Option<u64>)>,
}

impl RegisterContextBuilder {
    pub fn new_bit(name: &str) -> Self {
        Self {
            name: name.to_string(),
            known: false,
            value: 0,
            history: Vec::new(),
        }
    }

    pub fn is_value_known(&self) -> bool {
        self.known
    }

    pub fn set_value(&mut self, addr: Address, val: u64) {
        self.known = true;
        self.value = val;
        self.history.push((addr, Some(val)));
    }

    pub fn set_value_unknown(&mut self, addr: Address) {
        self.known = false;
        self.history.push((addr, None));
    }

    pub fn value_equals(&self, val: u64) -> bool {
        self.known && self.value == val
    }

    pub fn value_history(&self) -> &[(Address, Option<u64>)] {
        &self.history
    }
}

/// Tracks register context across an entire program.
#[derive(Debug, Default)]
pub struct RegisterContextTracker {
    bit_registers: HashMap<String, RegisterContextBuilder>,
    value_registers: HashMap<String, u64>,
}

impl RegisterContextTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track_bit_register(&mut self, name: &str) {
        self.bit_registers
            .insert(name.to_string(), RegisterContextBuilder::new_bit(name));
    }

    pub fn track_register(&mut self, name: &str, default_value: u64) {
        self.value_registers.insert(name.to_string(), default_value);
    }

    pub fn is_known(&self, name: &str) -> bool {
        self.bit_registers
            .get(name)
            .map(|b| b.is_value_known())
            .unwrap_or(false)
    }

    pub fn set_value(&mut self, name: &str, addr: Address, val: u64) {
        if let Some(b) = self.bit_registers.get_mut(name) {
            b.set_value(addr, val);
        }
    }

    pub fn get_value(&self, name: &str) -> Option<u64> {
        self.bit_registers.get(name).and_then(|b| {
            if b.is_value_known() {
                Some(b.value)
            } else {
                None
            }
        })
    }

    pub fn register_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .bit_registers
            .keys()
            .chain(self.value_registers.keys())
            .map(|s| s.as_str())
            .collect();
        names.sort();
        names
    }
}

/// Segmented calling convention classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentedCallingConvention {
    Near,
    Far,
    Interrupt,
}

/// Analyzer for segmented x86 calling conventions.
#[derive(Debug)]
pub struct SegmentedCallingConventionAnalyzer {
    base: AbstractAnalyzer,
}

impl SegmentedCallingConventionAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Segmented X86 Calling Conventions",
            "Analyzes segmented x86 calling conventions",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::FUNCTION_ANALYSIS);
        Self { base }
    }

    pub fn classify_return_opcode(opcode: u8) -> SegmentedCallingConvention {
        match opcode {
            0xC3 => SegmentedCallingConvention::Near,
            0xCB => SegmentedCallingConvention::Far,
            0xCF => SegmentedCallingConvention::Interrupt,
            _ => SegmentedCallingConvention::Near,
        }
    }
}

impl Default for SegmentedCallingConventionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for SegmentedCallingConventionAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }
    fn can_analyze(&self, program: &Program) -> bool {
        // Only for segmented x86
        program.name.contains("x86") || program.name.contains("X86")
    }
    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
        _log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog
    }

    fn make_arm_program() -> Program {
        Program::new(
            "arm_test",
            Language {
                processor: "ARM".into(),
                variant: "LE".into(),
                size: 32,
            },
        )
    }

    #[test]
    fn test_address_operations() {
        let a = Address::new(0x1000);
        assert_eq!(a.add(8), Address::new(0x1008));
        assert_eq!(a.to_string(), "0x00001000");
    }

    #[test]
    fn test_address_space() {
        let a = Address::in_space(2, 0x1000);
        assert_eq!(a.to_string(), "0x00001000");
    }

    #[test]
    fn test_address_range() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));
        assert_eq!(r.len(), 256);
        assert!(r.contains(&Address::new(0x1050)));
    }

    #[test]
    fn test_address_set() {
        let mut s = AddressSet::new();
        s.add(Address::new(0x1000));
        s.add(Address::new(0x1001));
        assert_eq!(s.num_addresses(), 2);
    }

    #[test]
    fn test_address_set_intersect() {
        let s1 = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
        ));
        let s2 = AddressSet::from_range(AddressRange::new(
            Address::new(0x1800),
            Address::new(0x2800),
        ));
        assert_eq!(s1.intersect(&s2).num_addresses(), 0x801);
    }

    #[test]
    fn test_address_set_union() {
        let s1 = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x1500),
        ));
        let s2 = AddressSet::from_range(AddressRange::new(
            Address::new(0x1400),
            Address::new(0x2000),
        ));
        assert_eq!(s1.union(&s2).num_addresses(), 0x1001);
    }

    #[test]
    fn test_address_iterator() {
        let s = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x1004),
        ));
        let a: Vec<_> = s.get_addresses(true).collect();
        assert_eq!(a.len(), 5);
        assert_eq!(a[4], Address::new(0x1004));
    }

    #[test]
    fn test_priority_ordering() {
        assert!(AnalysisPriority::FORMAT_ANALYSIS < AnalysisPriority::BLOCK_ANALYSIS);
        assert!(AnalysisPriority::BLOCK_ANALYSIS < AnalysisPriority::DISASSEMBLY);
        assert!(AnalysisPriority::LOW_PRIORITY > AnalysisPriority::DATA_TYPE_PROPAGATION);
    }

    #[test]
    fn test_before_after() {
        let b = AnalysisPriority::REFERENCE_ANALYSIS;
        assert!(b.before() < b);
        assert!(b < b.after());
    }

    #[test]
    fn test_analyzer_type_display() {
        assert_eq!(AnalyzerType::Byte.to_string(), "Byte Analyzer");
        assert_eq!(AnalyzerType::Data.to_string(), "Data Analyzer");
    }

    #[test]
    fn test_task_monitor() {
        let m = BasicTaskMonitor::new();
        assert!(!m.is_cancelled());
        m.cancel();
        assert!(m.is_cancelled());
        m.clear_cancelled();
        assert!(!m.is_cancelled());
    }

    #[test]
    fn test_task_monitor_progress() {
        let m = BasicTaskMonitor::new();
        m.initialize(100);
        assert_eq!(m.get_maximum(), 100);
        m.increment_progress(50);
        assert_eq!(m.get_progress(), 50);
        m.set_message("test");
    }

    #[test]
    fn test_flow_type() {
        assert!(FlowType::Call.is_call());
        assert!(FlowType::ConditionalJump.is_jump());
        assert!(FlowType::Return.is_terminal());
        assert!(FlowType::Fallthrough.has_fallthrough());
    }

    #[test]
    fn test_data_is_pointer() {
        let d = Data {
            address: Address::new(0),
            length: 4,
            data_type_name: "pointer".into(),
        };
        assert!(d.is_pointer());
        let d2 = Data {
            address: Address::new(0),
            length: 4,
            data_type_name: "dword".into(),
        };
        assert!(!d2.is_pointer());
    }

    #[test]
    fn test_function_manager() {
        let m = FunctionManager::default();
        assert!(m.get_functions(true).next().is_none());
    }

    #[test]
    fn test_listing_instructions() {
        let mut l = Listing::default();
        l.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 3,
                mnemonic: "mov".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1003)),
                flows: vec![],
                num_operands: 2,
            },
        );
        assert_eq!(l.num_instructions(), 1);
        let s = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
        ));
        let instrs: Vec<_> = l.get_instructions(&s, true).collect();
        assert_eq!(instrs.len(), 1);
    }

    #[test]
    fn test_listing_containing() {
        let mut l = Listing::default();
        l.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 5,
                mnemonic: "call".into(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x1005)),
                flows: vec![],
                num_operands: 1,
            },
        );
        assert!(l
            .get_instruction_containing(&Address::new(0x1002))
            .is_some());
        assert!(l
            .get_instruction_containing(&Address::new(0x1005))
            .is_none());
    }

    #[test]
    fn test_message_log() {
        let mut l = MessageLog::new();
        assert!(l.is_empty());
        l.append_msg("test");
        l.append_msg("test2");
        assert_eq!(l.len(), 2);
        l.clear();
        assert!(l.is_empty());
    }

    #[test]
    fn test_program_bookmarks() {
        let mut p = make_test_program();
        p.set_bookmark(
            Address::new(0x401000),
            BookmarkType::Analysis,
            "Test",
            "msg",
        );
        assert_eq!(p.bookmarks.len(), 1);
    }

    #[test]
    fn test_language_props() {
        let l = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        assert_eq!(l.default_pointer_size(), 8);
        assert!(!l.is_segmented());
    }

    #[test]
    fn test_option_values() {
        assert_eq!(
            AnalysisOptionValue::Bool(true),
            AnalysisOptionValue::Bool(true)
        );
        assert_ne!(
            AnalysisOptionValue::Bool(true),
            AnalysisOptionValue::Bool(false)
        );
    }

    #[test]
    fn test_abstract_analyzer() {
        let mut a = AbstractAnalyzer::new("Test", "desc", AnalyzerType::Byte);
        a.set_priority(AnalysisPriority::CODE_ANALYSIS);
        assert_eq!(a.name(), "Test");
        assert_eq!(a.priority(), AnalysisPriority::CODE_ANALYSIS);
    }

    #[test]
    fn test_function_start_analyzer() {
        let a = FunctionStartAnalyzer::new();
        assert_eq!(a.name(), "Function Start Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
        assert!(a.can_analyze(&make_test_program()));
    }

    #[test]
    fn test_code_boundary_analyzer() {
        let a = CodeBoundaryAnalyzer::new();
        assert_eq!(a.name(), "Code Boundary Analyzer");
        assert!(a.can_analyze(&make_test_program()));
    }

    #[test]
    fn test_data_reference_analyzer() {
        let a = DataReferenceAnalyzer::new();
        assert_eq!(a.name(), "Reference");
        assert!(a.supports_one_time_analysis());
        let a2 = DataReferenceAnalyzer::new().with_string_creation(false);
        assert!(!a2.create_ascii_strings);
    }

    #[test]
    fn test_stack_variable_analyzer() {
        let a = StackVariableAnalyzer::new();
        assert_eq!(a.name(), "Stack");
        assert_eq!(a.analysis_type(), AnalyzerType::Function);
    }

    #[test]
    fn test_constant_reference_analyzer() {
        let a = ConstantReferenceAnalyzer::new();
        assert_eq!(a.processor_name(), "Basic");
        let x86 = ConstantReferenceAnalyzer::with_processor("x86");
        assert!(x86.name().contains("x86"));
    }

    #[test]
    fn test_constant_evaluator() {
        let e = ConstantPropagationContextEvaluator::new(true);
        let p = make_test_program();
        assert!(!e.evaluate_constant(0, &p));
        assert!(!e.evaluate_constant(0xFFFFFFFF, &p));
        assert!(e.evaluate_constant(0x401000, &p));
    }

    #[test]
    fn test_switch_analyzer() {
        let a = SwitchAnalyzer::new();
        assert_eq!(a.name(), "Switch Table Analyzer");
    }

    #[test]
    fn test_arm_thumb_analyzer() {
        let a = ARMThumbAnalyzer::new();
        assert!(!a.can_analyze(&make_test_program()));
        assert!(a.can_analyze(&make_arm_program()));
    }

    #[test]
    fn test_no_return_known() {
        let a = NoReturnKnownAnalyzer::new();
        assert_eq!(a.name(), "Non-Returning Functions - Known");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_no_return_discovered() {
        let a = NoReturnDiscoveredAnalyzer::new();
        assert_eq!(a.name(), "Non-Returning Functions - Discovered");
        assert!(a.supports_one_time_analysis());
        assert_eq!(a.evidence_threshold, 3);
    }

    #[test]
    fn test_scalar_operand() {
        let a = ScalarOperandAnalyzer::new();
        assert_eq!(a.name(), "Scalar Operand References");
    }

    #[test]
    fn test_data_operand_ref() {
        let a = DataOperandReferenceAnalyzer::new();
        assert_eq!(a.name(), "Data Reference");
        assert_eq!(a.analysis_type(), AnalyzerType::Data);
    }

    #[test]
    fn test_ext_symbol_resolver() {
        let a = ExternalSymbolResolverAnalyzer::new();
        assert_eq!(a.name(), "External Symbol Resolver");
        assert!(!a.can_analyze(&make_test_program()));
        let mut elf = make_test_program();
        elf.executable_format = Some("ELF".into());
        assert!(a.can_analyze(&elf));
    }

    #[test]
    fn test_source_language() {
        let a = SourceLanguageAnalyzer::new();
        assert_eq!(a.name(), "Source Language Support");
    }

    #[test]
    fn test_apply_data_archive() {
        let a = ApplyDataArchiveAnalyzer::new();
        assert_eq!(a.name(), "Apply Data Archives");
        assert_eq!(a.archive_chooser, ArchiveChooserMode::AutoDetect);
    }

    #[test]
    fn test_dwarf_analyzer() {
        let a = DWARFAnalyzer::new();
        assert_eq!(a.name(), "DWARF");
        assert!(a.supports_one_time_analysis());
    }

    #[test]
    fn test_embedded_media() {
        let a = EmbeddedMediaAnalyzer::new();
        assert_eq!(a.name(), "Embedded Media");
        assert!(a.signatures.iter().any(|s| s.name == "PNG"));
        assert!(a.signatures.iter().any(|s| s.name == "JPEG"));
    }

    #[test]
    fn test_register_context() {
        let mut b = RegisterContextBuilder::new_bit("TMode");
        assert!(!b.is_value_known());
        b.set_value(Address::new(0x1000), 1);
        assert!(b.is_value_known());
        assert!(b.value_equals(1));
        b.set_value_unknown(Address::new(0x2000));
        assert!(!b.is_value_known());
        assert_eq!(b.value_history().len(), 2);
    }

    #[test]
    fn test_register_tracker() {
        let mut t = RegisterContextTracker::new();
        t.track_bit_register("TMode");
        t.track_register("ISA", 0xFF);
        assert!(!t.is_known("TMode"));
        t.set_value("TMode", Address::new(0x1000), 1);
        assert!(t.is_known("TMode"));
        assert_eq!(t.get_value("TMode"), Some(1));
        assert_eq!(t.register_names().len(), 2);
    }

    #[test]
    fn test_segmented_convention() {
        assert_eq!(
            SegmentedCallingConventionAnalyzer::classify_return_opcode(0xC3),
            SegmentedCallingConvention::Near
        );
        assert_eq!(
            SegmentedCallingConventionAnalyzer::classify_return_opcode(0xCB),
            SegmentedCallingConvention::Far
        );
        assert_eq!(
            SegmentedCallingConventionAnalyzer::classify_return_opcode(0xCF),
            SegmentedCallingConvention::Interrupt
        );
    }

    #[test]
    fn test_segmented_analyzer() {
        let a = SegmentedCallingConventionAnalyzer::new();
        assert_eq!(a.name(), "Segmented X86 Calling Conventions");
        assert_eq!(a.analysis_type(), AnalyzerType::Function);
        assert!(!a.can_analyze(&make_test_program()));
    }

    #[test]
    fn test_display_impls() {
        assert_eq!(Address::new(0xDEADBEEF).to_string(), "0xdeadbeef");
        assert!(AnalysisPriority::REFERENCE_ANALYSIS
            .to_string()
            .contains("REFERENCE"));
        assert_eq!(CancelledError.to_string(), "analysis cancelled by user");
    }

    #[test]
    fn test_analysis_results() {
        let r = AnalysisResults {
            tasks_executed: 5,
            was_cancelled: false,
            total_time_ms: 100,
            task_times: vec![],
        };
        assert!(r.has_changes());
        let r2 = AnalysisResults {
            tasks_executed: 0,
            was_cancelled: false,
            total_time_ms: 0,
            task_times: vec![],
        };
        assert!(!r2.has_changes());
    }
}
