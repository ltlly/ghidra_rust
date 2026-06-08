//! Comparison data abstractions and panel state management.
//!
//! Ported from Ghidra's `ghidra.features.base.codecompare.panel` Java package.
//!
//! This module provides the data abstractions used by comparison views
//! to represent what is being compared, along with state management for
//! saving and restoring comparison panel configurations.
//!
//! # Submodules
//!
//! - [`action_context`] -- action contexts for code comparison views
//! - [`code_comparison_view`] -- abstract base for code comparison views
//! - [`data_comparison`] -- ComparisonData implementation for Data objects
//! - [`function_comparison_panel`] -- top-level panel managing multiple comparison views
//! - [`function_comparison_state`] -- shared state for function comparison providers
//!
//! # Key types
//!
//! - [`ComparisonData`] -- trait for data that can be compared
//! - [`FunctionComparisonData`] -- comparison data backed by a function
//! - [`AddressSetComparisonData`] -- comparison data backed by an address range
//! - [`EmptyComparisonData`] -- sentinel for when nothing is selected
//! - [`ComparisonViewState`] -- per-view type save state
//! - [`ComparisonPanelState`] -- top-level panel state

pub mod action_context;
pub mod code_comparison_view;
pub mod comparison_actions;
pub mod data_comparison;
pub mod function_comparison_panel;
pub mod function_comparison_state;

use std::collections::HashMap;

/// An address range, representing a contiguous span of addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressRange {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (inclusive).
    pub end: u64,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Number of addresses in this range.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if the range contains an address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }
}

/// A set of address ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSet {
    ranges: Vec<AddressRange>,
}

impl AddressSet {
    /// Create an empty address set.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Create an address set with a single range.
    pub fn single(start: u64, end: u64) -> Self {
        Self {
            ranges: vec![AddressRange::new(start, end)],
        }
    }

    /// Add a range to the set.
    pub fn add(&mut self, start: u64, end: u64) {
        self.ranges.push(AddressRange::new(start, end));
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get the minimum address.
    pub fn min_address(&self) -> Option<u64> {
        self.ranges.iter().map(|r| r.start).min()
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> Option<u64> {
        self.ranges.iter().map(|r| r.end).max()
    }

    /// Check if the set contains an address.
    pub fn contains(&self, address: u64) -> bool {
        self.ranges.iter().any(|r| r.contains(address))
    }

    /// Get the number of ranges.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Iterate over ranges.
    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }

    /// Total number of addresses in the set.
    pub fn total_size(&self) -> u64 {
        self.ranges.iter().map(|r| r.size()).sum()
    }
}

impl Default for AddressSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a program for comparison purposes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProgramInfo {
    /// Unique program identifier.
    pub id: u64,
    /// File system path to the program.
    pub path: String,
    /// Program name.
    pub name: String,
}

impl ProgramInfo {
    /// Create new program info.
    pub fn new(id: u64, path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id,
            path: path.into(),
            name: name.into(),
        }
    }
}

/// A program location (address within a program).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramLocation {
    /// The program.
    pub program: ProgramInfo,
    /// The address.
    pub address: u64,
}

impl ProgramLocation {
    /// Create a new program location.
    pub fn new(program: ProgramInfo, address: u64) -> Self {
        Self { program, address }
    }
}

/// Trait for data that can be compared in a code comparison view.
///
/// Not all comparison views can handle all types of comparison data.
/// For example, the decompiler comparison only works when the comparison
/// data is a function.
///
/// Ported from Ghidra's `ComparisonData` Java interface.
pub trait ComparisonData {
    /// Returns the function being compared, or None if not function-based.
    fn get_function(&self) -> Option<&FunctionComparisonInfo>;

    /// Returns the address set being compared.
    fn get_address_set(&self) -> &AddressSet;

    /// Returns the program info for the data being compared.
    fn get_program(&self) -> Option<&ProgramInfo>;

    /// Returns a description of the data being compared (may contain HTML).
    fn get_description(&self) -> String;

    /// Returns a short description (useful for tab names).
    fn get_short_description(&self) -> String;

    /// Returns true if this comparison has no data to compare.
    fn is_empty(&self) -> bool;

    /// Returns the initial program location for the cursor.
    fn get_initial_location(&self) -> Option<ProgramLocation>;
}

/// Information about a function for comparison display purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionComparisonInfo {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_point: u64,
    /// Whether this is an external function.
    pub is_external: bool,
    /// Function body start address.
    pub body_start: u64,
    /// Function body end address.
    pub body_end: u64,
    /// Program info.
    pub program: ProgramInfo,
}

impl FunctionComparisonInfo {
    /// Create new function comparison info.
    pub fn new(
        name: impl Into<String>,
        entry_point: u64,
        body_start: u64,
        body_end: u64,
        program: ProgramInfo,
    ) -> Self {
        Self {
            name: name.into(),
            entry_point,
            is_external: false,
            body_start,
            body_end,
            program,
        }
    }

    /// Create new external function comparison info.
    pub fn new_external(name: impl Into<String>, entry_point: u64, program: ProgramInfo) -> Self {
        Self {
            name: name.into(),
            entry_point,
            is_external: true,
            body_start: entry_point,
            body_end: entry_point,
            program,
        }
    }

    /// Get the display name with parentheses.
    pub fn display_name(&self) -> String {
        format!("{}()", self.name)
    }
}

/// ComparisonData for a function.
///
/// Ported from Ghidra's `FunctionComparisonData` Java class.
#[derive(Debug, Clone)]
pub struct FunctionComparisonData {
    function: FunctionComparisonInfo,
    address_set: AddressSet,
}

impl FunctionComparisonData {
    /// Create new function comparison data.
    ///
    /// Computes the address set from the function info: for external functions,
    /// the set contains only the entry point; for normal functions, it contains
    /// the function body range.
    pub fn new(function: FunctionComparisonInfo) -> Self {
        let address_set = if function.is_external {
            AddressSet::single(function.entry_point, function.entry_point)
        } else {
            AddressSet::single(function.body_start, function.body_end)
        };
        Self {
            function,
            address_set,
        }
    }

    /// Get the underlying function info.
    pub fn function_info(&self) -> &FunctionComparisonInfo {
        &self.function
    }
}

impl ComparisonData for FunctionComparisonData {
    fn get_function(&self) -> Option<&FunctionComparisonInfo> {
        Some(&self.function)
    }

    fn get_address_set(&self) -> &AddressSet {
        &self.address_set
    }

    fn get_program(&self) -> Option<&ProgramInfo> {
        Some(&self.function.program)
    }

    fn get_description(&self) -> String {
        let func_str = format!("<b>{}</b>", html_escape(&self.function.display_name()));
        if let Some(program) = self.get_program() {
            let prog_str = html_color("#666666", &html_escape(&program.path));
            format!("    {} in {}    ", func_str, prog_str)
        } else {
            format!("    {}    ", func_str)
        }
    }

    fn get_short_description(&self) -> String {
        self.function.name.clone()
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn get_initial_location(&self) -> Option<ProgramLocation> {
        Some(ProgramLocation::new(
            self.function.program.clone(),
            self.function.entry_point,
        ))
    }
}

/// ComparisonData for a generic set of addresses.
///
/// Ported from Ghidra's `AddressSetComparisonData` Java class.
#[derive(Debug, Clone)]
pub struct AddressSetComparisonData {
    program: ProgramInfo,
    addresses: AddressSet,
}

impl AddressSetComparisonData {
    /// Create new address set comparison data.
    pub fn new(program: ProgramInfo, addresses: AddressSet) -> Self {
        Self { program, addresses }
    }
}

impl ComparisonData for AddressSetComparisonData {
    fn get_function(&self) -> Option<&FunctionComparisonInfo> {
        None
    }

    fn get_address_set(&self) -> &AddressSet {
        &self.addresses
    }

    fn get_program(&self) -> Option<&ProgramInfo> {
        Some(&self.program)
    }

    fn get_description(&self) -> String {
        let prog_str = html_color("#666666", &html_escape(&self.program.path));
        format!("    {}    ", prog_str)
    }

    fn get_short_description(&self) -> String {
        match (self.addresses.min_address(), self.addresses.max_address()) {
            (Some(min), Some(max)) => format!("0x{:x}:0x{:x}", min, max),
            _ => "Empty".to_string(),
        }
    }

    fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    fn get_initial_location(&self) -> Option<ProgramLocation> {
        self.addresses
            .min_address()
            .map(|addr| ProgramLocation::new(self.program.clone(), addr))
    }
}

/// Sentinel comparison data for when nothing is selected.
///
/// Ported from Ghidra's `EmptyComparisonData` Java class.
#[derive(Debug, Clone)]
pub struct EmptyComparisonData {
    /// An empty address set, stored so we can return a reference.
    empty_addresses: AddressSet,
}

impl EmptyComparisonData {
    /// Create a new empty comparison data sentinel.
    pub fn new() -> Self {
        Self {
            empty_addresses: AddressSet::new(),
        }
    }
}

impl Default for EmptyComparisonData {
    fn default() -> Self {
        Self::new()
    }
}

impl ComparisonData for EmptyComparisonData {
    fn get_function(&self) -> Option<&FunctionComparisonInfo> {
        None
    }

    fn get_address_set(&self) -> &AddressSet {
        &self.empty_addresses
    }

    fn get_program(&self) -> Option<&ProgramInfo> {
        None
    }

    fn get_description(&self) -> String {
        "No Comparison Data".to_string()
    }

    fn get_short_description(&self) -> String {
        "Empty".to_string()
    }

    fn is_empty(&self) -> bool {
        true
    }

    fn get_initial_location(&self) -> Option<ProgramLocation> {
        None
    }
}

/// A [`ComparisonData`] pair for left and right sides.
pub struct ComparisonDataPair {
    /// Left side data.
    pub left: Box<dyn ComparisonData>,
    /// Right side data.
    pub right: Box<dyn ComparisonData>,
}

impl std::fmt::Debug for ComparisonDataPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComparisonDataPair")
            .field("left", &self.left.get_short_description())
            .field("right", &self.right.get_short_description())
            .finish()
    }
}

impl ComparisonDataPair {
    /// Create a new comparison data pair.
    pub fn new(
        left: impl ComparisonData + 'static,
        right: impl ComparisonData + 'static,
    ) -> Self {
        Self {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Create an empty pair.
    pub fn empty() -> Self {
        Self {
            left: Box::new(EmptyComparisonData::new()),
            right: Box::new(EmptyComparisonData::new()),
        }
    }
}

/// State for a specific type of comparison view.
///
/// Stores key-value pairs that can be saved and restored.
///
/// Ported from Ghidra's `CodeComparisonViewState` Java class.
#[derive(Debug, Clone, Default)]
pub struct ComparisonViewState {
    values: HashMap<String, StateValue>,
}

/// A value stored in comparison view state.
#[derive(Debug, Clone)]
pub enum StateValue {
    Bool(bool),
    Int(i64),
    String(String),
}

impl ComparisonViewState {
    /// Create a new empty view state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a boolean value.
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.values.get(key) {
            Some(StateValue::Bool(v)) => *v,
            _ => default,
        }
    }

    /// Set a boolean value.
    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) {
        self.values.insert(key.into(), StateValue::Bool(value));
    }

    /// Get an integer value.
    pub fn get_int(&self, key: &str, default: i64) -> i64 {
        match self.values.get(key) {
            Some(StateValue::Int(v)) => *v,
            _ => default,
        }
    }

    /// Set an integer value.
    pub fn set_int(&mut self, key: impl Into<String>, value: i64) {
        self.values.insert(key.into(), StateValue::Int(value));
    }

    /// Get a string value.
    pub fn get_string(&self, key: &str, default: &str) -> String {
        match self.values.get(key) {
            Some(StateValue::String(v)) => v.clone(),
            _ => default.to_string(),
        }
    }

    /// Set a string value.
    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .insert(key.into(), StateValue::String(value.into()));
    }

    /// Get all keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.values.keys()
    }

    /// Check if the state is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Merge another state into this one.
    pub fn merge(&mut self, other: &ComparisonViewState) {
        for (key, value) in &other.values {
            self.values.insert(key.clone(), value.clone());
        }
    }

    /// Serialize to a compact string representation.
    pub fn to_string_repr(&self) -> String {
        let mut parts = Vec::new();
        for (key, value) in &self.values {
            let val_str = match value {
                StateValue::Bool(v) => format!("{}:bool:{}", key, v),
                StateValue::Int(v) => format!("{}:int:{}", key, v),
                StateValue::String(v) => format!("{}:str:{}", key, v),
            };
            parts.push(val_str);
        }
        parts.join(",")
    }

    /// Restore from a compact string representation.
    pub fn from_string_repr(s: &str) -> Self {
        let mut state = Self::new();
        for part in s.split(',') {
            let segments: Vec<&str> = part.splitn(3, ':').collect();
            if segments.len() == 3 {
                let key = segments[0].to_string();
                match segments[1] {
                    "bool" => {
                        if let Ok(v) = segments[2].parse::<bool>() {
                            state.values.insert(key, StateValue::Bool(v));
                        }
                    }
                    "int" => {
                        if let Ok(v) = segments[2].parse::<i64>() {
                            state.values.insert(key, StateValue::Int(v));
                        }
                    }
                    "str" => {
                        state.values.insert(key, StateValue::String(segments[2].to_string()));
                    }
                    _ => {}
                }
            }
        }
        state
    }
}

/// Top-level comparison panel state.
///
/// Manages per-view-type save state and the active view name.
///
/// Ported from Ghidra's `FunctionComparisonState` Java class.
#[derive(Debug, Clone, Default)]
pub struct ComparisonPanelState {
    /// The active view name.
    pub active_view: String,
    /// Whether scrolling is synchronized.
    pub scroll_sync: bool,
    /// Per-view orientation (side-by-side vs. stacked).
    pub orientations: HashMap<String, bool>,
    /// Per-view-type save states.
    pub view_states: HashMap<String, ComparisonViewState>,
    /// Generic panel-level state.
    pub panel_state: ComparisonViewState,
}

impl ComparisonPanelState {
    /// Create a new panel state with defaults.
    pub fn new() -> Self {
        Self {
            active_view: "Listing".to_string(),
            scroll_sync: true,
            orientations: HashMap::new(),
            view_states: HashMap::new(),
            panel_state: ComparisonViewState::new(),
        }
    }

    /// Get or create the view state for a given view type.
    pub fn get_view_state(&mut self, view_type: &str) -> &mut ComparisonViewState {
        self.view_states
            .entry(view_type.to_string())
            .or_insert_with(ComparisonViewState::new)
    }

    /// Serialize the state to a simple string representation.
    pub fn to_string_repr(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("active_view={}", self.active_view));
        parts.push(format!("scroll_sync={}", self.scroll_sync));
        for (view, &side_by_side) in &self.orientations {
            parts.push(format!("orientation_{}={}", view, side_by_side));
        }
        parts.join(";")
    }

    /// Restore state from a simple string representation.
    pub fn from_string_repr(s: &str) -> Self {
        let mut state = Self::new();
        for part in s.split(';') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "active_view" => state.active_view = value.to_string(),
                    "scroll_sync" => state.scroll_sync = value == "true",
                    _ if key.starts_with("orientation_") => {
                        let view = &key["orientation_".len()..];
                        state
                            .orientations
                            .insert(view.to_string(), value == "true");
                    }
                    _ => {}
                }
            }
        }
        state
    }
}

/// HTML helper functions for generating descriptions.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html_color(color: &str, text: &str) -> String {
    format!("<font color=\"{}\">{}</font>", color, text)
}

/// The empty comparison data singleton.
pub fn empty_comparison_data() -> EmptyComparisonData {
    EmptyComparisonData::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_func_info(
        name: &str,
        entry: u64,
        body_start: u64,
        body_end: u64,
        program: ProgramInfo,
    ) -> FunctionComparisonInfo {
        FunctionComparisonInfo::new(name, entry, body_start, body_end, program)
    }

    // --- AddressRange tests ---

    #[test]
    fn test_address_range() {
        let r = AddressRange::new(0x1000, 0x100f);
        assert_eq!(r.size(), 0x10);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1008));
        assert!(r.contains(0x100f));
        assert!(!r.contains(0x1010));
        assert!(!r.contains(0x0fff));
    }

    // --- AddressSet tests ---

    #[test]
    fn test_address_set_empty() {
        let set = AddressSet::new();
        assert!(set.is_empty());
        assert_eq!(set.min_address(), None);
        assert_eq!(set.max_address(), None);
    }

    #[test]
    fn test_address_set_single() {
        let set = AddressSet::single(0x1000, 0x100f);
        assert!(!set.is_empty());
        assert_eq!(set.min_address(), Some(0x1000));
        assert_eq!(set.max_address(), Some(0x100f));
        assert!(set.contains(0x1005));
        assert!(!set.contains(0x2000));
    }

    #[test]
    fn test_address_set_multiple_ranges() {
        let mut set = AddressSet::new();
        set.add(0x1000, 0x100f);
        set.add(0x2000, 0x200f);
        assert_eq!(set.range_count(), 2);
        assert_eq!(set.min_address(), Some(0x1000));
        assert_eq!(set.max_address(), Some(0x200f));
        assert!(set.contains(0x1005));
        assert!(set.contains(0x2005));
        assert!(!set.contains(0x1500));
        assert_eq!(set.total_size(), 0x20);
    }

    // --- ProgramInfo tests ---

    #[test]
    fn test_program_info() {
        let p = make_program(1, "/project/test", "test");
        assert_eq!(p.id, 1);
        assert_eq!(p.path, "/project/test");
        assert_eq!(p.name, "test");
    }

    // --- FunctionComparisonInfo tests ---

    #[test]
    fn test_function_comparison_info() {
        let p = make_program(1, "/project/test", "test");
        let f = make_func_info("main", 0x1000, 0x1000, 0x10ff, p);
        assert_eq!(f.display_name(), "main()");
        assert!(!f.is_external);
    }

    #[test]
    fn test_function_comparison_info_external() {
        let p = make_program(1, "/project/test", "test");
        let f = FunctionComparisonInfo::new_external("printf", 0, p);
        assert!(f.is_external);
    }

    // --- FunctionComparisonData tests ---

    #[test]
    fn test_function_comparison_data() {
        let p = make_program(1, "/project/test", "test");
        let f = make_func_info("main", 0x1000, 0x1000, 0x10ff, p);
        let data = FunctionComparisonData::new(f);

        assert!(!data.is_empty());
        assert!(data.get_function().is_some());
        assert_eq!(data.get_short_description(), "main");
        assert!(data.get_program().is_some());
        assert!(data.get_initial_location().is_some());
    }

    #[test]
    fn test_function_comparison_data_description() {
        let p = make_program(1, "/project/test", "test");
        let f = make_func_info("main", 0x1000, 0x1000, 0x10ff, p);
        let data = FunctionComparisonData::new(f);
        let desc = data.get_description();
        assert!(desc.contains("main()"));
        assert!(desc.contains("/project/test"));
    }

    // --- AddressSetComparisonData tests ---

    #[test]
    fn test_address_set_comparison_data() {
        let p = make_program(1, "/project/test", "test");
        let set = AddressSet::single(0x1000, 0x10ff);
        let data = AddressSetComparisonData::new(p, set);

        assert!(!data.is_empty());
        assert!(data.get_function().is_none());
        assert_eq!(data.get_short_description(), "0x1000:0x10ff");
        assert!(data.get_initial_location().is_some());
    }

    #[test]
    fn test_address_set_comparison_data_empty() {
        let p = make_program(1, "/project/test", "test");
        let data = AddressSetComparisonData::new(p, AddressSet::new());

        assert!(data.is_empty());
        assert_eq!(data.get_short_description(), "Empty");
    }

    // --- EmptyComparisonData tests ---

    #[test]
    fn test_empty_comparison_data() {
        let data = EmptyComparisonData::new();
        assert!(data.is_empty());
        assert!(data.get_function().is_none());
        assert!(data.get_program().is_none());
        assert_eq!(data.get_description(), "No Comparison Data");
        assert_eq!(data.get_short_description(), "Empty");
        assert!(data.get_initial_location().is_none());
    }

    // --- ComparisonViewState tests ---

    #[test]
    fn test_comparison_view_state_bool() {
        let mut state = ComparisonViewState::new();
        assert!(!state.get_bool("key", false));
        assert!(state.get_bool("key", true));

        state.set_bool("key", true);
        assert!(state.get_bool("key", false));
    }

    #[test]
    fn test_comparison_view_state_int() {
        let mut state = ComparisonViewState::new();
        assert_eq!(state.get_int("key", 42), 42);

        state.set_int("key", 100);
        assert_eq!(state.get_int("key", 42), 100);
    }

    #[test]
    fn test_comparison_view_state_string() {
        let mut state = ComparisonViewState::new();
        assert_eq!(state.get_string("key", "default"), "default");

        state.set_string("key", "value");
        assert_eq!(state.get_string("key", "default"), "value");
    }

    #[test]
    fn test_comparison_view_state_keys() {
        let mut state = ComparisonViewState::new();
        state.set_bool("a", true);
        state.set_int("b", 1);
        state.set_string("c", "v");

        let mut keys: Vec<&String> = state.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_comparison_view_state_merge() {
        let mut state1 = ComparisonViewState::new();
        state1.set_bool("a", true);

        let mut state2 = ComparisonViewState::new();
        state2.set_bool("b", true);
        state2.set_bool("a", false);

        state1.merge(&state2);
        assert!(!state1.get_bool("a", true));
        assert!(state1.get_bool("b", false));
    }

    // --- ComparisonPanelState tests ---

    #[test]
    fn test_panel_state_defaults() {
        let state = ComparisonPanelState::new();
        assert_eq!(state.active_view, "Listing");
        assert!(state.scroll_sync);
    }

    #[test]
    fn test_panel_state_serialization() {
        let mut state = ComparisonPanelState::new();
        state.active_view = "Decompiler".to_string();
        state.scroll_sync = false;
        state.orientations.insert("Listing".to_string(), true);

        let serialized = state.to_string_repr();
        let restored = ComparisonPanelState::from_string_repr(&serialized);

        assert_eq!(restored.active_view, "Decompiler");
        assert!(!restored.scroll_sync);
        assert_eq!(restored.orientations.get("Listing"), Some(&true));
    }

    #[test]
    fn test_panel_state_get_view_state() {
        let mut state = ComparisonPanelState::new();
        {
            let vs = state.get_view_state("Listing");
            vs.set_bool("show_bytes", true);
        }
        {
            let vs = state.get_view_state("Listing");
            assert!(vs.get_bool("show_bytes", false));
        }
    }

    // --- HTML helper tests ---

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("normal"), "normal");
    }

    #[test]
    fn test_html_color() {
        assert_eq!(
            html_color("#ff0000", "red"),
            "<font color=\"#ff0000\">red</font>"
        );
    }

    // --- ProgramLocation tests ---

    #[test]
    fn test_program_location() {
        let p = make_program(1, "/project/test", "test");
        let loc = ProgramLocation::new(p.clone(), 0x1000);
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.program.path, "/project/test");
    }
}
