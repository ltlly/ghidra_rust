//! Function comparison model.
//!
//! Ported from Ghidra's `ghidra.features.base.codecompare.model` Java package.
//!
//! This module provides the data model for comparing functions side-by-side.
//! It supports selecting which functions to display on each side of a comparison
//! and notifying listeners when the model changes.
//!
//! # Key types
//!
//! - [`FunctionInfo`] -- lightweight representation of a function
//! - [`ComparisonSide`] -- left or right side of a comparison
//! - [`FunctionComparisonModel`] -- trait for comparison model implementations
//! - [`AnyToAnyFunctionComparisonModel`] -- model where any function can be compared with any other
//! - [`MatchedFunctionComparisonModel`] -- model with matched source/target function pairs
//!
//! # Submodules
//!
//! - [`function_matcher`] -- function matching utilities for comparison

pub mod function_matcher;

use std::collections::{HashMap, HashSet};
use std::fmt;

/// The side of a function comparison (left or right).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComparisonSide {
    Left,
    Right,
}

impl ComparisonSide {
    /// The opposite side.
    pub fn opposite(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// Lightweight representation of a function for comparison purposes.
///
/// This is the Rust equivalent of Ghidra's `Function` object, containing
/// just the information needed for comparison model operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionInfo {
    /// Unique identifier for the function.
    pub id: u64,
    /// The function's name.
    pub name: String,
    /// Path of the program containing this function.
    pub program_path: String,
    /// Entry point address.
    pub entry_point: u64,
    /// Whether this is an external function.
    pub is_external: bool,
}

impl FunctionInfo {
    /// Create a new FunctionInfo.
    pub fn new(
        id: u64,
        name: impl Into<String>,
        program_path: impl Into<String>,
        entry_point: u64,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            program_path: program_path.into(),
            entry_point,
            is_external: false,
        }
    }

    /// Create a new external FunctionInfo.
    pub fn new_external(
        id: u64,
        name: impl Into<String>,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            program_path: program_path.into(),
            entry_point: 0,
            is_external: true,
        }
    }

    /// Get the display name (name with parentheses).
    pub fn display_name(&self) -> String {
        format!("{}()", self.name)
    }
}

impl PartialOrd for FunctionInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionInfo {
    /// Orders functions by program path, then name, then entry point.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.program_path
            .cmp(&other.program_path)
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| self.entry_point.cmp(&other.entry_point))
    }
}

impl fmt::Display for FunctionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in {}", self.display_name(), self.program_path)
    }
}

/// Trait for receiving notifications about model changes.
///
/// Ported from Ghidra's `FunctionComparisonModelListener` Java interface.
pub trait FunctionComparisonModelListener: Send + Sync {
    /// Called when the selected function changed on one side.
    fn active_function_changed(&self, side: ComparisonSide, function: &FunctionInfo);

    /// Called when the set of functions on at least one side changed.
    fn model_data_changed(&self);
}

/// Trait for a function comparison model.
///
/// A model manages which functions are available for comparison and
/// which function is currently active on each side.
///
/// Ported from Ghidra's `FunctionComparisonModel` Java interface.
pub trait FunctionComparisonModel: Send + Sync {
    /// Set the active function for the given side.
    ///
    /// Returns true if the function was made active, false if it doesn't exist
    /// for the given side or is already active.
    fn set_active_function(&mut self, side: ComparisonSide, function: &FunctionInfo) -> bool;

    /// Get the active function for the given side.
    fn get_active_function(&self, side: ComparisonSide) -> Option<&FunctionInfo>;

    /// Get the list of all functions available for the given side.
    fn get_functions(&self, side: ComparisonSide) -> Vec<&FunctionInfo>;

    /// Remove a function from both sides of the comparison.
    fn remove_function(&mut self, function: &FunctionInfo);

    /// Remove multiple functions from both sides.
    fn remove_functions(&mut self, functions: &[FunctionInfo]);

    /// Remove all functions from the given program.
    fn remove_functions_by_program(&mut self, program_path: &str);

    /// Check if the model has no functions to compare.
    fn is_empty(&self) -> bool;

    /// Add a listener for model changes.
    fn add_listener(&mut self, listener: Box<dyn FunctionComparisonModelListener>);

    /// Remove all listeners.
    fn clear_listeners(&mut self);

    /// Upcast to `Any` for downcasting support.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Upcast to mutable `Any` for downcasting support.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// A simple listener implementation that tracks changes.
#[derive(Debug, Default)]
pub struct TrackingListener {
    /// Count of active function changes.
    pub active_changes: std::sync::Mutex<Vec<(ComparisonSide, u64)>>,
    /// Count of model data changes.
    pub data_changes: std::sync::Mutex<usize>,
}

impl TrackingListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }
}

impl FunctionComparisonModelListener for TrackingListener {
    fn active_function_changed(&self, side: ComparisonSide, function: &FunctionInfo) {
        self.active_changes.lock().unwrap().push((side, function.id));
    }

    fn model_data_changed(&self) {
        *self.data_changes.lock().unwrap() += 1;
    }
}

impl FunctionComparisonModelListener for std::sync::Arc<TrackingListener> {
    fn active_function_changed(&self, side: ComparisonSide, function: &FunctionInfo) {
        (**self).active_function_changed(side, function);
    }

    fn model_data_changed(&self) {
        (**self).model_data_changed();
    }
}

/// A [`Duo`]-like pair holding one value per side.
#[derive(Debug, Clone)]
pub struct SidePair<T> {
    left: T,
    right: T,
}

impl<T: Clone> SidePair<T> {
    /// Create a new side pair.
    pub fn new(left: T, right: T) -> Self {
        Self { left, right }
    }

    /// Get the value for the given side.
    pub fn get(&self, side: ComparisonSide) -> &T {
        match side {
            ComparisonSide::Left => &self.left,
            ComparisonSide::Right => &self.right,
        }
    }

    /// Create a new pair with the given side replaced.
    pub fn with(&self, side: ComparisonSide, value: T) -> Self {
        match side {
            ComparisonSide::Left => Self {
                left: value,
                right: self.right.clone(),
            },
            ComparisonSide::Right => Self {
                left: self.left.clone(),
                right: value,
            },
        }
    }
}

impl<T: Default + Clone> Default for SidePair<T> {
    fn default() -> Self {
        Self {
            left: T::default(),
            right: T::default(),
        }
    }
}

/// Base implementation of [`FunctionComparisonModel`] with listener support
/// and tracking of the selected function for each side.
///
/// Ported from Ghidra's `AbstractFunctionComparisonModel` Java class.
pub struct AbstractFunctionComparisonModel {
    listeners: Vec<Box<dyn FunctionComparisonModelListener>>,
    active_functions: SidePair<Option<FunctionInfo>>,
}

impl AbstractFunctionComparisonModel {
    /// Create a new abstract model.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            active_functions: SidePair::new(None, None),
        }
    }

    /// Get the active functions pair.
    pub fn active_functions(&self) -> &SidePair<Option<FunctionInfo>> {
        &self.active_functions
    }

    /// Set the active functions pair.
    pub fn set_active_functions(&mut self, pair: SidePair<Option<FunctionInfo>>) {
        self.active_functions = pair;
    }

    /// Fire the active function changed event.
    pub fn fire_active_function_changed(&self, side: ComparisonSide, function: &FunctionInfo) {
        for listener in &self.listeners {
            listener.active_function_changed(side, function);
        }
    }

    /// Fire the model data changed event.
    pub fn fire_model_data_changed(&self) {
        for listener in &self.listeners {
            listener.model_data_changed();
        }
    }

    /// Add a listener.
    pub fn add_listener_impl(&mut self, listener: Box<dyn FunctionComparisonModelListener>) {
        self.listeners.push(listener);
    }

    /// Clear all listeners.
    pub fn clear_listeners_impl(&mut self) {
        self.listeners.clear();
    }
}

impl Default for AbstractFunctionComparisonModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Basic [`FunctionComparisonModel`] where a set of functions can be compared
/// with each other. Any function in the set can be selected for either side.
///
/// Ported from Ghidra's `AnyToAnyFunctionComparisonModel` Java class.
pub struct AnyToAnyFunctionComparisonModel {
    base: AbstractFunctionComparisonModel,
    functions: HashSet<FunctionInfo>,
}

impl AnyToAnyFunctionComparisonModel {
    /// Create a model from a collection of functions.
    ///
    /// If there are at least two functions, the first two (in sorted order)
    /// are set as the left and right active functions.
    pub fn new(functions: impl IntoIterator<Item = FunctionInfo>) -> Self {
        let func_set: HashSet<FunctionInfo> = functions.into_iter().collect();
        let mut model = Self {
            base: AbstractFunctionComparisonModel::new(),
            functions: func_set,
        };

        let mut ordered: Vec<&FunctionInfo> = model.functions.iter().collect();
        ordered.sort();

        if ordered.len() == 1 {
            let f = ordered[0].clone();
            model.base.active_functions = SidePair::new(Some(f.clone()), Some(f));
        } else if ordered.len() > 1 {
            model.base.active_functions =
                SidePair::new(Some(ordered[0].clone()), Some(ordered[1].clone()));
        }

        model
    }

    /// Create a model comparing exactly two functions.
    pub fn new_pair(left: FunctionInfo, right: FunctionInfo) -> Self {
        let mut functions = HashSet::new();
        functions.insert(left.clone());
        functions.insert(right.clone());
        Self {
            base: AbstractFunctionComparisonModel::new(),
            functions,
        }
        .tap(|m| {
            m.base.active_functions = SidePair::new(Some(left), Some(right));
        })
    }

    /// Add additional functions to the model.
    pub fn add_functions(&mut self, additional: impl IntoIterator<Item = FunctionInfo>) {
        let mut changed = false;
        for f in additional {
            if self.functions.insert(f) {
                changed = true;
            }
        }
        if changed {
            self.base.fire_model_data_changed();
        }
    }

    /// Add a single function to the model.
    pub fn add_function(&mut self, function: FunctionInfo) {
        self.add_functions(std::iter::once(function));
    }

    /// Get the functions in sorted order.
    fn ordered_functions(&self) -> Vec<FunctionInfo> {
        let mut v: Vec<FunctionInfo> = self.functions.iter().cloned().collect();
        v.sort();
        v
    }

    /// Fix up active functions after removal.
    fn fixup_active_functions(&mut self) {
        let left = self.base.active_functions.left.clone();
        let right = self.base.active_functions.right.clone();

        let contains_left = left.as_ref().map_or(false, |f| self.functions.contains(f));
        let contains_right = right.as_ref().map_or(false, |f| self.functions.contains(f));

        if contains_left && contains_right {
            return;
        }

        let first = self.ordered_functions().into_iter().next();

        self.base.active_functions = SidePair::new(
            if contains_left { left } else { first.clone() },
            if contains_right { right } else { first },
        );
    }
}

impl FunctionComparisonModel for AnyToAnyFunctionComparisonModel {
    fn set_active_function(&mut self, side: ComparisonSide, function: &FunctionInfo) -> bool {
        let current = self.base.active_functions.get(side);
        if current.as_ref() == Some(function) {
            return false;
        }
        if !self.functions.contains(function) {
            return false;
        }
        self.base.active_functions = self.base.active_functions.with(side, Some(function.clone()));
        self.base.fire_active_function_changed(side, function);
        true
    }

    fn get_active_function(&self, side: ComparisonSide) -> Option<&FunctionInfo> {
        self.base.active_functions.get(side).as_ref()
    }

    fn get_functions(&self, _side: ComparisonSide) -> Vec<&FunctionInfo> {
        let mut v: Vec<&FunctionInfo> = self.functions.iter().collect();
        v.sort();
        v
    }

    fn remove_function(&mut self, function: &FunctionInfo) {
        self.remove_functions(&[function.clone()]);
    }

    fn remove_functions(&mut self, functions: &[FunctionInfo]) {
        let before = self.functions.len();
        for f in functions {
            self.functions.remove(f);
        }
        let after = self.functions.len();
        if before != after {
            self.fixup_active_functions();
            self.base.fire_model_data_changed();
        }
    }

    fn remove_functions_by_program(&mut self, program_path: &str) {
        let to_remove: Vec<FunctionInfo> = self
            .functions
            .iter()
            .filter(|f| f.program_path == program_path)
            .cloned()
            .collect();
        self.remove_functions(&to_remove);
    }

    fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    fn add_listener(&mut self, listener: Box<dyn FunctionComparisonModelListener>) {
        self.base.add_listener_impl(listener);
    }

    fn clear_listeners(&mut self) {
        self.base.clear_listeners_impl();
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Helper trait for builder-style construction.
trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&mut Self)) -> Self {
        let mut this = self;
        f(&mut this);
        this
    }
}

impl<T> Tap for T {}

/// A [`FunctionComparisonModel`] comprised of matched pairs of source and target
/// functions. Each source function has its own set of target functions that it
/// can be compared with.
///
/// Ported from Ghidra's `MatchedFunctionComparisonModel` Java class.
pub struct MatchedFunctionComparisonModel {
    base: AbstractFunctionComparisonModel,
    /// Maps source function -> set of target functions.
    source_to_targets: HashMap<FunctionInfo, HashSet<FunctionInfo>>,
}

impl MatchedFunctionComparisonModel {
    /// Create a new empty matched model.
    pub fn new() -> Self {
        Self {
            base: AbstractFunctionComparisonModel::new(),
            source_to_targets: HashMap::new(),
        }
    }

    /// Add a matched pair of source and target functions.
    ///
    /// If the source function already exists, the target is added to its set.
    /// Otherwise, a new entry is created.
    pub fn add_match(&mut self, source: FunctionInfo, target: FunctionInfo) {
        let targets = self
            .source_to_targets
            .entry(source.clone())
            .or_insert_with(HashSet::new);
        targets.insert(target.clone());
        self.base.active_functions = SidePair::new(Some(source), Some(target));
        self.base.fire_model_data_changed();
    }

    /// Get all source functions in sorted order.
    pub fn get_source_functions(&self) -> Vec<FunctionInfo> {
        let mut v: Vec<FunctionInfo> = self.source_to_targets.keys().cloned().collect();
        v.sort();
        v
    }

    /// Get target functions for the currently active source, in sorted order.
    fn get_target_functions(&self) -> Vec<FunctionInfo> {
        let source = self.base.active_functions.left.as_ref();
        match source.and_then(|s| self.source_to_targets.get(s)) {
            Some(targets) => {
                let mut v: Vec<FunctionInfo> = targets.iter().cloned().collect();
                v.sort();
                v
            }
            None => Vec::new(),
        }
    }

    /// Fix up active functions after removal.
    fn fixup_active_functions(&mut self) {
        if self.source_to_targets.is_empty() {
            self.base.active_functions = SidePair::new(None, None);
            return;
        }

        let left = self.base.active_functions.left.clone();
        if !self.contains_function_impl(ComparisonSide::Left, left.as_ref()) {
            let new_left = self.get_source_functions().into_iter().next();
            self.base.active_functions = self.base.active_functions.with(
                ComparisonSide::Left,
                new_left,
            );
        }

        let right = self.base.active_functions.right.clone();
        if !self.contains_function_impl(ComparisonSide::Right, right.as_ref()) {
            let new_right = self.get_target_functions().into_iter().next();
            self.base.active_functions = self.base.active_functions.with(
                ComparisonSide::Right,
                new_right,
            );
        }
    }

    /// Check if the model contains the given function on the given side.
    fn contains_function_impl(&self, side: ComparisonSide, function: Option<&FunctionInfo>) -> bool {
        match function {
            None => false,
            Some(f) => match side {
                ComparisonSide::Left => self.source_to_targets.contains_key(f),
                ComparisonSide::Right => {
                    let source = self.base.active_functions.left.as_ref();
                    match source.and_then(|s| self.source_to_targets.get(s)) {
                        Some(targets) => targets.contains(f),
                        None => false,
                    }
                }
            },
        }
    }

    /// Remove a function from targets across all sources.
    fn remove_from_targets(&mut self, function: &FunctionInfo) -> bool {
        let mut did_remove = false;
        let mut empty_sources = Vec::new();

        for (source, targets) in &mut self.source_to_targets {
            if targets.remove(function) {
                did_remove = true;
            }
            if targets.is_empty() {
                empty_sources.push(source.clone());
            }
        }

        for source in empty_sources {
            self.source_to_targets.remove(&source);
        }

        did_remove
    }

    /// Remove a function from sources.
    fn remove_from_sources(&mut self, function: &FunctionInfo) -> bool {
        self.source_to_targets.remove(function).is_some()
    }
}

impl Default for MatchedFunctionComparisonModel {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionComparisonModel for MatchedFunctionComparisonModel {
    fn set_active_function(&mut self, side: ComparisonSide, function: &FunctionInfo) -> bool {
        // Right side changes are simple
        if side == ComparisonSide::Right {
            let current = self.base.active_functions.get(ComparisonSide::Right);
            if current.as_ref() == Some(function) {
                return false;
            }
            if !self.contains_function_impl(ComparisonSide::Right, Some(function)) {
                return false;
            }
            self.base.active_functions = self
                .base
                .active_functions
                .with(ComparisonSide::Right, Some(function.clone()));
            self.base
                .fire_active_function_changed(ComparisonSide::Right, function);
            return true;
        }

        // Left side changes: also update right side
        let current = self.base.active_functions.get(ComparisonSide::Left);
        if current.as_ref() == Some(function) {
            return false;
        }
        if !self.contains_function_impl(ComparisonSide::Left, Some(function)) {
            return false;
        }

        self.base.active_functions = self
            .base
            .active_functions
            .with(ComparisonSide::Left, Some(function.clone()));

        let new_right = self.get_target_functions().into_iter().next();
        self.base.active_functions = self
            .base
            .active_functions
            .with(ComparisonSide::Right, new_right);

        self.base.fire_model_data_changed();
        true
    }

    fn get_active_function(&self, side: ComparisonSide) -> Option<&FunctionInfo> {
        self.base.active_functions.get(side).as_ref()
    }

    fn get_functions(&self, side: ComparisonSide) -> Vec<&FunctionInfo> {
        match side {
            ComparisonSide::Left => {
                let mut v: Vec<&FunctionInfo> = self.source_to_targets.keys().collect();
                v.sort();
                v
            }
            ComparisonSide::Right => {
                let source = self.base.active_functions.left.as_ref();
                match source.and_then(|s| self.source_to_targets.get(s)) {
                    Some(targets) => {
                        let mut v: Vec<&FunctionInfo> = targets.iter().collect();
                        v.sort();
                        v
                    }
                    None => Vec::new(),
                }
            }
        }
    }

    fn remove_function(&mut self, function: &FunctionInfo) {
        let removed_from_targets = self.remove_from_targets(function);
        let removed_from_sources = self.remove_from_sources(function);
        if removed_from_targets || removed_from_sources {
            self.fixup_active_functions();
            self.base.fire_model_data_changed();
        }
    }

    fn remove_functions(&mut self, functions: &[FunctionInfo]) {
        let mut did_remove = false;
        for f in functions {
            did_remove |= self.remove_from_targets(f);
            did_remove |= self.remove_from_sources(f);
        }
        if did_remove {
            self.fixup_active_functions();
            self.base.fire_model_data_changed();
        }
    }

    fn remove_functions_by_program(&mut self, program_path: &str) {
        let to_remove: Vec<FunctionInfo> = {
            let mut set = HashSet::new();
            for (source, targets) in &self.source_to_targets {
                if source.program_path == program_path {
                    set.insert(source.clone());
                }
                for target in targets {
                    if target.program_path == program_path {
                        set.insert(target.clone());
                    }
                }
            }
            set.into_iter().collect()
        };
        self.remove_functions(&to_remove);
    }

    fn is_empty(&self) -> bool {
        self.source_to_targets.is_empty()
    }

    fn add_listener(&mut self, listener: Box<dyn FunctionComparisonModelListener>) {
        self.base.add_listener_impl(listener);
    }

    fn clear_listeners(&mut self) {
        self.base.clear_listeners_impl();
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_func(id: u64, name: &str, program: &str, entry: u64) -> FunctionInfo {
        FunctionInfo::new(id, name, program, entry)
    }

    fn make_func_ext(id: u64, name: &str, program: &str) -> FunctionInfo {
        FunctionInfo::new_external(id, name, program)
    }

    // --- FunctionInfo tests ---

    #[test]
    fn test_function_info_new() {
        let f = make_func(1, "main", "/project/test", 0x1000);
        assert_eq!(f.id, 1);
        assert_eq!(f.name, "main");
        assert_eq!(f.program_path, "/project/test");
        assert_eq!(f.entry_point, 0x1000);
        assert!(!f.is_external);
    }

    #[test]
    fn test_function_info_external() {
        let f = make_func_ext(2, "printf", "/project/test");
        assert!(f.is_external);
        assert_eq!(f.entry_point, 0);
    }

    #[test]
    fn test_function_info_display_name() {
        let f = make_func(1, "main", "/project/test", 0x1000);
        assert_eq!(f.display_name(), "main()");
    }

    #[test]
    fn test_function_info_display() {
        let f = make_func(1, "main", "/project/test", 0x1000);
        assert_eq!(format!("{}", f), "main() in /project/test");
    }

    #[test]
    fn test_function_info_ordering() {
        let f1 = make_func(1, "alpha", "/a/prog", 0x1000);
        let f2 = make_func(2, "beta", "/a/prog", 0x1000);
        let f3 = make_func(3, "alpha", "/b/prog", 0x1000);
        let f4 = make_func(4, "alpha", "/a/prog", 0x2000);

        assert!(f1 < f2); // same program, name differs
        assert!(f1 < f3); // different program
        assert!(f1 < f4); // same program+name, address differs
    }

    // --- ComparisonSide tests ---

    #[test]
    fn test_comparison_side_opposite() {
        assert_eq!(ComparisonSide::Left.opposite(), ComparisonSide::Right);
        assert_eq!(ComparisonSide::Right.opposite(), ComparisonSide::Left);
    }

    // --- SidePair tests ---

    #[test]
    fn test_side_pair() {
        let pair = SidePair::new(10, 20);
        assert_eq!(*pair.get(ComparisonSide::Left), 10);
        assert_eq!(*pair.get(ComparisonSide::Right), 20);

        let pair2 = pair.with(ComparisonSide::Left, 30);
        assert_eq!(*pair2.get(ComparisonSide::Left), 30);
        assert_eq!(*pair2.get(ComparisonSide::Right), 20);
    }

    // --- AnyToAnyFunctionComparisonModel tests ---

    #[test]
    fn test_any_to_any_basic() {
        let f1 = make_func(1, "main", "/prog", 0x1000);
        let f2 = make_func(2, "init", "/prog", 0x2000);
        let model = AnyToAnyFunctionComparisonModel::new(vec![f1.clone(), f2.clone()]);

        assert!(!model.is_empty());
        let left = model.get_active_function(ComparisonSide::Left).unwrap();
        let right = model.get_active_function(ComparisonSide::Right).unwrap();
        // init sorts before main
        assert_eq!(left.name, "init");
        assert_eq!(right.name, "main");
    }

    #[test]
    fn test_any_to_any_single_function() {
        let f = make_func(1, "main", "/prog", 0x1000);
        let model = AnyToAnyFunctionComparisonModel::new(vec![f.clone()]);

        let left = model.get_active_function(ComparisonSide::Left).unwrap();
        let right = model.get_active_function(ComparisonSide::Right).unwrap();
        assert_eq!(left.id, 1);
        assert_eq!(right.id, 1);
    }

    #[test]
    fn test_any_to_any_empty() {
        let model = AnyToAnyFunctionComparisonModel::new(vec![]);
        assert!(model.is_empty());
        assert!(model.get_active_function(ComparisonSide::Left).is_none());
    }

    #[test]
    fn test_any_to_any_set_active() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);
        let f3 = make_func(3, "ccc", "/prog", 0x3000);

        let mut model = AnyToAnyFunctionComparisonModel::new(vec![
            f1.clone(),
            f2.clone(),
            f3.clone(),
        ]);

        assert!(model.set_active_function(ComparisonSide::Right, &f3));
        assert_eq!(
            model.get_active_function(ComparisonSide::Right).unwrap().id,
            3
        );

        // Setting to same function should return false
        assert!(!model.set_active_function(ComparisonSide::Right, &f3));
    }

    #[test]
    fn test_any_to_any_set_active_unknown_function() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f_unknown = make_func(99, "zzz", "/prog", 0x9000);

        let mut model = AnyToAnyFunctionComparisonModel::new(vec![f1.clone()]);
        assert!(!model.set_active_function(ComparisonSide::Left, &f_unknown));
    }

    #[test]
    fn test_any_to_any_remove_function() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);
        let f3 = make_func(3, "ccc", "/prog", 0x3000);

        let mut model = AnyToAnyFunctionComparisonModel::new(vec![
            f1.clone(),
            f2.clone(),
            f3.clone(),
        ]);

        model.remove_function(&f2);
        assert_eq!(model.get_functions(ComparisonSide::Left).len(), 2);
    }

    #[test]
    fn test_any_to_any_remove_active_function() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);

        let mut model = AnyToAnyFunctionComparisonModel::new(vec![f1.clone(), f2.clone()]);
        model.remove_function(&f1);

        // The remaining function should become active on both sides
        let left = model.get_active_function(ComparisonSide::Left).unwrap();
        let right = model.get_active_function(ComparisonSide::Right).unwrap();
        assert_eq!(left.id, 2);
        assert_eq!(right.id, 2);
    }

    #[test]
    fn test_any_to_any_remove_all() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let mut model = AnyToAnyFunctionComparisonModel::new(vec![f1]);
        model.remove_function(&make_func(1, "aaa", "/prog", 0x1000));
        assert!(model.is_empty());
    }

    #[test]
    fn test_any_to_any_remove_by_program() {
        let f1 = make_func(1, "aaa", "/prog1", 0x1000);
        let f2 = make_func(2, "bbb", "/prog1", 0x2000);
        let f3 = make_func(3, "ccc", "/prog2", 0x3000);

        let mut model =
            AnyToAnyFunctionComparisonModel::new(vec![f1.clone(), f2.clone(), f3.clone()]);

        model.remove_functions_by_program("/prog1");
        assert_eq!(model.get_functions(ComparisonSide::Left).len(), 1);
        assert_eq!(
            model.get_functions(ComparisonSide::Left)[0].program_path,
            "/prog2"
        );
    }

    #[test]
    fn test_any_to_any_add_functions() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let mut model = AnyToAnyFunctionComparisonModel::new(vec![f1]);

        let f2 = make_func(2, "bbb", "/prog", 0x2000);
        model.add_function(f2);
        assert_eq!(model.get_functions(ComparisonSide::Left).len(), 2);
    }

    #[test]
    fn test_any_to_any_get_functions_both_sides_same() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);
        let model = AnyToAnyFunctionComparisonModel::new(vec![f1, f2]);

        let left_funcs = model.get_functions(ComparisonSide::Left);
        let right_funcs = model.get_functions(ComparisonSide::Right);
        assert_eq!(left_funcs.len(), right_funcs.len());
    }

    #[test]
    fn test_any_to_any_listener() {
        let f1 = make_func(1, "aaa", "/prog", 0x1000);
        let f2 = make_func(2, "bbb", "/prog", 0x2000);

        let mut model = AnyToAnyFunctionComparisonModel::new(vec![f1.clone(), f2.clone()]);
        let listener = Arc::new(TrackingListener::new());
        model.add_listener(Box::new(listener.clone()));

        // Right is already f2 after init (second in sorted order),
        // so set it to f1 to trigger a real change.
        model.set_active_function(ComparisonSide::Right, &f1);
        assert_eq!(listener.active_changes.lock().unwrap().len(), 1);
    }

    // --- MatchedFunctionComparisonModel tests ---

    #[test]
    fn test_matched_basic() {
        let src1 = make_func(1, "main_old", "/old", 0x1000);
        let tgt1 = make_func(2, "main_new", "/new", 0x2000);
        let src2 = make_func(3, "init_old", "/old", 0x3000);
        let tgt2 = make_func(4, "init_new", "/new", 0x4000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src1.clone(), tgt1.clone());
        model.add_match(src2.clone(), tgt2.clone());

        assert!(!model.is_empty());
        assert_eq!(model.get_source_functions().len(), 2);
    }

    #[test]
    fn test_matched_empty() {
        let model = MatchedFunctionComparisonModel::new();
        assert!(model.is_empty());
        assert!(model.get_active_function(ComparisonSide::Left).is_none());
    }

    #[test]
    fn test_matched_set_active_left() {
        let src1 = make_func(1, "aaa", "/old", 0x1000);
        let tgt1 = make_func(2, "aaa_tgt", "/new", 0x2000);
        let src2 = make_func(3, "bbb", "/old", 0x3000);
        let tgt2 = make_func(4, "bbb_tgt", "/new", 0x4000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src1.clone(), tgt1.clone());
        model.add_match(src2.clone(), tgt2.clone());

        // Switch left to src2; right should auto-update
        model.set_active_function(ComparisonSide::Left, &src2);
        let left = model.get_active_function(ComparisonSide::Left).unwrap();
        assert_eq!(left.id, 3);
    }

    #[test]
    fn test_matched_set_active_right() {
        let src = make_func(1, "src", "/old", 0x1000);
        let tgt1 = make_func(2, "tgt1", "/new", 0x2000);
        let tgt2 = make_func(3, "tgt2", "/new", 0x3000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src.clone(), tgt1.clone());
        // Add second target for the same source
        model.add_match(src.clone(), tgt2.clone());

        model.set_active_function(ComparisonSide::Right, &tgt2);
        let right = model.get_active_function(ComparisonSide::Right).unwrap();
        assert_eq!(right.id, 3);
    }

    #[test]
    fn test_matched_get_functions_right_depends_on_left() {
        let src1 = make_func(1, "aaa", "/old", 0x1000);
        let tgt1 = make_func(2, "tgt_a", "/new", 0x2000);
        let src2 = make_func(3, "bbb", "/old", 0x3000);
        let tgt2 = make_func(4, "tgt_b", "/new", 0x4000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src1.clone(), tgt1.clone());
        model.add_match(src2.clone(), tgt2.clone());

        // Right side should show targets for the active left (last added = src2 -> tgt2)
        let right_funcs = model.get_functions(ComparisonSide::Right);
        assert_eq!(right_funcs.len(), 1);
    }

    #[test]
    fn test_matched_remove_function() {
        let src = make_func(1, "src", "/old", 0x1000);
        let tgt = make_func(2, "tgt", "/new", 0x2000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src.clone(), tgt.clone());

        model.remove_function(&src);
        assert!(model.is_empty());
    }

    #[test]
    fn test_matched_remove_target() {
        let src = make_func(1, "src", "/old", 0x1000);
        let tgt1 = make_func(2, "tgt1", "/new", 0x2000);
        let tgt2 = make_func(3, "tgt2", "/new", 0x3000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src.clone(), tgt1.clone());
        model.add_match(src.clone(), tgt2.clone());

        model.remove_function(&tgt1);
        assert!(!model.is_empty());
        let right_funcs = model.get_functions(ComparisonSide::Right);
        assert_eq!(right_funcs.len(), 1);
    }

    #[test]
    fn test_matched_remove_by_program() {
        let src = make_func(1, "src", "/old", 0x1000);
        let tgt = make_func(2, "tgt", "/new", 0x2000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src.clone(), tgt.clone());

        model.remove_functions_by_program("/old");
        assert!(model.is_empty());
    }

    #[test]
    fn test_matched_get_source_functions_sorted() {
        let src1 = make_func(3, "zzz", "/old", 0x3000);
        let tgt1 = make_func(4, "tgt_z", "/new", 0x4000);
        let src2 = make_func(1, "aaa", "/old", 0x1000);
        let tgt2 = make_func(2, "tgt_a", "/new", 0x2000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src1, tgt1);
        model.add_match(src2, tgt2);

        let sources = model.get_source_functions();
        assert_eq!(sources[0].name, "aaa");
        assert_eq!(sources[1].name, "zzz");
    }

    #[test]
    fn test_matched_set_active_unknown_function() {
        let src = make_func(1, "src", "/old", 0x1000);
        let unknown = make_func(99, "unknown", "/old", 0x9000);

        let mut model = MatchedFunctionComparisonModel::new();
        model.add_match(src, make_func(2, "tgt", "/new", 0x2000));

        assert!(!model.set_active_function(ComparisonSide::Left, &unknown));
    }

    // --- TrackingListener tests ---

    #[test]
    fn test_tracking_listener_data_change() {
        let listener = TrackingListener::new();
        listener.model_data_changed();
        listener.model_data_changed();
        assert_eq!(*listener.data_changes.lock().unwrap(), 2);
    }

    #[test]
    fn test_tracking_listener_active_change() {
        let listener = TrackingListener::new();
        let f = make_func(1, "test", "/prog", 0x1000);
        listener.active_function_changed(ComparisonSide::Left, &f);
        let changes = listener.active_changes.lock().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].0, ComparisonSide::Left);
        assert_eq!(changes[0].1, 1);
    }
}
