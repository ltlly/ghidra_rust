//! Proposed utility types used by the debug framework.
//!
//! Ported from Ghidra's `ProposedUtils` module.
//!
//! Provides utility types including:
//! - **Spatial data structures**: R*-tree, hyper-box queries, 2D rectangles.
//! - **Database utilities**: Key spans, field spans, cached object stores,
//!   directed iterators, and annotated object frameworks.
//! - **General utilities**: Observable collections, lock holds, pairing iterators,
//!   merging spliterators, and dependent service resolution.

pub mod database;
pub mod spatial;

// ---------------------------------------------------------------------------
// General Utilities
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// A lock hold guard that tracks whether a lock is currently held.
///
/// Ported from Ghidra's `LockHold`.
#[derive(Debug, Clone, Default)]
pub struct LockHold {
    held: bool,
}

impl LockHold {
    /// Create a new lock hold (not held).
    pub fn new() -> Self {
        Self { held: false }
    }

    /// Acquire the lock.
    pub fn acquire(&mut self) {
        self.held = true;
    }

    /// Release the lock.
    pub fn release(&mut self) {
        self.held = false;
    }

    /// Whether the lock is currently held.
    pub fn is_held(&self) -> bool {
        self.held
    }
}

/// An iterator that merges two sorted iterators.
///
/// Ported from Ghidra's `MergeSortingSpliterator`.
#[derive(Debug, Clone)]
pub struct MergingIterator<T: Ord> {
    a: Vec<T>,
    b: Vec<T>,
    pos_a: usize,
    pos_b: usize,
}

impl<T: Ord + Clone> MergingIterator<T> {
    /// Create a new merging iterator from two sorted vectors.
    pub fn new(a: Vec<T>, b: Vec<T>) -> Self {
        Self {
            a,
            b,
            pos_a: 0,
            pos_b: 0,
        }
    }

    /// Collect all remaining items into a sorted vector.
    pub fn merge_collect(&mut self) -> Vec<T> {
        let mut result = Vec::with_capacity(self.a.len() + self.b.len());
        while self.pos_a < self.a.len() && self.pos_b < self.b.len() {
            if self.a[self.pos_a] <= self.b[self.pos_b] {
                result.push(self.a[self.pos_a].clone());
                self.pos_a += 1;
            } else {
                result.push(self.b[self.pos_b].clone());
                self.pos_b += 1;
            }
        }
        while self.pos_a < self.a.len() {
            result.push(self.a[self.pos_a].clone());
            self.pos_a += 1;
        }
        while self.pos_b < self.b.len() {
            result.push(self.b[self.pos_b].clone());
            self.pos_b += 1;
        }
        result
    }
}

/// An observable collection that notifies listeners of changes.
///
/// Ported from Ghidra's `ObservableCollection`.
#[derive(Debug, Clone)]
pub struct ObservableCollection<T: Clone> {
    items: Vec<T>,
    /// Number of times the collection has been modified.
    pub modification_count: u64,
}

impl<T: Clone> ObservableCollection<T> {
    /// Create a new observable collection.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            modification_count: 0,
        }
    }

    /// Add an item.
    pub fn push(&mut self, item: T) {
        self.items.push(item);
        self.modification_count += 1;
    }

    /// Remove an item at the given index.
    pub fn remove(&mut self, index: usize) -> T {
        self.modification_count += 1;
        self.items.remove(index)
    }

    /// Get the number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get an item by index.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.items.get(index)
    }

    /// Iterate over items.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }
}

impl<T: Clone> Default for ObservableCollection<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A lazy collection that materializes elements on demand.
///
/// Ported from Ghidra's `LazyCollection`.
#[derive(Debug, Clone)]
pub struct LazyCollection<T> {
    materialized: Vec<T>,
    remaining: usize,
}

impl<T> LazyCollection<T> {
    /// Create a new lazy collection.
    pub fn new(remaining: usize) -> Self {
        Self {
            materialized: Vec::new(),
            remaining,
        }
    }

    /// Add an already-materialized item.
    pub fn push(&mut self, item: T) {
        self.materialized.push(item);
        if self.remaining > 0 {
            self.remaining -= 1;
        }
    }

    /// Get the number of materialized items.
    pub fn materialized_len(&self) -> usize {
        self.materialized.len()
    }

    /// How many items remain to be materialized.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Whether all items have been materialized.
    pub fn is_fully_materialized(&self) -> bool {
        self.remaining == 0
    }

    /// Get a reference to the materialized items.
    pub fn as_slice(&self) -> &[T] {
        &self.materialized
    }
}

/// An iterator that pairs items from two iterators.
///
/// Ported from Ghidra's `PairingIteratorMerger`.
#[derive(Debug, Clone)]
pub struct PairingIterator<A, B> {
    a: Vec<A>,
    b: Vec<B>,
    pos: usize,
}

impl<A: Clone, B: Clone> PairingIterator<A, B> {
    /// Create a new pairing iterator.
    pub fn new(a: Vec<A>, b: Vec<B>) -> Self {
        Self { a, b, pos: 0 }
    }

    /// Collect all pairs.
    pub fn collect_pairs(&mut self) -> Vec<(A, B)> {
        let mut result = Vec::new();
        while self.pos < self.a.len() && self.pos < self.b.len() {
            result.push((self.a[self.pos].clone(), self.b[self.pos].clone()));
            self.pos += 1;
        }
        result
    }
}

/// A cached address set view.
///
/// Ported from Ghidra's `CachedAddressSetView`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachedAddressSetView {
    /// Address ranges: (min, max) pairs, sorted.
    ranges: Vec<(u64, u64)>,
}

impl CachedAddressSetView {
    /// Create a new empty address set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range.
    pub fn add_range(&mut self, min: u64, max: u64) {
        self.ranges.push((min, max));
        self.ranges.sort_by_key(|r| r.0);
    }

    /// Whether the set contains an address.
    pub fn contains(&self, addr: u64) -> bool {
        self.ranges.iter().any(|(min, max)| addr >= *min && addr <= *max)
    }

    /// The number of ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// The total number of addresses.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|(min, max)| max - min + 1).sum()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Iterate over ranges.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }
}

/// An iterator direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Forward iteration.
    Forward,
    /// Backward iteration.
    Backward,
}

// ---------------------------------------------------------------------------
// Dependent Service Resolution
// ---------------------------------------------------------------------------

use std::any::TypeId;
use std::collections::{HashMap, HashSet, VecDeque};

/// Error during service construction.
///
/// Ported from Ghidra's `ServiceConstructionException`.
#[derive(Debug, Clone)]
pub struct ServiceConstructionException {
    message: String,
}

impl ServiceConstructionException {
    /// Create a new service construction exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ServiceConstructionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServiceConstructionException: {}", self.message)
    }
}

impl std::error::Error for ServiceConstructionException {}

/// Error when required fields have no matching constructor.
///
/// Ported from Ghidra's `UnsatisfiedFieldsException`.
#[derive(Debug, Clone)]
pub struct UnsatisfiedFieldsException {
    missing: Vec<String>,
}

impl UnsatisfiedFieldsException {
    /// Create a new exception listing the missing field types.
    pub fn new(missing: Vec<String>) -> Self {
        Self { missing }
    }

    /// The set of field types that have no constructor.
    pub fn missing(&self) -> &[String] {
        &self.missing
    }
}

impl std::fmt::Display for UnsatisfiedFieldsException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnsatisfiedFieldsException: missing constructors for {:?}",
            self.missing
        )
    }
}

impl std::error::Error for UnsatisfiedFieldsException {}

/// Error when required parameter dependencies form a cycle.
///
/// Ported from Ghidra's `UnsatisfiedParameterException`.
#[derive(Debug, Clone)]
pub struct UnsatisfiedParameterException {
    unresolved: Vec<String>,
}

impl UnsatisfiedParameterException {
    /// Create a new exception listing the unresolved parameter types.
    pub fn new(unresolved: Vec<String>) -> Self {
        Self { unresolved }
    }

    /// The set of parameter types that could not be resolved.
    pub fn unresolved(&self) -> &[String] {
        &self.unresolved
    }
}

impl std::fmt::Display for UnsatisfiedParameterException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnsatisfiedParameterException: unresolved dependencies {:?}",
            self.unresolved
        )
    }
}

impl std::error::Error for UnsatisfiedParameterException {}

/// A service constructor descriptor for dependency injection.
///
/// Ported from Ghidra's `DependentServiceConstructor`.
#[derive(Debug, Clone)]
pub struct DependentServiceConstructor {
    /// The type ID of the service this constructor produces.
    pub produces: TypeId,
    /// The type IDs of the dependencies required to construct this service.
    pub requires: Vec<TypeId>,
    /// Human-readable name for diagnostics.
    pub name: String,
}

impl DependentServiceConstructor {
    /// Create a new constructor descriptor.
    pub fn new(
        name: impl Into<String>,
        produces: TypeId,
        requires: Vec<TypeId>,
    ) -> Self {
        Self {
            name: name.into(),
            produces,
            requires,
        }
    }
}

/// A resolver for dependent services using topological ordering.
///
/// Ported from Ghidra's `DependentServiceResolver`.
///
/// This resolver takes a set of service constructors (each declaring
/// what they produce and what they require) and produces a topologically
/// ordered sequence for construction.
#[derive(Debug, Clone, Default)]
pub struct DependentServiceResolver {
    constructors: Vec<DependentServiceConstructor>,
    field_requirements: Vec<TypeId>,
}

impl DependentServiceResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a service constructor.
    pub fn add_constructor(&mut self, constructor: DependentServiceConstructor) {
        self.constructors.push(constructor);
    }

    /// Register a field that requires a service of the given type.
    pub fn add_field_requirement(&mut self, type_id: TypeId) {
        self.field_requirements.push(type_id);
    }

    /// Compile the dependency graph and return topologically ordered constructors.
    ///
    /// Returns `UnsatisfiedFieldsException` if any field requirement has no
    /// matching constructor, and `UnsatisfiedParameterException` if the
    /// dependency graph contains a cycle.
    pub fn compile(
        &self,
    ) -> Result<Vec<DependentServiceConstructor>, Box<dyn std::error::Error>> {
        let produced: HashSet<TypeId> =
            self.constructors.iter().map(|c| c.produces).collect();

        // Check field requirements
        let missing_fields: Vec<String> = self
            .field_requirements
            .iter()
            .filter(|f| !produced.contains(f))
            .map(|f| format!("{:?}", f))
            .collect();
        if !missing_fields.is_empty() {
            return Err(Box::new(UnsatisfiedFieldsException::new(missing_fields)));
        }

        // Topological sort via Kahn's algorithm
        let mut in_degree: HashMap<TypeId, usize> = HashMap::new();
        let mut adjacency: HashMap<TypeId, Vec<TypeId>> = HashMap::new();

        for constructor in &self.constructors {
            in_degree.entry(constructor.produces).or_insert(0);
            for dep in &constructor.requires {
                adjacency
                    .entry(*dep)
                    .or_default()
                    .push(constructor.produces);
                *in_degree.entry(constructor.produces).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<TypeId> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut order: Vec<TypeId> = Vec::new();
        while let Some(id) = queue.pop_front() {
            order.push(id);
            if let Some(dependents) = adjacency.get(&id) {
                for dep_id in dependents {
                    let deg = in_degree.get_mut(dep_id).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(*dep_id);
                    }
                }
            }
        }

        if order.len() != self.constructors.len() {
            let unresolved: Vec<String> = self
                .constructors
                .iter()
                .filter(|c| !order.contains(&c.produces))
                .map(|c| c.name.clone())
                .collect();
            return Err(Box::new(UnsatisfiedParameterException::new(unresolved)));
        }

        let constructor_map: HashMap<TypeId, &DependentServiceConstructor> =
            self.constructors.iter().map(|c| (c.produces, c)).collect();

        Ok(order
            .into_iter()
            .filter_map(|id| constructor_map.get(&id).map(|c| (*c).clone()))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Topological Sorter
// ---------------------------------------------------------------------------

/// A standalone topological sorter for directed acyclic graphs.
///
/// Ported from Ghidra's `TopologicalSorter`.
#[derive(Debug, Clone, Default)]
pub struct TopologicalSorter<T: Eq + std::hash::Hash + Clone> {
    nodes: HashSet<T>,
    edges: HashMap<T, Vec<T>>,
}

impl<T: Eq + std::hash::Hash + Clone> TopologicalSorter<T> {
    /// Create a new empty sorter.
    pub fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            edges: HashMap::new(),
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: T) {
        self.nodes.insert(node);
    }

    /// Add a directed edge from `from` to `to`.
    pub fn add_edge(&mut self, from: T, to: T) {
        self.nodes.insert(from.clone());
        self.nodes.insert(to.clone());
        self.edges.entry(from).or_default().push(to);
    }

    /// Perform topological sort. Returns `None` if the graph has a cycle.
    pub fn sort(&self) -> Option<Vec<T>> {
        let mut in_degree: HashMap<&T, usize> = HashMap::new();
        for node in &self.nodes {
            in_degree.entry(node).or_insert(0);
        }
        for (_, targets) in &self.edges {
            for target in targets {
                *in_degree.entry(target).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<&T> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&n, _)| n)
            .collect();

        let mut order = Vec::new();
        while let Some(node) = queue.pop_front() {
            order.push(node.clone());
            if let Some(targets) = self.edges.get(node) {
                for target in targets {
                    let deg = in_degree.get_mut(target).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(target);
                    }
                }
            }
        }

        if order.len() == self.nodes.len() {
            Some(order)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Collection Utilities
// ---------------------------------------------------------------------------

/// A collection that is the union of multiple sub-collections.
///
/// Ported from Ghidra's `AbstractUnionedCollection`.
#[derive(Debug, Clone)]
pub struct UnionedCollection<T: Clone> {
    collections: Vec<Vec<T>>,
}

impl<T: Clone> UnionedCollection<T> {
    /// Create a new empty unioned collection.
    pub fn new() -> Self {
        Self {
            collections: Vec::new(),
        }
    }

    /// Add a sub-collection.
    pub fn add_collection(&mut self, collection: Vec<T>) {
        self.collections.push(collection);
    }

    /// The total number of items across all sub-collections.
    pub fn len(&self) -> usize {
        self.collections.iter().map(|c| c.len()).sum()
    }

    /// Whether the union is empty.
    pub fn is_empty(&self) -> bool {
        self.collections.iter().all(|c| c.is_empty())
    }

    /// Iterate over all items in order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.collections.iter().flat_map(|c| c.iter())
    }
}

impl<T: Clone> Default for UnionedCollection<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A collection formed by concatenating multiple collections.
///
/// Ported from Ghidra's `CatenatedCollection`.
#[derive(Debug, Clone)]
pub struct CatenatedCollection<T: Clone> {
    parts: Vec<Vec<T>>,
}

impl<T: Clone> CatenatedCollection<T> {
    /// Create a new catenated collection.
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }

    /// Append a new part.
    pub fn push_part(&mut self, part: Vec<T>) {
        self.parts.push(part);
    }

    /// Total length.
    pub fn len(&self) -> usize {
        self.parts.iter().map(|p| p.len()).sum()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.parts.iter().all(|p| p.is_empty())
    }

    /// Flatten into a single vector.
    pub fn flatten(&self) -> Vec<T> {
        self.parts.iter().flat_map(|p| p.iter().cloned()).collect()
    }

    /// Iterate over all items.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.parts.iter().flat_map(|p| p.iter())
    }

    /// Number of parts.
    pub fn num_parts(&self) -> usize {
        self.parts.len()
    }
}

impl<T: Clone> Default for CatenatedCollection<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Stream / Iterator Utilities
// ---------------------------------------------------------------------------

/// Iterator that yields only distinct (deduplicated) elements.
///
/// Ported from Ghidra's `DistinctIterator`.
#[derive(Debug, Clone)]
pub struct DistinctIterator<T: Eq + std::hash::Hash + Clone> {
    inner: Vec<T>,
    pos: usize,
    seen: HashSet<T>,
}

impl<T: Eq + std::hash::Hash + Clone> DistinctIterator<T> {
    /// Create a new distinct iterator from a vector.
    pub fn new(items: Vec<T>) -> Self {
        Self {
            inner: items,
            pos: 0,
            seen: HashSet::new(),
        }
    }

    /// Collect all distinct items.
    pub fn collect_distinct(&mut self) -> Vec<T> {
        let mut result = Vec::new();
        while self.pos < self.inner.len() {
            let item = self.inner[self.pos].clone();
            self.pos += 1;
            if self.seen.insert(item.clone()) {
                result.push(item);
            }
        }
        result
    }
}

/// Stream utility functions.
///
/// Ported from Ghidra's `StreamUtils`.
pub struct StreamUtils;

impl StreamUtils {
    /// Merge multiple sorted vectors into a single sorted vector.
    ///
    /// Ported from Ghidra's `StreamUtils.merge`.
    pub fn merge_sorted<T: Ord + Clone>(vectors: Vec<Vec<T>>) -> Vec<T> {
        if vectors.is_empty() {
            return Vec::new();
        }
        if vectors.len() == 1 {
            return vectors.into_iter().next().unwrap();
        }

        // Merge using a binary heap (min-heap via Reverse)
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        #[derive(Eq, PartialEq)]
        struct HeapEntry<T: Ord> {
            value: T,
            vec_idx: usize,
            elem_idx: usize,
        }

        impl<T: Ord> PartialOrd for HeapEntry<T> {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl<T: Ord> Ord for HeapEntry<T> {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.value.cmp(&other.value)
            }
        }

        let mut heap = BinaryHeap::new();
        for (i, vec) in vectors.iter().enumerate() {
            if !vec.is_empty() {
                heap.push(Reverse(HeapEntry {
                    value: vec[0].clone(),
                    vec_idx: i,
                    elem_idx: 0,
                }));
            }
        }

        let mut result = Vec::new();
        while let Some(Reverse(entry)) = heap.pop() {
            result.push(entry.value.clone());
            let next_idx = entry.elem_idx + 1;
            if next_idx < vectors[entry.vec_idx].len() {
                heap.push(Reverse(HeapEntry {
                    value: vectors[entry.vec_idx][next_idx].clone(),
                    vec_idx: entry.vec_idx,
                    elem_idx: next_idx,
                }));
            }
        }

        result
    }

    /// Filter a vector to only include items matching a predicate.
    pub fn filter<T: Clone>(items: &[T], predicate: impl Fn(&T) -> bool) -> Vec<T> {
        items.iter().filter(|i| predicate(i)).cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// General Utilities
// ---------------------------------------------------------------------------

/// Language/processor utilities.
///
/// Ported from Ghidra's `LanguageUtilities`.
pub struct LanguageUtilities;

impl LanguageUtilities {
    /// Normalize a language ID string to lowercase with underscores.
    pub fn normalize_language_id(id: &str) -> String {
        id.to_lowercase().replace('-', "_").replace(' ', "_")
    }

    /// Parse a "language::compiler" string into (language, compiler) parts.
    ///
    /// The convention uses `::` as separator between language and compiler:
    /// `"x86:LE:64:default::gcc"` becomes `("x86:LE:64:default", Some("gcc"))`.
    /// Without `::`, the entire string is treated as the language.
    pub fn parse_language_compiler(spec: &str) -> (String, Option<String>) {
        if let Some(pos) = spec.find("::") {
            let lang = &spec[..pos];
            let comp = &spec[pos + 2..];
            if !lang.is_empty() && !comp.is_empty() {
                return (lang.to_string(), Some(comp.to_string()));
            }
        }
        (spec.to_string(), None)
    }
}

/// Byte buffer utilities.
///
/// Ported from Ghidra's `ByteBufferUtils`.
pub struct ByteBufferUtils;

impl ByteBufferUtils {
    /// Convert a byte slice to a hex string.
    pub fn to_hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Parse a hex string into bytes.
    pub fn from_hex_string(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("Hex string must have even length".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
            })
            .collect()
    }

    /// Compare two byte slices for equality up to `len` bytes.
    pub fn equals(a: &[u8], b: &[u8], len: usize) -> bool {
        a.get(..len).is_some()
            && b.get(..len).is_some()
            && a[..len] == b[..len]
    }

    /// Read a big-endian u32 from a byte slice at the given offset.
    pub fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
        bytes.get(offset..offset + 4).map(|b| {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    /// Read a little-endian u32 from a byte slice at the given offset.
    pub fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
        bytes.get(offset..offset + 4).map(|b| {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }
}

/// A timed message for performance measurement.
///
/// Ported from Ghidra's `TimedMsg`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedMsg {
    /// The message text.
    pub message: String,
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Elapsed time in milliseconds since the previous TimedMsg.
    pub elapsed_ms: u64,
}

impl TimedMsg {
    /// Create a new timed message.
    pub fn new(message: impl Into<String>, timestamp_ms: u64, elapsed_ms: u64) -> Self {
        Self {
            message: message.into(),
            timestamp_ms,
            elapsed_ms,
        }
    }
}

/// A callback that can be suppressed and re-enabled.
///
/// Ported from Ghidra's `SuppressableCallback`.
#[derive(Debug, Clone)]
pub struct SuppressableCallback {
    suppressed: bool,
    pending: bool,
    name: String,
}

impl SuppressableCallback {
    /// Create a new suppressable callback with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            suppressed: false,
            pending: false,
            name: name.into(),
        }
    }

    /// Suppress the callback. While suppressed, calls to `trigger` are
    /// recorded but the callback body is not executed.
    pub fn suppress(&mut self) {
        self.suppressed = true;
    }

    /// Resume the callback. If any triggers occurred while suppressed,
    /// returns `true` so the caller can re-execute.
    pub fn resume(&mut self) -> bool {
        self.suppressed = false;
        let was_pending = self.pending;
        self.pending = false;
        was_pending
    }

    /// Trigger the callback. Returns `true` if the callback is active
    /// (not suppressed) and should be executed.
    pub fn trigger(&mut self) -> bool {
        if self.suppressed {
            self.pending = true;
            false
        } else {
            true
        }
    }

    /// Whether the callback is currently suppressed.
    pub fn is_suppressed(&self) -> bool {
        self.suppressed
    }

    /// Whether a trigger occurred while suppressed.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Get the callback name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ---------------------------------------------------------------------------
// ID Types
// ---------------------------------------------------------------------------

/// A unique identifier with a display-friendly string representation.
///
/// Ported from Ghidra's `ID` interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ID {
    /// The underlying value.
    pub value: u64,
    /// Optional display name.
    pub display: Option<String>,
}

impl ID {
    /// Create a new ID.
    pub fn new(value: u64) -> Self {
        Self {
            value,
            display: None,
        }
    }

    /// Create a new ID with a display name.
    pub fn with_display(value: u64, display: impl Into<String>) -> Self {
        Self {
            value,
            display: Some(display.into()),
        }
    }
}

impl std::fmt::Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.display {
            Some(d) => write!(f, "{}", d),
            None => write!(f, "{}", self.value),
        }
    }
}

/// A trait for types that have an associated `ID`.
///
/// Ported from Ghidra's `IDKeyed`.
pub trait IDKeyed {
    /// Get the ID of this object.
    fn id(&self) -> &ID;
}

/// A trait for types that use their ID for hashing.
///
/// Ported from Ghidra's `IDHashed`.
pub trait IDHashed: IDKeyed {
    /// Compute a hash from the ID value.
    fn id_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.id().value.hash(&mut hasher);
        hasher.finish()
    }
}

// ---------------------------------------------------------------------------
// Proxy Utilities
// ---------------------------------------------------------------------------

/// Utilities for creating proxy objects.
///
/// Ported from Ghidra's `ProxyUtilities`.
pub struct ProxyUtilities;

impl ProxyUtilities {
    /// Wrap a value in a container that provides interior mutability.
    pub fn shared_ref<T>(value: T) -> std::rc::Rc<std::cell::RefCell<T>> {
        std::rc::Rc::new(std::cell::RefCell::new(value))
    }

    /// Create a thread-safe shared reference.
    pub fn shared_ref_sync<T>(value: T) -> std::sync::Arc<std::sync::Mutex<T>> {
        std::sync::Arc::new(std::sync::Mutex::new(value))
    }
}

// ---------------------------------------------------------------------------
// Debug Message Tracer
// ---------------------------------------------------------------------------

/// A debug message tracer for recording debug output.
///
/// Ported from Ghidra's `DbgMsgTracer`.
#[derive(Debug, Clone, Default)]
pub struct DbgMsgTracer {
    messages: Vec<String>,
    enabled: bool,
}

impl DbgMsgTracer {
    /// Create a new tracer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable the tracer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the tracer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record a debug message.
    pub fn trace(&mut self, message: impl Into<String>) {
        if self.enabled {
            self.messages.push(message.into());
        }
    }

    /// Get all recorded messages.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    /// Clear all recorded messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// The number of recorded messages.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether no messages have been recorded.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Default Observable Collection with Listeners
// ---------------------------------------------------------------------------

/// A listener for collection change events.
///
/// Ported from Ghidra's `CollectionChangeListener`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionChangeKind {
    /// An element was added.
    Added,
    /// An element was removed.
    Removed,
    /// The collection was cleared.
    Cleared,
}

/// An event describing a collection change.
#[derive(Debug, Clone)]
pub struct CollectionChangeEvent<T: Clone> {
    /// The kind of change.
    pub kind: CollectionChangeKind,
    /// The element affected (if applicable).
    pub element: Option<T>,
    /// The index at which the change occurred (if applicable).
    pub index: Option<usize>,
}

/// A type alias for collection change listener functions.
pub type CollectionChangeListenerFn<T> = Box<dyn Fn(&CollectionChangeEvent<T>)>;

/// An observable collection with listener support.
///
/// Ported from Ghidra's `DefaultObservableCollection`.
pub struct DefaultObservableCollection<T: Clone + std::fmt::Debug> {
    items: Vec<T>,
    listeners: Vec<CollectionChangeListenerFn<T>>,
    modification_count: u64,
}

impl<T: Clone + std::fmt::Debug> std::fmt::Debug for DefaultObservableCollection<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultObservableCollection")
            .field("items", &self.items)
            .field("num_listeners", &self.listeners.len())
            .field("modification_count", &self.modification_count)
            .finish()
    }
}

impl<T: Clone + std::fmt::Debug> DefaultObservableCollection<T> {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            listeners: Vec::new(),
            modification_count: 0,
        }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: CollectionChangeListenerFn<T>) {
        self.listeners.push(listener);
    }

    fn notify(&self, event: &CollectionChangeEvent<T>) {
        for listener in &self.listeners {
            listener(event);
        }
    }

    /// Add an element and notify listeners.
    pub fn push(&mut self, item: T) {
        let index = self.items.len();
        self.items.push(item.clone());
        self.modification_count += 1;
        self.notify(&CollectionChangeEvent {
            kind: CollectionChangeKind::Added,
            element: Some(item),
            index: Some(index),
        });
    }

    /// Remove an element at the given index and notify listeners.
    pub fn remove(&mut self, index: usize) -> T {
        let item = self.items.remove(index);
        self.modification_count += 1;
        self.notify(&CollectionChangeEvent {
            kind: CollectionChangeKind::Removed,
            element: Some(item.clone()),
            index: Some(index),
        });
        item
    }

    /// Clear the collection and notify listeners.
    pub fn clear(&mut self) {
        self.items.clear();
        self.modification_count += 1;
        self.notify(&CollectionChangeEvent {
            kind: CollectionChangeKind::Cleared,
            element: None,
            index: None,
        });
    }

    /// Get the number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get an item by index.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.items.get(index)
    }

    /// Iterate over items.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    /// The modification count.
    pub fn modification_count(&self) -> u64 {
        self.modification_count
    }
}

impl<T: Clone + std::fmt::Debug> Default for DefaultObservableCollection<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Privately Queued Listener
// ---------------------------------------------------------------------------

/// A listener wrapper that queues events and dispatches them later.
///
/// Ported from Ghidra's `PrivatelyQueuedListener`.
#[derive(Debug)]
pub struct QueuedListener<T: Clone + std::fmt::Debug> {
    queue: Vec<T>,
    active: bool,
}

impl<T: Clone + std::fmt::Debug> QueuedListener<T> {
    /// Create a new queued listener.
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            active: true,
        }
    }

    /// Enqueue an event.
    pub fn enqueue(&mut self, event: T) {
        if self.active {
            self.queue.push(event);
        }
    }

    /// Drain and return all queued events.
    pub fn drain(&mut self) -> Vec<T> {
        std::mem::take(&mut self.queue)
    }

    /// Whether there are queued events.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Enable or disable the listener.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Whether the listener is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl<T: Clone + std::fmt::Debug> Default for QueuedListener<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_hold() {
        let mut lh = LockHold::new();
        assert!(!lh.is_held());
        lh.acquire();
        assert!(lh.is_held());
        lh.release();
        assert!(!lh.is_held());
    }

    #[test]
    fn test_merging_iterator() {
        let mut mi = MergingIterator::new(vec![1, 3, 5], vec![2, 4, 6]);
        let result = mi.merge_collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_merging_iterator_empty() {
        let mut mi = MergingIterator::<i32>::new(vec![], vec![]);
        assert!(mi.merge_collect().is_empty());
    }

    #[test]
    fn test_merging_iterator_one_empty() {
        let mut mi = MergingIterator::new(vec![1, 2], vec![]);
        assert_eq!(mi.merge_collect(), vec![1, 2]);
    }

    #[test]
    fn test_observable_collection() {
        let mut col = ObservableCollection::new();
        assert!(col.is_empty());

        col.push(10);
        col.push(20);
        assert_eq!(col.len(), 2);
        assert_eq!(col.modification_count, 2);

        let removed = col.remove(0);
        assert_eq!(removed, 10);
        assert_eq!(col.modification_count, 3);
    }

    #[test]
    fn test_lazy_collection() {
        let mut lc = LazyCollection::new(5);
        assert_eq!(lc.remaining(), 5);
        assert!(!lc.is_fully_materialized());

        lc.push(1);
        lc.push(2);
        assert_eq!(lc.materialized_len(), 2);
        assert_eq!(lc.remaining(), 3);
    }

    #[test]
    fn test_pairing_iterator() {
        let mut pi = PairingIterator::new(vec!["a", "b", "c"], vec![1, 2, 3]);
        let pairs = pi.collect_pairs();
        assert_eq!(pairs, vec![("a", 1), ("b", 2), ("c", 3)]);
    }

    #[test]
    fn test_pairing_iterator_mismatched() {
        let mut pi = PairingIterator::new(vec!["a", "b"], vec![1]);
        let pairs = pi.collect_pairs();
        assert_eq!(pairs, vec![("a", 1)]);
    }

    #[test]
    fn test_cached_address_set_view() {
        let mut set = CachedAddressSetView::new();
        set.add_range(0x1000, 0x1FFF);
        set.add_range(0x400000, 0x400FFF);

        assert!(set.contains(0x1500));
        assert!(set.contains(0x400000));
        assert!(!set.contains(0x2000));
        assert_eq!(set.num_ranges(), 2);
        assert_eq!(set.num_addresses(), 0x1000 + 0x1000);
    }

    #[test]
    fn test_cached_address_set_empty() {
        let set = CachedAddressSetView::new();
        assert!(set.is_empty());
        assert!(!set.contains(0));
    }

    #[test]
    fn test_direction() {
        assert_ne!(Direction::Forward, Direction::Backward);
    }

    #[test]
    fn test_observable_collection_default() {
        let col: ObservableCollection<i32> = ObservableCollection::default();
        assert!(col.is_empty());
    }

    // DependentServiceResolver tests

    #[test]
    fn test_dependent_service_resolver_empty() {
        let resolver = DependentServiceResolver::new();
        let result = resolver.compile().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_dependent_service_resolver_simple_chain() {
        let mut resolver = DependentServiceResolver::new();
        let type_a = TypeId::of::<i32>();
        let type_b = TypeId::of::<u64>();
        let type_c = TypeId::of::<String>();

        // B depends on A, C depends on B
        resolver.add_constructor(DependentServiceConstructor::new("A", type_a, vec![]));
        resolver.add_constructor(DependentServiceConstructor::new("B", type_b, vec![type_a]));
        resolver.add_constructor(DependentServiceConstructor::new("C", type_c, vec![type_b]));

        let order = resolver.compile().unwrap();
        assert_eq!(order.len(), 3);
        assert_eq!(order[0].produces, type_a);
        assert_eq!(order[1].produces, type_b);
        assert_eq!(order[2].produces, type_c);
    }

    #[test]
    fn test_dependent_service_resolver_cycle() {
        let mut resolver = DependentServiceResolver::new();
        let type_a = TypeId::of::<i32>();
        let type_b = TypeId::of::<u64>();

        // A depends on B, B depends on A -> cycle
        resolver.add_constructor(DependentServiceConstructor::new("A", type_a, vec![type_b]));
        resolver.add_constructor(DependentServiceConstructor::new("B", type_b, vec![type_a]));

        let result = resolver.compile();
        assert!(result.is_err());
    }

    #[test]
    fn test_dependent_service_resolver_unsatisfied_field() {
        let mut resolver = DependentServiceResolver::new();
        let type_a = TypeId::of::<i32>();
        let type_missing = TypeId::of::<f64>();

        resolver.add_constructor(DependentServiceConstructor::new("A", type_a, vec![]));
        resolver.add_field_requirement(type_missing);

        let result = resolver.compile();
        assert!(result.is_err());
    }

    // TopologicalSorter tests

    #[test]
    fn test_topological_sorter_diamond() {
        let mut sorter = TopologicalSorter::new();
        sorter.add_node("A");
        sorter.add_node("B");
        sorter.add_node("C");
        sorter.add_node("D");
        sorter.add_edge("A", "B");
        sorter.add_edge("A", "C");
        sorter.add_edge("B", "D");
        sorter.add_edge("C", "D");

        let result = sorter.sort().unwrap();
        let pos_a = result.iter().position(|x| *x == "A").unwrap();
        let pos_b = result.iter().position(|x| *x == "B").unwrap();
        let pos_c = result.iter().position(|x| *x == "C").unwrap();
        let pos_d = result.iter().position(|x| *x == "D").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_a < pos_c);
        assert!(pos_b < pos_d);
        assert!(pos_c < pos_d);
    }

    #[test]
    fn test_topological_sorter_cycle() {
        let mut sorter = TopologicalSorter::new();
        sorter.add_edge("A", "B");
        sorter.add_edge("B", "C");
        sorter.add_edge("C", "A");
        assert!(sorter.sort().is_none());
    }

    #[test]
    fn test_topological_sorter_single() {
        let mut sorter = TopologicalSorter::new();
        sorter.add_node("X");
        let result = sorter.sort().unwrap();
        assert_eq!(result, vec!["X"]);
    }

    // Collection utilities tests

    #[test]
    fn test_unioned_collection() {
        let mut uc = UnionedCollection::new();
        uc.add_collection(vec![1, 2, 3]);
        uc.add_collection(vec![4, 5]);
        assert_eq!(uc.len(), 5);
        let items: Vec<_> = uc.iter().cloned().collect();
        assert_eq!(items, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_unioned_collection_empty() {
        let uc: UnionedCollection<i32> = UnionedCollection::new();
        assert!(uc.is_empty());
        assert_eq!(uc.len(), 0);
    }

    #[test]
    fn test_catenated_collection() {
        let mut cc = CatenatedCollection::new();
        cc.push_part(vec![1, 2]);
        cc.push_part(vec![3, 4, 5]);
        assert_eq!(cc.len(), 5);
        assert_eq!(cc.num_parts(), 2);
        assert_eq!(cc.flatten(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_catenated_collection_empty() {
        let cc: CatenatedCollection<i32> = CatenatedCollection::new();
        assert!(cc.is_empty());
        assert_eq!(cc.num_parts(), 0);
    }

    // DistinctIterator tests

    #[test]
    fn test_distinct_iterator() {
        let mut di = DistinctIterator::new(vec![1, 2, 2, 3, 3, 3, 1]);
        let result = di.collect_distinct();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_distinct_iterator_empty() {
        let mut di = DistinctIterator::<i32>::new(vec![]);
        assert!(di.collect_distinct().is_empty());
    }

    #[test]
    fn test_distinct_iterator_all_same() {
        let mut di = DistinctIterator::new(vec![5, 5, 5, 5]);
        assert_eq!(di.collect_distinct(), vec![5]);
    }

    // StreamUtils tests

    #[test]
    fn test_stream_utils_merge_sorted() {
        let result = StreamUtils::merge_sorted(vec![vec![1, 3, 5], vec![2, 4, 6]]);
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_stream_utils_merge_single() {
        let result = StreamUtils::merge_sorted(vec![vec![1, 2, 3]]);
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_stream_utils_merge_empty() {
        let result: Vec<i32> = StreamUtils::merge_sorted(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_stream_utils_merge_with_empties() {
        let result = StreamUtils::merge_sorted(vec![vec![], vec![1, 2], vec![]]);
        assert_eq!(result, vec![1, 2]);
    }

    #[test]
    fn test_stream_utils_filter() {
        let items = vec![1, 2, 3, 4, 5, 6];
        let evens = StreamUtils::filter(&items, |x| x % 2 == 0);
        assert_eq!(evens, vec![2, 4, 6]);
    }

    // LanguageUtilities tests

    #[test]
    fn test_normalize_language_id() {
        assert_eq!(
            LanguageUtilities::normalize_language_id("x86:LE:64:default"),
            "x86:le:64:default"
        );
    }

    #[test]
    fn test_parse_language_compiler() {
        // No compiler part (just the language spec)
        let (lang, comp) =
            LanguageUtilities::parse_language_compiler("x86:LE:64:default");
        assert_eq!(lang, "x86:LE:64:default");
        assert!(comp.is_none());

        // With compiler part (split on :: separator)
        let (lang2, comp2) =
            LanguageUtilities::parse_language_compiler("x86:LE:64:default::gcc");
        assert_eq!(lang2, "x86:LE:64:default");
        assert_eq!(comp2.unwrap(), "gcc");

        // Simple language without colons
        let (lang3, comp3) =
            LanguageUtilities::parse_language_compiler("ARM");
        assert_eq!(lang3, "ARM");
        assert!(comp3.is_none());
    }

    // ByteBufferUtils tests

    #[test]
    fn test_byte_buffer_to_hex() {
        assert_eq!(
            ByteBufferUtils::to_hex_string(&[0xDE, 0xAD, 0xBE, 0xEF]),
            "deadbeef"
        );
    }

    #[test]
    fn test_byte_buffer_from_hex() {
        let bytes = ByteBufferUtils::from_hex_string("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_byte_buffer_from_hex_invalid() {
        assert!(ByteBufferUtils::from_hex_string("xyz").is_err());
        assert!(ByteBufferUtils::from_hex_string("123").is_err());
    }

    #[test]
    fn test_byte_buffer_equals() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 9, 9];
        assert!(ByteBufferUtils::equals(&a, &b, 3));
        assert!(!ByteBufferUtils::equals(&a, &b, 4));
    }

    #[test]
    fn test_byte_buffer_read_u32() {
        let be_bytes = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(ByteBufferUtils::read_u32_be(&be_bytes, 0), Some(0x01020304));

        let le_bytes = [0x04, 0x03, 0x02, 0x01];
        assert_eq!(ByteBufferUtils::read_u32_le(&le_bytes, 0), Some(0x01020304));
    }

    // TimedMsg tests

    #[test]
    fn test_timed_msg() {
        let msg = TimedMsg::new("test", 1000, 50);
        assert_eq!(msg.message, "test");
        assert_eq!(msg.timestamp_ms, 1000);
        assert_eq!(msg.elapsed_ms, 50);
    }

    // SuppressableCallback tests

    #[test]
    fn test_suppressable_callback_basic() {
        let mut cb = SuppressableCallback::new("test_cb");
        assert!(cb.trigger());
        assert!(!cb.is_suppressed());
    }

    #[test]
    fn test_suppressable_callback_suppressed() {
        let mut cb = SuppressableCallback::new("test_cb");
        cb.suppress();
        assert!(cb.is_suppressed());

        // Trigger while suppressed -> returns false, marks pending
        assert!(!cb.trigger());
        assert!(cb.is_pending());

        // Resume returns true because trigger was pending
        assert!(cb.resume());
        assert!(!cb.is_pending());
        assert!(!cb.is_suppressed());
    }

    #[test]
    fn test_suppressable_callback_no_trigger_while_suppressed() {
        let mut cb = SuppressableCallback::new("test_cb");
        cb.suppress();
        // No trigger was called while suppressed, so resume returns false
        assert!(!cb.resume());
        assert!(!cb.is_pending());
    }

    // ID tests

    #[test]
    fn test_id_basic() {
        let id = ID::new(42);
        assert_eq!(id.value, 42);
        assert_eq!(format!("{}", id), "42");
    }

    #[test]
    fn test_id_with_display() {
        let id = ID::with_display(42, "Thread-1");
        assert_eq!(id.value, 42);
        assert_eq!(format!("{}", id), "Thread-1");
    }

    #[test]
    fn test_id_equality() {
        let a = ID::new(1);
        let b = ID::new(1);
        let c = ID::new(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // IDKeyed / IDHashed tests

    struct TestObject {
        id: ID,
        name: String,
    }

    impl IDKeyed for TestObject {
        fn id(&self) -> &ID {
            &self.id
        }
    }

    impl IDHashed for TestObject {}

    #[test]
    fn test_id_keyed() {
        let obj = TestObject {
            id: ID::new(10),
            name: "test".to_string(),
        };
        assert_eq!(obj.id().value, 10);
    }

    #[test]
    fn test_id_hashed() {
        let obj = TestObject {
            id: ID::new(10),
            name: "test".to_string(),
        };
        let _hash = obj.id_hash();
    }

    // ProxyUtilities tests

    #[test]
    fn test_proxy_utilities_shared_ref() {
        let shared = ProxyUtilities::shared_ref(42);
        assert_eq!(*shared.borrow(), 42);
        *shared.borrow_mut() = 100;
        assert_eq!(*shared.borrow(), 100);
    }

    #[test]
    fn test_proxy_utilities_shared_ref_sync() {
        let shared = ProxyUtilities::shared_ref_sync("hello");
        assert_eq!(*shared.lock().unwrap(), "hello");
    }

    // DbgMsgTracer tests

    #[test]
    fn test_dbg_msg_tracer() {
        let mut tracer = DbgMsgTracer::new();
        assert!(!tracer.is_enabled());

        tracer.set_enabled(true);
        assert!(tracer.is_enabled());

        tracer.trace("message 1");
        tracer.trace("message 2");
        assert_eq!(tracer.len(), 2);
        assert_eq!(tracer.messages()[0], "message 1");
        assert_eq!(tracer.messages()[1], "message 2");

        tracer.clear();
        assert!(tracer.is_empty());
    }

    #[test]
    fn test_dbg_msg_tracer_disabled() {
        let mut tracer = DbgMsgTracer::new();
        tracer.trace("should not be recorded");
        assert!(tracer.is_empty());
    }

    // DefaultObservableCollection tests

    #[test]
    fn test_default_observable_collection() {
        let mut col = DefaultObservableCollection::new();
        col.push(10);
        col.push(20);
        assert_eq!(col.len(), 2);
        assert_eq!(col.modification_count(), 2);

        let removed = col.remove(0);
        assert_eq!(removed, 10);
        assert_eq!(col.modification_count(), 3);

        col.clear();
        assert!(col.is_empty());
        assert_eq!(col.modification_count(), 4);
    }

    #[test]
    fn test_default_observable_collection_with_listener() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let events = Rc::new(RefCell::new(Vec::new()));
        let events_clone = events.clone();

        let mut col = DefaultObservableCollection::new();
        col.add_listener(Box::new(move |event: &CollectionChangeEvent<i32>| {
            events_clone.borrow_mut().push(format!("{:?}", event.kind));
        }));

        col.push(1);
        col.push(2);
        col.remove(0);
        col.clear();

        let recorded = events.borrow();
        assert_eq!(recorded.len(), 4);
        assert_eq!(recorded[0], "Added");
        assert_eq!(recorded[1], "Added");
        assert_eq!(recorded[2], "Removed");
        assert_eq!(recorded[3], "Cleared");
    }

    // QueuedListener tests

    #[test]
    fn test_queued_listener() {
        let mut ql = QueuedListener::new();
        assert!(ql.is_active());
        assert!(!ql.has_pending());

        ql.enqueue("event1");
        ql.enqueue("event2");
        assert!(ql.has_pending());

        let events = ql.drain();
        assert_eq!(events, vec!["event1", "event2"]);
        assert!(!ql.has_pending());
    }

    #[test]
    fn test_queued_listener_inactive() {
        let mut ql = QueuedListener::new();
        ql.set_active(false);

        ql.enqueue("event1");
        assert!(!ql.has_pending());
        assert!(ql.drain().is_empty());
    }

    // ServiceConstructionException tests

    #[test]
    fn test_service_construction_exception() {
        let e = ServiceConstructionException::new("something failed");
        assert!(format!("{}", e).contains("something failed"));
    }

    // UnsatisfiedFieldsException tests

    #[test]
    fn test_unsatisfied_fields_exception() {
        let e = UnsatisfiedFieldsException::new(vec!["type_a".into(), "type_b".into()]);
        assert_eq!(e.missing().len(), 2);
        assert!(format!("{}", e).contains("type_a"));
    }

    // UnsatisfiedParameterException tests

    #[test]
    fn test_unsatisfied_parameter_exception() {
        let e = UnsatisfiedParameterException::new(vec!["circular".into()]);
        assert_eq!(e.unresolved().len(), 1);
        assert!(format!("{}", e).contains("circular"));
    }
}
