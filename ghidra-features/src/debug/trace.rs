//! Top-level Trace type for the Debug framework.
//!
//! Ported from `ghidra.trace.model.Trace` — the main domain object that
//! coordinates all trace managers.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::bookmark::TraceBookmarkManager;
use super::breakpoint::BreakpointManager;
use super::change_set::TraceChangeSet;
use super::listing::TraceCodeManager;
use super::memory::TraceMemoryManager;
use super::modules::TraceModuleManager;
use super::property::TraceAddressPropertyManager;
use super::stack::TraceStackManager;
use super::static_mapping::TraceStaticMappingManager;
use super::symbol::TraceSymbolManager;
use super::thread::TraceThreadManager;
use super::time::TraceTimeManager;
use super::trace_object::TraceObjectManager;

// ---------------------------------------------------------------------------
// TraceLanguageInfo
// ---------------------------------------------------------------------------

/// Basic language information for a trace.
///
/// This is a simplified representation of Ghidra's Language/CompilerSpec.
#[derive(Debug, Clone)]
pub struct TraceLanguageInfo {
    /// The language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// The compiler spec ID (e.g., "default").
    pub compiler_spec_id: String,
    /// The processor name (e.g., "x86").
    pub processor: String,
    /// The address size in bytes (e.g., 8 for 64-bit).
    pub address_size: usize,
    /// Whether big-endian.
    pub big_endian: bool,
}

impl TraceLanguageInfo {
    /// Create a new language info.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        processor: impl Into<String>,
        address_size: usize,
        big_endian: bool,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            processor: processor.into(),
            address_size,
            big_endian,
        }
    }

    /// An x86 32-bit LE language.
    pub fn x86_le_32() -> Self {
        Self::new("x86:LE:32:default", "default", "x86", 4, false)
    }

    /// An x86 64-bit LE language.
    pub fn x86_le_64() -> Self {
        Self::new("x86:LE:64:default", "default", "x86", 8, false)
    }

    /// An AARCH64 LE language.
    pub fn aarch64_le() -> Self {
        Self::new("AARCH64:LE:64:v8A", "default", "AARCH64", 8, false)
    }

    /// A MIPS 32-bit BE language.
    pub fn mips_be_32() -> Self {
        Self::new("MIPS:BE:32:default", "default", "MIPS", 4, true)
    }
}

impl fmt::Display for TraceLanguageInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.language_id)
    }
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

/// An indexed record of observations over the course of a target's execution.
///
/// Ported from `ghidra.trace.model.Trace`. This is the central domain object
/// that ties together all the trace managers: time, thread, memory, listing,
/// symbols, breakpoints, modules, stacks, bookmarks, properties, static
/// mappings, objects, and more.
///
/// Conceptually, this is the equivalent of a Ghidra `Program`, but multiplied
/// by a concrete dimension of time and organized into snapshots.
#[derive(Debug)]
pub struct Trace {
    /// Unique trace ID.
    id: u64,
    /// The trace name.
    name: String,
    /// Language information.
    language: TraceLanguageInfo,
    /// Emulator cache version.
    emulator_cache_version: u64,

    // --- Managers ---
    /// Manages time / snapshots.
    pub time: TraceTimeManager,
    /// Manages threads and processes.
    pub threads: TraceThreadManager,
    /// Manages memory blocks and regions.
    pub memory: TraceMemoryManager,
    /// Manages code units (listing).
    pub code: TraceCodeManager,
    /// Manages symbols, references, and equates.
    pub symbols: TraceSymbolManager,
    /// Manages breakpoints.
    pub breakpoints: BreakpointManager,
    /// Manages modules and sections.
    pub modules: TraceModuleManager,
    /// Manages stacks.
    pub stacks: TraceStackManager,
    /// Manages bookmarks.
    pub bookmarks: TraceBookmarkManager,
    /// Manages address properties.
    pub properties: TraceAddressPropertyManager,
    /// Manages static mappings.
    pub static_mappings: TraceStaticMappingManager,
    /// Manages target objects.
    pub objects: TraceObjectManager,
}

static TRACE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

impl Trace {
    /// Create a new trace with the given language and name.
    pub fn new(language: TraceLanguageInfo, name: impl Into<String>) -> Self {
        let id = TRACE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            name: name.into(),
            language,
            emulator_cache_version: 0,
            time: TraceTimeManager::new(),
            threads: TraceThreadManager::new(),
            memory: TraceMemoryManager::new(),
            code: TraceCodeManager::new(),
            symbols: TraceSymbolManager::new(),
            breakpoints: BreakpointManager::new(),
            modules: TraceModuleManager::new(),
            stacks: TraceStackManager::new(),
            bookmarks: TraceBookmarkManager::new(),
            properties: TraceAddressPropertyManager::new(),
            static_mappings: TraceStaticMappingManager::new(),
            objects: TraceObjectManager::new(),
        }
    }

    /// Returns the unique trace ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the trace name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the trace name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Returns language information.
    pub fn language(&self) -> &TraceLanguageInfo {
        &self.language
    }

    /// Returns the emulator cache version.
    pub fn emulator_cache_version(&self) -> u64 {
        self.emulator_cache_version
    }

    /// Set the emulator cache version.
    pub fn set_emulator_cache_version(&mut self, version: u64) {
        self.emulator_cache_version = version;
    }

    /// Create a snapshot in the trace.
    pub fn create_snapshot(&mut self, snap: i64) {
        self.time.add_snapshot(snap);
    }

    /// Create a snapshot with a description.
    pub fn create_snapshot_with_desc(&mut self, snap: i64, description: impl Into<String>) {
        self.time.add_snapshot_with_desc(snap, description);
    }

    /// Compute a change set between two snapshots.
    pub fn compute_change_set(&self, since_snap: i64, to_snap: i64) -> TraceChangeSet {
        let mut cs = TraceChangeSet::new(since_snap);

        // Symbol changes
        for id in self.symbols.get_ids_added(since_snap, to_snap) {
            cs.symbol_added(id);
        }
        for id in self.symbols.get_ids_removed(since_snap, to_snap) {
            cs.symbol_removed(id);
        }

        // Bookmark changes
        for bm in self.bookmarks.get_bookmarks_added(since_snap, to_snap) {
            cs.bookmark_changed(bm.offset());
        }
        for bm in self.bookmarks.get_bookmarks_removed(since_snap, to_snap) {
            cs.bookmark_changed(bm.offset());
        }

        cs
    }
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trace({}, {}, lang={})",
            self.id, self.name, self.language
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::core_types::{Lifespan, TraceExecutionState};
    use super::super::breakpoint::BreakpointKindSet;
    #[test]
    fn test_trace_creation() {
        let trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test_trace");
        assert_eq!(trace.name(), "test_trace");
        assert_eq!(trace.language().language_id, "x86:LE:64:default");
        assert_eq!(trace.emulator_cache_version(), 0);
    }

    #[test]
    fn test_trace_set_name() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "original");
        trace.set_name("renamed");
        assert_eq!(trace.name(), "renamed");
    }

    #[test]
    fn test_trace_snapshots() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        trace.create_snapshot(0);
        trace.create_snapshot_with_desc(1, "Step into main");
        trace.create_snapshot(2);

        assert_eq!(trace.time.len(), 3);
        let snap = trace.time.get_snapshot(1).unwrap();
        assert_eq!(snap.description.as_deref(), Some("Step into main"));
    }

    #[test]
    fn test_trace_threads() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        let tk = trace.threads.add_thread(100, 0, "main");
        {
            let thread = trace.threads.get_thread(tk).unwrap();
            assert_eq!(thread.tid, 100);
            assert_eq!(thread.get_name(0), Some("main"));
        }
        {
            let thread_mut = trace.threads.get_thread_mut(tk).unwrap();
            thread_mut.set_execution_state(5, TraceExecutionState::Stopped);
        }
        {
            let thread = trace.threads.get_thread(tk).unwrap();
            assert_eq!(
                thread.get_execution_state(5),
                Some(TraceExecutionState::Stopped)
            );
        }
    }

    #[test]
    fn test_trace_memory() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        trace.memory.add_block(super::super::memory::TraceMemoryBlock::from_bytes(
            0x400000,
            &[0x90, 0xB8, 0x01, 0x00, 0x00, 0x00],
        ));
        let bytes = trace.memory.get_bytes(0x400001, 2).unwrap();
        assert_eq!(bytes, vec![0xB8, 0x01]);

        trace.memory.add_region(0, ".text", 0x400000, 0x400FFF);
        let region = trace.memory.get_region(1).unwrap();
        assert_eq!(region.get_name(0), Some(".text"));
    }

    #[test]
    fn test_trace_code() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        trace.code.create_instruction(
            "ram",
            0x400000,
            "NOP",
            vec![],
            vec![0x90],
            Lifespan::now_on(0),
        );
        trace.code.create_data(
            "ram",
            0x600000,
            "dword",
            4,
            vec![0x78, 0x56, 0x34, 0x12],
            Lifespan::now_on(0),
        );

        assert_eq!(trace.code.count_units(0), 2);
    }

    #[test]
    fn test_trace_symbols() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        let gns = trace.symbols.get_global_namespace().unwrap();
        assert_eq!(gns.name(), "::");

        trace.symbols.create_label(
            "main",
            0,
            "ram",
            0x400000,
            Lifespan::now_on(0),
        );
        let labels = trace.symbols.get_labels(0);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].name(), "main");

        trace.symbols.add_reference(
            0x400000,
            0x400100,
            super::super::symbol::ReferenceType::Call,
            -1,
            Lifespan::now_on(0),
        );
        assert_eq!(trace.symbols.references().count(), 1);
    }

    #[test]
    fn test_trace_breakpoints() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        let spec_key = trace.breakpoints.add_spec(0, BreakpointKindSet::sw_execute());
        trace.breakpoints.add_location_at(spec_key, 0, 0x400000);

        let spec = trace.breakpoints.get_spec(spec_key).unwrap();
        assert!(spec.is_enabled(0));
    }

    #[test]
    fn test_trace_modules() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        let m = trace.modules.add_module(
            0,
            "libc",
            "/usr/lib/libc.so",
            0x7F0000,
            0x7FFFFF,
        );
        trace.modules.add_section(m, 0, ".text", 0x7F0000, 0x7F0FFF);

        let module = trace.modules.get_module(m).unwrap();
        assert_eq!(module.get_name(0), Some("libc"));

        let sections = trace.modules.get_sections_for_module(m);
        assert_eq!(sections.len(), 1);
    }

    #[test]
    fn test_trace_stacks() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        let tk = trace.threads.add_thread(100, 0, "main");
        trace.stacks.create_stack(
            tk,
            0,
            &[0x400100, 0x400200, 0x400300],
        );

        let stack = trace.stacks.find_stack(tk, 0).unwrap();
        assert_eq!(stack.depth(), 3);
    }

    #[test]
    fn test_trace_bookmarks() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        let key = trace.bookmarks.set_bookmark(
            "Note",
            "ram",
            0x400000,
            Lifespan::now_on(0),
            "",
            "Important location",
        );

        let bm = trace.bookmarks.get_bookmark(key).unwrap();
        assert_eq!(bm.type_name(), "Note");
        assert_eq!(bm.comment(), "Important location");
    }

    #[test]
    fn test_trace_properties() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        trace.properties.set("ram", 0x400000, 0, "function_start");
        assert_eq!(
            trace.properties.get("ram", 0x400000, 0),
            Some("function_start")
        );
    }

    #[test]
    fn test_trace_static_mappings() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        trace.static_mappings.add_mapping(
            0x400000,
            0x400FFF,
            "file:///prog",
            "0x100000",
            0,
            Lifespan::now_on(0),
        );

        let found = trace.static_mappings.get_mappings_for_address(0x400500, 0);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_trace_objects() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        let obj = super::super::trace_object::TraceObject::new(
            super::super::trace_object::KeyPath::of("Process"),
            "Process",
            Lifespan::now_on(0),
        );
        trace.objects.add_object(obj);

        let found = trace
            .objects
            .get_object(&super::super::trace_object::KeyPath::of("Process"));
        assert!(found.is_some());
    }

    #[test]
    fn test_trace_change_set() {
        let mut trace = Trace::new(TraceLanguageInfo::x86_le_64(), "test");
        trace.create_snapshot(0);
        trace.symbols.create_label("main", 0, "ram", 0x400000, Lifespan::now_on(0));
        trace.create_snapshot(1);

        let cs = trace.compute_change_set(0, 1);
        assert!(cs.has_changes());
        assert!(cs.has_symbol_changes());
    }

    #[test]
    fn test_trace_display() {
        let trace = Trace::new(TraceLanguageInfo::x86_le_64(), "my_trace");
        let s = format!("{trace}");
        assert!(s.contains("my_trace"));
        assert!(s.contains("x86:LE:64:default"));
    }

    #[test]
    fn test_trace_language_info() {
        let lang = TraceLanguageInfo::x86_le_64();
        assert_eq!(lang.language_id, "x86:LE:64:default");
        assert_eq!(lang.processor, "x86");
        assert_eq!(lang.address_size, 8);
        assert!(!lang.big_endian);

        let mips = TraceLanguageInfo::mips_be_32();
        assert!(mips.big_endian);
        assert_eq!(mips.address_size, 4);
    }
}
