//! Additional database implementations for remaining trace model types.
//!
//! Ported from various packages:
//! - `DBTraceBookmark.java`, `DBTraceBookmarkManager.java`
//! - `DBTraceModule.java`, `DBTraceSection.java`, `DBTraceStaticMapping.java`
//! - `DBTraceStackFrame.java`
//! - `DBTraceThreadManager.java`, `DBTraceObjectProcess.java`
//! - `DBTraceGuestPlatform.java`, `DBTraceGuestPlatformMappedRange.java`
//! - `DBTraceRegisterContextSpace.java`
//! - `TraceAddressFactory.java`
//! - `DBTraceDelegatingManager.java`, `AbstractDBTraceSpaceBasedManager.java`

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::model::Lifespan;

// ============================================================================
// Bookmarks
// ============================================================================

/// A bookmark type (e.g., "Analysis", "Breakpoint", "Note").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkType {
    /// Type ID.
    pub id: u64,
    /// Type name.
    pub name: String,
    /// Type category.
    pub category: String,
    /// Display color (hex).
    pub color: u32,
}

/// A trace bookmark.
///
/// Ported from `DBTraceBookmark.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBookmarkEntry {
    /// Bookmark ID.
    pub id: u64,
    /// Bookmark type ID.
    pub type_id: u64,
    /// The address offset.
    pub address_offset: u64,
    /// The address space name.
    pub space_name: String,
    /// The snap.
    pub snap: i64,
    /// Comment text.
    pub comment: String,
}

/// A bookmark space storing bookmarks for a specific address space.
///
/// Ported from `DBTraceBookmarkSpace.java`.
#[derive(Debug)]
pub struct BookmarkSpace {
    pub space_name: String,
    bookmarks: BTreeMap<u64, TraceBookmarkEntry>,
    next_id: u64,
}

impl BookmarkSpace {
    pub fn new(space_name: String) -> Self {
        Self {
            space_name,
            bookmarks: BTreeMap::new(),
            next_id: 1,
        }
    }

    pub fn add_bookmark(&mut self, mut entry: TraceBookmarkEntry) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        entry.id = id;
        self.bookmarks.insert(id, entry);
        id
    }

    pub fn remove_bookmark(&mut self, id: u64) -> Option<TraceBookmarkEntry> {
        self.bookmarks.remove(&id)
    }

    pub fn get_bookmarks_at(&self, snap: i64, offset: u64) -> Vec<&TraceBookmarkEntry> {
        self.bookmarks
            .values()
            .filter(|b| b.snap == snap && b.address_offset == offset)
            .collect()
    }

    pub fn all_bookmarks(&self) -> Vec<&TraceBookmarkEntry> {
        self.bookmarks.values().collect()
    }
}

/// Bookmark manager across all spaces.
///
/// Ported from `DBTraceBookmarkManager.java`.
#[derive(Debug)]
pub struct DbTraceBookmarkManager {
    spaces: BTreeMap<String, BookmarkSpace>,
    types: BTreeMap<u64, BookmarkType>,
    next_type_id: u64,
}

impl DbTraceBookmarkManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            spaces: BTreeMap::new(),
            types: BTreeMap::new(),
            next_type_id: 1,
        };
        // Create built-in types
        mgr.create_type("Analysis".into(), "Analysis".into(), 0x00FF00);
        mgr.create_type("Note".into(), "User".into(), 0xFFFF00);
        mgr.create_type("Breakpoint".into(), "Debug".into(), 0xFF0000);
        mgr
    }

    pub fn create_type(&mut self, name: String, category: String, color: u32) -> u64 {
        let id = self.next_type_id;
        self.next_type_id += 1;
        self.types.insert(
            id,
            BookmarkType {
                id,
                name,
                category,
                color,
            },
        );
        id
    }

    pub fn add_bookmark(
        &mut self,
        space: &str,
        type_id: u64,
        snap: i64,
        offset: u64,
        comment: String,
    ) -> u64 {
        let s = self
            .spaces
            .entry(space.to_string())
            .or_insert_with(|| BookmarkSpace::new(space.to_string()));
        s.add_bookmark(TraceBookmarkEntry {
            id: 0,
            type_id,
            address_offset: offset,
            space_name: space.to_string(),
            snap,
            comment,
        })
    }

    pub fn get_types(&self) -> Vec<&BookmarkType> {
        self.types.values().collect()
    }
}

impl Default for DbTraceBookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Modules and Sections
// ============================================================================

/// A trace module (loaded binary/library).
///
/// Ported from `DBTraceModule.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceModule {
    /// Module ID.
    pub id: u64,
    /// Module name (file path).
    pub name: String,
    /// Base address in trace.
    pub base_offset: u64,
    /// Module size.
    pub size: u64,
    /// Address space.
    pub space_name: String,
    /// Lifespan.
    pub lifespan: Lifespan,
}

/// A trace section within a module.
///
/// Ported from `DBTraceSection.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceSection {
    /// Section ID.
    pub id: u64,
    /// Module ID.
    pub module_id: u64,
    /// Section name.
    pub name: String,
    /// Offset within the module.
    pub offset_in_module: u64,
    /// Section size.
    pub size: u64,
    /// Whether executable.
    pub executable: bool,
    /// Whether writable.
    pub writable: bool,
}

/// A static mapping between program and trace.
///
/// Ported from `DBTraceStaticMapping.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceStaticMapping {
    /// Mapping ID.
    pub id: u64,
    /// Program URL.
    pub program_url: String,
    /// Program address min.
    pub program_min: u64,
    /// Program address max.
    pub program_max: u64,
    /// Trace address min.
    pub trace_min: u64,
    /// Trace address max.
    pub trace_max: u64,
    /// Lifespan.
    pub lifespan: Lifespan,
}

/// Module and static mapping manager.
///
/// Ported from `DBTraceModuleManager.java` and `DBTraceStaticMappingManager.java`.
#[derive(Debug)]
pub struct DbTraceModuleManager {
    modules: BTreeMap<u64, DbTraceModule>,
    sections: BTreeMap<u64, DbTraceSection>,
    static_mappings: BTreeMap<u64, DbTraceStaticMapping>,
    next_id: u64,
}

impl DbTraceModuleManager {
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            sections: BTreeMap::new(),
            static_mappings: BTreeMap::new(),
            next_id: 1,
        }
    }

    pub fn add_module(&mut self, mut module: DbTraceModule) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        module.id = id;
        self.modules.insert(id, module);
        id
    }

    pub fn add_section(&mut self, mut section: DbTraceSection) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        section.id = id;
        self.sections.insert(id, section);
        id
    }

    pub fn add_static_mapping(&mut self, mut mapping: DbTraceStaticMapping) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        mapping.id = id;
        self.static_mappings.insert(id, mapping);
        id
    }

    pub fn get_modules_at_snap(&self, snap: i64) -> Vec<&DbTraceModule> {
        self.modules
            .values()
            .filter(|m| m.lifespan.contains(snap))
            .collect()
    }

    pub fn get_sections_for_module(&self, module_id: u64) -> Vec<&DbTraceSection> {
        self.sections.values().filter(|s| s.module_id == module_id).collect()
    }

    pub fn all_modules(&self) -> Vec<&DbTraceModule> {
        self.modules.values().collect()
    }

    pub fn all_static_mappings(&self) -> Vec<&DbTraceStaticMapping> {
        self.static_mappings.values().collect()
    }
}

impl Default for DbTraceModuleManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Stack Frames
// ============================================================================

/// A trace stack frame.
///
/// Ported from `DBTraceStackFrame.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceStackFrame {
    /// Frame ID.
    pub id: u64,
    /// Thread key.
    pub thread_key: i64,
    /// Frame level (0 = innermost).
    pub level: u32,
    /// Program counter.
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer.
    pub fp: u64,
    /// Return address.
    pub return_address: u64,
    /// Snap at which this frame exists.
    pub snap: i64,
}

// ============================================================================
// Thread Manager
// ============================================================================

/// A trace thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceThread {
    /// Thread ID.
    pub id: u64,
    /// Thread name.
    pub name: String,
    /// Process/aggregate ID.
    pub process_id: u64,
    /// Lifespan.
    pub lifespan: Lifespan,
}

/// A trace process (aggregate of threads).
///
/// Ported from `DBTraceObjectProcess.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceProcess {
    /// Process ID.
    pub id: u64,
    /// Process name.
    pub name: String,
    /// PID (from the debug target).
    pub pid: u64,
    /// Lifespan.
    pub lifespan: Lifespan,
}

/// Thread manager.
///
/// Ported from `DBTraceThreadManager.java`.
#[derive(Debug)]
pub struct DbTraceThreadManager {
    threads: BTreeMap<u64, DbTraceThread>,
    processes: BTreeMap<u64, DbTraceProcess>,
    next_id: u64,
}

impl DbTraceThreadManager {
    pub fn new() -> Self {
        Self {
            threads: BTreeMap::new(),
            processes: BTreeMap::new(),
            next_id: 1,
        }
    }

    pub fn add_thread(&mut self, name: &str, process_id: u64, lifespan: &Lifespan) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.threads.insert(
            id,
            DbTraceThread {
                id,
                name: name.to_string(),
                process_id,
                lifespan: lifespan.clone(),
            },
        );
        id
    }

    pub fn add_process(&mut self, name: &str, pid: u64, lifespan: &Lifespan) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.processes.insert(
            id,
            DbTraceProcess {
                id,
                name: name.to_string(),
                pid,
                lifespan: lifespan.clone(),
            },
        );
        id
    }

    pub fn get_threads_at_snap(&self, snap: i64) -> Vec<&DbTraceThread> {
        self.threads
            .values()
            .filter(|t| t.lifespan.contains(snap))
            .collect()
    }

    pub fn get_thread(&self, id: u64) -> Option<&DbTraceThread> {
        self.threads.get(&id)
    }

    pub fn get_process(&self, id: u64) -> Option<&DbTraceProcess> {
        self.processes.get(&id)
    }

    pub fn all_threads(&self) -> Vec<&DbTraceThread> {
        self.threads.values().collect()
    }
}

impl Default for DbTraceThreadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Guest Platform
// ============================================================================

/// A guest platform (architecture mapped into a trace).
///
/// Ported from `DBTraceGuestPlatform.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceGuestPlatform {
    /// Platform ID.
    pub id: u64,
    /// Language ID.
    pub language_id: String,
    /// Compiler spec ID.
    pub compiler_spec_id: String,
    /// Mapped ranges.
    pub mapped_ranges: Vec<GuestPlatformMappedRange>,
}

/// A mapped range in a guest platform.
///
/// Ported from `DBTraceGuestPlatformMappedRange.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestPlatformMappedRange {
    /// Guest address min.
    pub guest_min: u64,
    /// Guest address max.
    pub guest_max: u64,
    /// Host space name.
    pub host_space: String,
    /// Host address min.
    pub host_min: u64,
    /// Host address max.
    pub host_max: u64,
}

// ============================================================================
// Register Context Space
// ============================================================================

/// A register context space storing register context values.
///
/// Ported from `DBTraceRegisterContextSpace.java`.
#[derive(Debug)]
pub struct DbTraceRegisterContextSpace {
    /// The register name.
    pub register: String,
    /// Context values: (snap, offset) -> value bytes.
    values: BTreeMap<(i64, u64), Vec<u8>>,
}

impl DbTraceRegisterContextSpace {
    pub fn new(register: String) -> Self {
        Self {
            register,
            values: BTreeMap::new(),
        }
    }

    pub fn set_value(&mut self, snap: i64, offset: u64, value: Vec<u8>) {
        self.values.insert((snap, offset), value);
    }

    pub fn get_value(&self, snap: i64, offset: u64) -> Option<&Vec<u8>> {
        // Get latest value at or before snap
        self.values
            .range(..=(snap, offset))
            .rev()
            .next()
            .map(|(_, v)| v)
    }
}

// ============================================================================
// Address Factory
// ============================================================================

/// A factory for creating addresses in a trace.
///
/// Ported from `TraceAddressFactory.java`.
#[derive(Debug)]
pub struct TraceAddressFactory {
    /// Address space name.
    pub space_name: String,
    /// Address size in bytes.
    pub address_size: usize,
}

impl TraceAddressFactory {
    pub fn new(space_name: String, address_size: usize) -> Self {
        Self {
            space_name,
            address_size,
        }
    }

    /// Create an address offset.
    pub fn create_address(&self, offset: u64) -> u64 {
        // In full implementation, would create proper Address objects
        offset
    }
}

// ============================================================================
// Space-Based Manager
// ============================================================================

/// Abstract base for space-based managers.
///
/// Ported from `AbstractDBTraceSpaceBasedManager.java`.
#[derive(Debug)]
pub struct SpaceBasedManager<T: std::fmt::Debug> {
    /// Manager name.
    pub name: String,
    /// Per-space storage.
    pub spaces: BTreeMap<String, T>,
}

impl<T: std::fmt::Debug> SpaceBasedManager<T> {
    pub fn new(name: String) -> Self {
        Self {
            name,
            spaces: BTreeMap::new(),
        }
    }

    pub fn get_space(&self, name: &str) -> Option<&T> {
        self.spaces.get(name)
    }

    pub fn get_space_mut(&mut self, name: &str) -> Option<&mut T> {
        self.spaces.get_mut(name)
    }

    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }
}

/// A delegating manager that forwards operations to space-based sub-managers.
///
/// Ported from `DBTraceDelegatingManager.java`.
pub trait DelegatingManager<S>: std::fmt::Debug {
    /// Get the space for a given address space name.
    fn get_for_space(&self, space_name: &str, create_if_absent: bool) -> Option<&S>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_manager() {
        let mut mgr = DbTraceBookmarkManager::new();
        assert_eq!(mgr.get_types().len(), 3); // Analysis, Note, Breakpoint

        let id = mgr.add_bookmark("ram", 1, 0, 0x400000, "test bookmark".into());
        assert!(id > 0);
    }

    #[test]
    fn test_module_manager() {
        let mut mgr = DbTraceModuleManager::new();
        let module_id = mgr.add_module(DbTraceModule {
            id: 0,
            name: "libc.so".into(),
            base_offset: 0x7F0000,
            size: 0x100000,
            space_name: "ram".into(),
            lifespan: Lifespan::span(0, 100),
        });
        assert!(module_id > 0);

        let modules = mgr.get_modules_at_snap(50);
        assert_eq!(modules.len(), 1);
    }

    #[test]
    fn test_thread_manager() {
        let mut mgr = DbTraceThreadManager::new();
        let proc_id = mgr.add_process("test", 1234, &Lifespan::span(0, 100));
        let thread_id = mgr.add_thread("main", proc_id, &Lifespan::span(0, 100));
        assert!(thread_id > 0);

        let threads = mgr.get_threads_at_snap(50);
        assert_eq!(threads.len(), 1);
    }

    #[test]
    fn test_stack_frame() {
        let frame = DbTraceStackFrame {
            id: 1,
            thread_key: 1,
            level: 0,
            pc: 0x400000,
            sp: 0x7FFF00,
            fp: 0x7FFF80,
            return_address: 0x400100,
            snap: 0,
        };
        assert_eq!(frame.pc, 0x400000);
    }

    #[test]
    fn test_register_context_space() {
        let mut ctx = DbTraceRegisterContextSpace::new("CPSR".into());
        ctx.set_value(0, 0x400000, vec![0x60, 0x00, 0x00, 0x00]);
        let val = ctx.get_value(0, 0x400000);
        assert!(val.is_some());
    }

    #[test]
    fn test_address_factory() {
        let factory = TraceAddressFactory::new("ram".into(), 8);
        assert_eq!(factory.create_address(0x400000), 0x400000);
    }

    #[test]
    fn test_guest_platform() {
        let platform = DbTraceGuestPlatform {
            id: 1,
            language_id: "x86:LE:64:default".into(),
            compiler_spec_id: "default".into(),
            mapped_ranges: vec![GuestPlatformMappedRange {
                guest_min: 0,
                guest_max: 0xFFFFFFFF,
                host_space: "ram".into(),
                host_min: 0x100000000,
                host_max: 0x1FFFFFFFF,
            }],
        };
        assert_eq!(platform.mapped_ranges.len(), 1);
    }
}
