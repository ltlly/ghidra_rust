//! TraceModule / TraceSection - loaded modules and their sections.

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// A loaded module in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceModule {
    /// Unique key for this module.
    pub key: i64,
    /// Full path name.
    pub path: String,
    /// Short name (file system path of the module).
    pub module_name: String,
    /// Base address offset.
    pub min_address: u64,
    /// Maximum address offset.
    pub max_address: u64,
    /// Lifespan of the module (load to unload).
    pub lifespan: Lifespan,
}

impl TraceModule {
    /// Create a new module.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        module_name: impl Into<String>,
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            path: path.into(),
            module_name: module_name.into(),
            min_address,
            max_address,
            lifespan,
        }
    }

    /// Whether this module is loaded at the given snap.
    pub fn is_loaded_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// The address range size.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }
}

/// A section within a loaded module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSection {
    /// Unique key for this section.
    pub key: i64,
    /// Key of the containing module.
    pub module_key: i64,
    /// Full path name.
    pub path: String,
    /// Section name.
    pub name: String,
    /// Start offset.
    pub min_address: u64,
    /// End offset.
    pub max_address: u64,
}

impl TraceSection {
    /// Create a new section.
    pub fn new(
        key: i64,
        module_key: i64,
        path: impl Into<String>,
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            key,
            module_key,
            path: path.into(),
            name: name.into(),
            min_address,
            max_address,
        }
    }

    /// Address range size.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }
}

/// A static mapping between a trace address range and a program address range.
///
/// Ported from Ghidra's `ghidra.trace.model.modules.TraceStaticMapping`.
/// Maps a range in a dynamic trace to a corresponding range in a static
/// Ghidra Program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStaticMapping {
    /// Unique key.
    pub key: i64,
    /// Start offset in the trace.
    pub trace_min_address: u64,
    /// End offset in the trace.
    pub trace_max_address: u64,
    /// Start offset in the mapped program.
    pub program_min_address: u64,
    /// The program URL or path.
    pub program_url: String,
    /// The lifespan (snap range) of this mapping.
    pub lifespan: Lifespan,
    /// Whether the program was relocated.
    pub relocated: bool,
}

impl TraceStaticMapping {
    /// Create a new static mapping.
    pub fn new(
        key: i64,
        trace_min_address: u64,
        trace_max_address: u64,
        program_min_address: u64,
        program_url: impl Into<String>,
    ) -> Self {
        Self {
            key,
            trace_min_address,
            trace_max_address,
            program_min_address,
            program_url: program_url.into(),
            lifespan: Lifespan::now_on(0),
            relocated: false,
        }
    }

    /// Create a new static mapping with an explicit lifespan.
    pub fn with_lifespan(
        key: i64,
        trace_min_address: u64,
        trace_max_address: u64,
        program_min_address: u64,
        program_url: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            trace_min_address,
            trace_max_address,
            program_min_address,
            program_url: program_url.into(),
            lifespan,
            relocated: false,
        }
    }

    /// Get the length of the mapping (trace address range size).
    pub fn length(&self) -> u64 {
        self.trace_max_address - self.trace_min_address + 1
    }

    /// Get the address shift from program to trace.
    pub fn shift(&self) -> i64 {
        (self.trace_min_address as i64) - (self.program_min_address as i64)
    }

    /// Get the starting snap of the lifespan.
    pub fn start_snap(&self) -> i64 {
        self.lifespan.lmin()
    }

    /// Get the ending snap of the lifespan.
    pub fn end_snap(&self) -> i64 {
        self.lifespan.lmax()
    }

    /// Check if this mapping is active at the given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Check if this mapping would conflict with the given prospective mapping.
    pub fn conflicts_with(
        &self,
        min_addr: u64,
        max_addr: u64,
        lifespan: &Lifespan,
        program_url: &str,
        program_min_addr: u64,
    ) -> bool {
        if self.program_url != program_url {
            return self.trace_min_address <= max_addr
                && min_addr <= self.trace_max_address
                && self.lifespan.intersects(lifespan);
        }
        if self.shift() != (min_addr as i64) - (program_min_addr as i64) {
            return self.trace_min_address <= max_addr
                && min_addr <= self.trace_max_address
                && self.lifespan.intersects(lifespan);
        }
        false
    }
}

/// Manager for static mappings between trace and program address ranges.
///
/// Ported from Ghidra's `ghidra.trace.model.modules.TraceStaticMappingManager`.
/// Manages mappings from a trace into static Ghidra Programs.
pub trait TraceStaticMappingManager {
    /// Add a new mapping, if not already covered.
    ///
    /// A new mapping may overlap an existing mapping, so long as they agree
    /// in address shift. Returns the new entry, or any entry which subsumes
    /// the specified mapping.
    fn add_mapping(
        &mut self,
        trace_min: u64,
        trace_max: u64,
        lifespan: Lifespan,
        program_url: &str,
        program_min: u64,
    ) -> Result<TraceStaticMapping, TraceConflictedMappingException>;

    /// Get all mappings in the manager.
    fn get_all_entries(&self) -> Vec<&TraceStaticMapping>;

    /// Find any mapping applicable to the given snap and address.
    fn find_containing(&self, address: u64, snap: i64) -> Option<&TraceStaticMapping>;

    /// Find any mapping that would conflict with the given prospective mapping.
    fn find_any_conflicting(
        &self,
        trace_min: u64,
        trace_max: u64,
        lifespan: &Lifespan,
        program_url: &str,
        program_min: u64,
    ) -> Option<&TraceStaticMapping>;

    /// Find all mappings that overlap the given address range and span of time.
    fn find_all_overlapping(
        &self,
        trace_min: u64,
        trace_max: u64,
        lifespan: &Lifespan,
    ) -> Vec<&TraceStaticMapping>;

    /// Remove a mapping by key.
    fn remove_mapping(&mut self, key: i64) -> bool;
}

/// Exception thrown when a new mapping conflicts with an existing one.
///
/// Ported from Ghidra's `TraceConflictedMappingException`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Conflicting static mapping: {message}")]
pub struct TraceConflictedMappingException {
    /// Description of the conflict.
    pub message: String,
    /// The conflicting existing mapping, if known.
    pub conflicting: Option<TraceStaticMapping>,
}

impl TraceConflictedMappingException {
    /// Create a new conflict exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            conflicting: None,
        }
    }

    /// Create a conflict exception with the conflicting mapping.
    pub fn with_conflicting(message: impl Into<String>, conflicting: TraceStaticMapping) -> Self {
        Self {
            message: message.into(),
            conflicting: Some(conflicting),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_loaded_at() {
        let m = TraceModule::new(1, "mods[1]", "libc.so", 0x7f0000, 0x7fffff, Lifespan::now_on(0));
        assert!(m.is_loaded_at(0));
        assert!(m.is_loaded_at(100));
        assert!(!m.is_loaded_at(-1));
    }

    #[test]
    fn test_module_size() {
        let m = TraceModule::new(1, "mods[1]", "test", 0x100, 0x1ff, Lifespan::at(0));
        assert_eq!(m.size(), 256);
    }

    #[test]
    fn test_section() {
        let s = TraceSection::new(1, 1, "mods[1].sections[.text]", ".text", 0x1000, 0x1fff);
        assert_eq!(s.size(), 0x1000);
        assert_eq!(s.module_key, 1);
    }

    #[test]
    fn test_static_mapping() {
        let m = TraceStaticMapping::new(1, 0x400000, 0x400fff, 0x0, "file:///tmp/prog");
        assert_eq!(m.trace_min_address, 0x400000);
        assert!(!m.relocated);
    }
}
