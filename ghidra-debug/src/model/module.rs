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
            relocated: false,
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
