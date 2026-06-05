//! DebuggerRegions - memory region panel model for the debugger.
//!
//! Ported from Ghidra's `DebuggerRegionsPanel` and related types in
//! `ghidra.app.plugin.core.debug.gui.modules`.

use serde::{Deserialize, Serialize};

/// Permissions for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegionPermissions {
    /// Region is readable.
    pub read: bool,
    /// Region is writable.
    pub write: bool,
    /// Region is executable.
    pub execute: bool,
}

impl RegionPermissions {
    /// All permissions.
    pub fn all() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    /// Read-only.
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }

    /// Read + execute.
    pub fn read_execute() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    /// Read + write.
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// No permissions.
    pub fn none() -> Self {
        Self::default()
    }

    /// Format as rwx string.
    pub fn to_rwx(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.read { 'r' } else { '-' });
        s.push(if self.write { 'w' } else { '-' });
        s.push(if self.execute { 'x' } else { '-' });
        s
    }
}

impl std::fmt::Display for RegionPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_rwx())
    }
}

/// A memory region displayed in the debugger regions panel.
///
/// Ported from Ghidra's memory region types in `DebuggerRegionsPanel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerRegion {
    /// Start address of the region.
    pub min_address: u64,
    /// End address of the region.
    pub max_address: u64,
    /// Region name or label.
    pub name: String,
    /// Permissions.
    pub permissions: RegionPermissions,
    /// The module this region belongs to, if any.
    pub module: Option<String>,
    /// Section name within the module, if any.
    pub section: Option<String>,
    /// Whether this region was mapped from a static program.
    pub is_static: bool,
    /// The thread ID this region belongs to, if thread-local.
    pub thread_id: Option<u64>,
}

impl DebuggerRegion {
    /// Create a new region.
    pub fn new(min_address: u64, max_address: u64, name: impl Into<String>) -> Self {
        Self {
            min_address,
            max_address,
            name: name.into(),
            permissions: RegionPermissions::all(),
            module: None,
            section: None,
            is_static: false,
            thread_id: None,
        }
    }

    /// Set the permissions.
    pub fn with_permissions(mut self, perms: RegionPermissions) -> Self {
        self.permissions = perms;
        self
    }

    /// Set the module name.
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    /// Set the section name.
    pub fn with_section(mut self, section: impl Into<String>) -> Self {
        self.section = Some(section.into());
        self
    }

    /// Mark as statically mapped.
    pub fn with_static(mut self) -> Self {
        self.is_static = true;
        self
    }

    /// The size of this region in bytes.
    pub fn size(&self) -> u64 {
        self.max_address.saturating_sub(self.min_address) + 1
    }

    /// Check if an address falls within this region.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.min_address && address <= self.max_address
    }
}

/// Search scope for finding regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchRegionScope {
    /// Search all regions.
    All,
    /// Search only static (mapped) regions.
    StaticOnly,
    /// Search only dynamic (target-side) regions.
    DynamicOnly,
    /// Search regions belonging to a specific module.
    ModuleOnly,
}

/// Factory for creating region search queries.
///
/// Ported from Ghidra's `DebuggerSearchRegionFactory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRegionQuery {
    /// The address to search for.
    pub address: Option<u64>,
    /// The name substring to search for.
    pub name_pattern: Option<String>,
    /// The search scope.
    pub scope: SearchRegionScope,
    /// The module name to search within (when scope is ModuleOnly).
    pub module: Option<String>,
}

impl SearchRegionQuery {
    /// Create a query for an address.
    pub fn for_address(address: u64) -> Self {
        Self {
            address: Some(address),
            name_pattern: None,
            scope: SearchRegionScope::All,
            module: None,
        }
    }

    /// Create a query for a name pattern.
    pub fn for_name(pattern: impl Into<String>) -> Self {
        Self {
            address: None,
            name_pattern: Some(pattern.into()),
            scope: SearchRegionScope::All,
            module: None,
        }
    }

    /// Restrict to a scope.
    pub fn with_scope(mut self, scope: SearchRegionScope) -> Self {
        self.scope = scope;
        self
    }

    /// Restrict to a module.
    pub fn in_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self.scope = SearchRegionScope::ModuleOnly;
        self
    }

    /// Execute the query against a list of regions.
    pub fn search<'a>(&self, regions: &'a [DebuggerRegion]) -> Vec<&'a DebuggerRegion> {
        regions
            .iter()
            .filter(|r| {
                if let Some(addr) = self.address {
                    if !r.contains(addr) {
                        return false;
                    }
                }
                if let Some(ref pattern) = self.name_pattern {
                    if !r.name.contains(pattern.as_str()) {
                        return false;
                    }
                }
                match self.scope {
                    SearchRegionScope::All => true,
                    SearchRegionScope::StaticOnly => r.is_static,
                    SearchRegionScope::DynamicOnly => !r.is_static,
                    SearchRegionScope::ModuleOnly => {
                        if let Some(ref m) = self.module {
                            r.module.as_deref() == Some(m.as_str())
                        } else {
                            true
                        }
                    }
                }
            })
            .collect()
    }
}

/// The regions panel model for managing displayed memory regions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebuggerRegionsModel {
    /// All known regions.
    pub regions: Vec<DebuggerRegion>,
}

impl DebuggerRegionsModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region.
    pub fn add_region(&mut self, region: DebuggerRegion) {
        self.regions.push(region);
    }

    /// Remove regions overlapping the given range.
    pub fn remove_overlapping(&mut self, min: u64, max: u64) {
        self.regions
            .retain(|r| r.max_address < min || r.min_address > max);
    }

    /// Find the region containing the given address.
    pub fn region_at(&self, address: u64) -> Option<&DebuggerRegion> {
        self.regions.iter().find(|r| r.contains(address))
    }

    /// Get all regions for a given module.
    pub fn regions_for_module(&self, module: &str) -> Vec<&DebuggerRegion> {
        self.regions
            .iter()
            .filter(|r| r.module.as_deref() == Some(module))
            .collect()
    }

    /// Total number of regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether there are no regions.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permissions_display() {
        assert_eq!(RegionPermissions::all().to_string(), "rwx");
        assert_eq!(RegionPermissions::read_only().to_string(), "r--");
        assert_eq!(RegionPermissions::read_execute().to_string(), "r-x");
        assert_eq!(RegionPermissions::none().to_string(), "---");
    }

    #[test]
    fn test_region_contains() {
        let r = DebuggerRegion::new(0x1000, 0x1FFF, "test");
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1500));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn test_region_size() {
        let r = DebuggerRegion::new(0x1000, 0x1FFF, "test");
        assert_eq!(r.size(), 0x1000);
    }

    #[test]
    fn test_regions_model() {
        let mut model = DebuggerRegionsModel::new();
        model.add_region(
            DebuggerRegion::new(0x1000, 0x1FFF, ".text")
                .with_module("libc.so")
                .with_permissions(RegionPermissions::read_execute()),
        );
        model.add_region(
            DebuggerRegion::new(0x2000, 0x2FFF, ".data")
                .with_module("libc.so")
                .with_permissions(RegionPermissions::read_write()),
        );
        assert_eq!(model.len(), 2);

        let text = model.region_at(0x1500);
        assert!(text.is_some());
        assert_eq!(text.unwrap().name, ".text");
    }

    #[test]
    fn test_regions_for_module() {
        let mut model = DebuggerRegionsModel::new();
        model.add_region(DebuggerRegion::new(0x1000, 0x1FFF, ".text").with_module("a.so"));
        model.add_region(DebuggerRegion::new(0x2000, 0x2FFF, ".text").with_module("b.so"));
        model.add_region(DebuggerRegion::new(0x3000, 0x3FFF, ".data").with_module("a.so"));

        let a_regions = model.regions_for_module("a.so");
        assert_eq!(a_regions.len(), 2);
    }

    #[test]
    fn test_search_region_query() {
        let mut model = DebuggerRegionsModel::new();
        model.add_region(
            DebuggerRegion::new(0x1000, 0x1FFF, ".text")
                .with_module("main")
                .with_static(),
        );
        model.add_region(DebuggerRegion::new(0x2000, 0x2FFF, ".stack"));

        let q = SearchRegionQuery::for_address(0x1500);
        let results = q.search(&model.regions);
        assert_eq!(results.len(), 1);

        let q = SearchRegionQuery::for_name(".text");
        let results = q.search(&model.regions);
        assert_eq!(results.len(), 1);

        let q = SearchRegionQuery::for_name("")
            .with_scope(SearchRegionScope::StaticOnly);
        let results = q.search(&model.regions);
        assert_eq!(results.len(), 1);

        let q = SearchRegionQuery::for_name("")
            .with_scope(SearchRegionScope::DynamicOnly);
        let results = q.search(&model.regions);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_region_builder_chain() {
        let r = DebuggerRegion::new(0x400000, 0x401000, "mmap")
            .with_module("libc.so")
            .with_section(".bss")
            .with_static()
            .with_permissions(RegionPermissions::read_write());

        assert_eq!(r.module.as_deref(), Some("libc.so"));
        assert_eq!(r.section.as_deref(), Some(".bss"));
        assert!(r.is_static);
    }

    #[test]
    fn test_remove_overlapping() {
        let mut model = DebuggerRegionsModel::new();
        model.add_region(DebuggerRegion::new(0x1000, 0x1FFF, "old"));
        model.add_region(DebuggerRegion::new(0x3000, 0x3FFF, "keep"));
        model.remove_overlapping(0x1000, 0x1FFF);
        assert_eq!(model.len(), 1);
        assert_eq!(model.regions[0].name, "keep");
    }

    #[test]
    fn test_search_module_scope() {
        let mut model = DebuggerRegionsModel::new();
        model.add_region(DebuggerRegion::new(0x1000, 0x1FFF, ".text").with_module("a.so"));
        model.add_region(DebuggerRegion::new(0x2000, 0x2FFF, ".text").with_module("b.so"));

        let q = SearchRegionQuery::for_name(".text").in_module("a.so");
        let results = q.search(&model.regions);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].module.as_deref(), Some("a.so"));
    }
}
