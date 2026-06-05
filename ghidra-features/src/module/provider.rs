//! Module tree provider.
//!
//! Ported from `ghidra.app.plugin.core.module` classes.
//!
//! Provides the module tree view for navigating program modules
//! (shared libraries, archives, and other program modules).

/// A module entry in the module tree.
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    /// The module name.
    pub name: String,
    /// Module path (for nested modules).
    pub path: String,
    /// The module type.
    pub module_type: ModuleType,
    /// Whether this module is currently loaded.
    pub is_loaded: bool,
    /// The base address (if known).
    pub base_address: Option<u64>,
    /// The size in bytes (if known).
    pub size: Option<u64>,
    /// Child module entries (for nested modules).
    pub children: Vec<ModuleEntry>,
}

/// Module types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleType {
    /// A shared library (.so, .dll, .dylib).
    SharedLibrary,
    /// An archive (.a, .lib).
    Archive,
    /// A main executable.
    Executable,
    /// A plugin or extension.
    Plugin,
    /// Unknown module type.
    Unknown,
}

impl ModuleType {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::SharedLibrary => "Shared Library",
            Self::Archive => "Archive",
            Self::Executable => "Executable",
            Self::Plugin => "Plugin",
            Self::Unknown => "Unknown",
        }
    }
}

/// Provider for the module tree view.
#[derive(Debug)]
pub struct ModuleTreeProvider {
    /// Root module entries.
    modules: Vec<ModuleEntry>,
    /// Selected index.
    selected: Option<usize>,
    /// Whether to show loaded modules only.
    loaded_only: bool,
}

impl ModuleTreeProvider {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            selected: None,
            loaded_only: false,
        }
    }

    pub fn set_modules(&mut self, modules: Vec<ModuleEntry>) {
        self.modules = modules;
        self.selected = None;
    }

    pub fn modules(&self) -> &[ModuleEntry] {
        &self.modules
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    pub fn selected(&self) -> Option<&ModuleEntry> {
        self.selected.and_then(|i| self.modules.get(i))
    }

    pub fn set_loaded_only(&mut self, loaded_only: bool) {
        self.loaded_only = loaded_only;
    }

    pub fn is_loaded_only(&self) -> bool {
        self.loaded_only
    }

    /// Count loaded modules.
    pub fn loaded_count(&self) -> usize {
        self.modules.iter().filter(|m| m.is_loaded).count()
    }

    /// Find a module by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ModuleEntry> {
        self.modules.iter().find(|m| m.name == name)
    }
}

impl Default for ModuleTreeProvider {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_modules() -> Vec<ModuleEntry> {
        vec![
            ModuleEntry {
                name: "main.exe".to_string(),
                path: "/main.exe".to_string(),
                module_type: ModuleType::Executable,
                is_loaded: true,
                base_address: Some(0x400000),
                size: Some(0x10000),
                children: Vec::new(),
            },
            ModuleEntry {
                name: "libgui.so".to_string(),
                path: "/lib/libgui.so".to_string(),
                module_type: ModuleType::SharedLibrary,
                is_loaded: true,
                base_address: Some(0x7F000000),
                size: Some(0x50000),
                children: Vec::new(),
            },
            ModuleEntry {
                name: "unused.so".to_string(),
                path: "/lib/unused.so".to_string(),
                module_type: ModuleType::SharedLibrary,
                is_loaded: false,
                base_address: None,
                size: None,
                children: Vec::new(),
            },
        ]
    }

    #[test]
    fn test_module_tree_provider() {
        let mut provider = ModuleTreeProvider::new();
        provider.set_modules(sample_modules());
        assert_eq!(provider.module_count(), 3);
        assert_eq!(provider.loaded_count(), 2);
    }

    #[test]
    fn test_find_by_name() {
        let mut provider = ModuleTreeProvider::new();
        provider.set_modules(sample_modules());
        assert!(provider.find_by_name("libgui.so").is_some());
        assert!(provider.find_by_name("missing.so").is_none());
    }

    #[test]
    fn test_module_type_display() {
        assert_eq!(ModuleType::Executable.display_name(), "Executable");
        assert_eq!(ModuleType::SharedLibrary.display_name(), "Shared Library");
    }

    #[test]
    fn test_select() {
        let mut provider = ModuleTreeProvider::new();
        provider.set_modules(sample_modules());
        provider.select(Some(1));
        assert_eq!(provider.selected().unwrap().name, "libgui.so");
    }

    #[test]
    fn test_loaded_only() {
        let mut provider = ModuleTreeProvider::new();
        provider.set_loaded_only(true);
        assert!(provider.is_loaded_only());
    }
}
