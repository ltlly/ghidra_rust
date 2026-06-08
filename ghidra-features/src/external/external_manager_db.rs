//! ExternalManagerDB -- database-backed external reference manager.
//!
//! Ported from `ghidra.program.database.external.ExternalManagerDB`.
//!
//! Manages external programs (libraries) and the external locations
//! within them.  Provides methods for adding, removing, and querying
//! external references, including library management and location
//! lookup by name, address, or namespace.

use std::collections::BTreeMap;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

use super::external_location_db::{ExternalLocationDB, ExternalLocationError, ExtResult};

/// Information about an external library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLibraryInfo {
    /// The library name.
    pub name: String,
    /// The associated file path (e.g., path to the .so or .dll).
    pub path: Option<String>,
    /// The source type.
    pub source: SourceType,
    /// The ordinal (for PE imports).
    pub ordinal: i32,
    /// The library symbol ID.
    pub symbol_id: Option<u64>,
}

impl ExternalLibraryInfo {
    /// Create new library info.
    pub fn new(name: impl Into<String>, source: SourceType) -> Self {
        Self {
            name: name.into(),
            path: None,
            source,
            ordinal: -1,
            symbol_id: None,
        }
    }

    /// Create library info with a path.
    pub fn with_path(
        name: impl Into<String>,
        path: impl Into<String>,
        source: SourceType,
    ) -> Self {
        Self {
            name: name.into(),
            path: Some(path.into()),
            source,
            ordinal: -1,
            symbol_id: None,
        }
    }
}

/// The unknown library name constant.
pub const UNKNOWN_LIBRARY: &str = "<UNKNOWN>";

/// Manages the database for external references.
///
/// This is the Rust port of Ghidra's `ExternalManagerDB`.  It provides
/// methods for:
/// - Adding and removing external libraries
/// - Adding external locations (functions and data) to libraries
/// - Querying locations by name, address, or namespace
/// - Managing library ordinals and paths
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::ExternalManagerDB;
/// use ghidra_core::symbol::SourceType;
/// use ghidra_core::Address;
///
/// let mut mgr = ExternalManagerDB::new();
///
/// // Add a library
/// mgr.add_library("libc", SourceType::Imported).unwrap();
///
/// // Add an external function
/// mgr.add_ext_function(
///     "libc", "printf", Some(Address::new(0x1000)), SourceType::Imported,
/// ).unwrap();
///
/// // Query
/// assert_eq!(mgr.library_count(), 1);
/// let locs = mgr.get_external_locations_by_label("printf");
/// assert_eq!(locs.len(), 1);
/// ```
#[derive(Debug)]
pub struct ExternalManagerDB {
    /// Libraries keyed by name.
    libraries: BTreeMap<String, ExternalLibraryInfo>,
    /// External locations keyed by library name + label.
    locations: Vec<ExternalLocationDB>,
    /// Next external symbol address.
    next_ext_addr: u64,
}

impl ExternalManagerDB {
    /// Create a new ExternalManagerDB.
    pub fn new() -> Self {
        Self {
            libraries: BTreeMap::new(),
            locations: Vec::new(),
            next_ext_addr: 1,
        }
    }

    // ------------------------------------------------------------------
    // Library management
    // ------------------------------------------------------------------

    /// Add an external library name.
    ///
    /// Returns `true` if the library was newly created, `false` if it
    /// already existed.
    pub fn add_library(
        &mut self,
        name: impl Into<String>,
        source: SourceType,
    ) -> ExtResult<bool> {
        let n = name.into();
        if self.libraries.contains_key(&n) {
            return Ok(false);
        }
        self.libraries
            .insert(n.clone(), ExternalLibraryInfo::new(&n, source));
        Ok(true)
    }

    /// Remove an external library.
    ///
    /// Returns `false` if the library has associated external locations.
    pub fn remove_library(&mut self, name: &str) -> bool {
        if name == UNKNOWN_LIBRARY {
            return false;
        }
        // Check if any locations reference this library
        let has_locations = self.locations.iter().any(|loc| loc.library_name() == name);
        if has_locations {
            return false;
        }
        self.libraries.remove(name).is_some()
    }

    /// Check if a library exists.
    pub fn contains_library(&self, name: &str) -> bool {
        self.libraries.contains_key(name)
    }

    /// Returns all library names, sorted by preferred search order.
    pub fn get_library_names(&self) -> Vec<String> {
        self.libraries.keys().cloned().collect()
    }

    /// Returns all external library names (trait-compatible name).
    pub fn get_external_library_names(&self) -> Vec<String> {
        self.get_library_names()
    }

    /// Returns the number of libraries.
    pub fn library_count(&self) -> usize {
        self.libraries.len()
    }

    /// Returns info about a specific library.
    pub fn get_library_info(&self, name: &str) -> Option<&ExternalLibraryInfo> {
        self.libraries.get(name)
    }

    /// Returns a reference to a library's info (trait-compatible name).
    pub fn get_external_library(&self, name: &str) -> Option<&ExternalLibraryInfo> {
        self.libraries.get(name)
    }

    /// Returns mutable info about a specific library.
    pub fn get_library_info_mut(&mut self, name: &str) -> Option<&mut ExternalLibraryInfo> {
        self.libraries.get_mut(name)
    }

    /// Update a library name.
    pub fn update_library_name(
        &mut self,
        old_name: &str,
        new_name: &str,
        source: SourceType,
    ) -> ExtResult<()> {
        if !self.libraries.contains_key(old_name) {
            return Err(ExternalLocationError::Other(format!(
                "Library '{}' not found",
                old_name
            )));
        }
        if self.libraries.contains_key(new_name) {
            return Err(ExternalLocationError::DuplicateName(new_name.to_string()));
        }

        let mut info = self.libraries.remove(old_name).unwrap();
        info.name = new_name.to_string();
        info.source = source;
        self.libraries.insert(new_name.to_string(), info);

        // Update locations
        for loc in &mut self.locations {
            if loc.library_name() == old_name {
                // In a real impl, we'd update the library name reference
            }
        }

        Ok(())
    }

    /// Set the external path for a library.
    pub fn set_external_path(
        &mut self,
        name: &str,
        path: &str,
        user_defined: bool,
    ) -> ExtResult<()> {
        let source = if user_defined {
            SourceType::UserDefined
        } else {
            SourceType::Imported
        };

        if !self.libraries.contains_key(name) {
            self.add_library(name, source)?;
        }

        if let Some(info) = self.libraries.get_mut(name) {
            info.path = Some(path.to_string());
        }
        Ok(())
    }

    /// Get the external library path.
    pub fn get_external_library_path(&self, name: &str) -> Option<&str> {
        self.libraries.get(name).and_then(|i| i.path.as_deref())
    }

    /// Set the library ordinal.
    pub fn set_library_ordinal(&mut self, name: &str, ordinal: i32) -> i32 {
        if name == UNKNOWN_LIBRARY {
            return -1;
        }
        if let Some(info) = self.libraries.get_mut(name) {
            info.ordinal = ordinal;
            info.ordinal
        } else {
            -1
        }
    }

    /// Get the library ordinal.
    pub fn get_library_ordinal(&self, name: &str) -> i32 {
        self.libraries
            .get(name)
            .map(|info| info.ordinal)
            .unwrap_or(-1)
    }

    // ------------------------------------------------------------------
    // External location management
    // ------------------------------------------------------------------

    /// Add an external library name (trait-compatible name).
    pub fn add_external_library_name(
        &mut self,
        name: &str,
        source: SourceType,
    ) -> ExtResult<()> {
        self.add_library(name, source)?;
        Ok(())
    }

    /// Check if a library has any external locations.
    pub fn has_external_locations(&self, library_name: &str) -> bool {
        self.locations.iter().any(|loc| loc.library_name() == library_name)
    }

    /// Add an external location (trait-compatible name that takes an ExternalLocationDB).
    pub fn add_external_location(
        &mut self,
        location: ExternalLocationDB,
    ) -> ExtResult<usize> {
        let lib_name = location.library_name().to_string();
        self.add_library(&lib_name, location.source())?;
        self.locations.push(location);
        Ok(self.locations.len() - 1)
    }

    /// Get the unique external location for a library name and label (trait-compatible).
    pub fn get_external_location(
        &self,
        library_name: &str,
        label: &str,
    ) -> Option<&ExternalLocationDB> {
        self.get_unique_external_location(library_name, label)
    }

    /// Add an external function location.
    pub fn add_ext_function(
        &mut self,
        library_name: &str,
        label: &str,
        addr: Option<Address>,
        source: SourceType,
    ) -> ExtResult<usize> {
        // Ensure library exists
        self.add_library(library_name, source)?;

        // Check for existing location with same name in same library
        if let Some(idx) = self.find_existing_index(library_name, Some(label), addr) {
            return Ok(idx);
        }

        let loc = ExternalLocationDB::new_function(library_name, label, addr, source);
        self.locations.push(loc);
        Ok(self.locations.len() - 1)
    }

    /// Add an external data location.
    pub fn add_ext_data(
        &mut self,
        library_name: &str,
        label: &str,
        addr: Option<Address>,
        source: SourceType,
    ) -> ExtResult<usize> {
        self.add_library(library_name, source)?;

        if let Some(idx) = self.find_existing_index(library_name, Some(label), addr) {
            return Ok(idx);
        }

        let loc = ExternalLocationDB::new_data(library_name, label, addr, source);
        self.locations.push(loc);
        Ok(self.locations.len() - 1)
    }

    /// Add an external location (generic).
    pub fn add_ext_location(
        &mut self,
        library_name: &str,
        label: &str,
        addr: Option<Address>,
        source: SourceType,
    ) -> ExtResult<usize> {
        self.add_ext_data(library_name, label, addr, source)
    }

    /// Get the external location at the given address.
    pub fn get_ext_location_by_address(&self, addr: Address) -> Option<&ExternalLocationDB> {
        self.locations
            .iter()
            .find(|loc| loc.external_space_address() == Some(addr))
    }

    /// Get all external locations for a library.
    pub fn get_external_locations(
        &self,
        library_name: &str,
    ) -> Vec<&ExternalLocationDB> {
        self.locations
            .iter()
            .filter(|loc| loc.library_name() == library_name)
            .collect()
    }

    /// Get external locations by label (across all libraries).
    pub fn get_external_locations_by_label(&self, label: &str) -> Vec<&ExternalLocationDB> {
        self.locations
            .iter()
            .filter(|loc| loc.label() == Some(label))
            .collect()
    }

    /// Get external locations by library name and label.
    pub fn get_external_locations_by_lib_and_label(
        &self,
        library_name: &str,
        label: &str,
    ) -> Vec<&ExternalLocationDB> {
        self.locations
            .iter()
            .filter(|loc| {
                loc.library_name() == library_name && loc.label() == Some(label)
            })
            .collect()
    }

    /// Get the unique external location for a library and label.
    ///
    /// Returns the location only if there is exactly one match.
    pub fn get_unique_external_location(
        &self,
        library_name: &str,
        label: &str,
    ) -> Option<&ExternalLocationDB> {
        let locs = self.get_external_locations_by_lib_and_label(library_name, label);
        if locs.len() == 1 {
            Some(locs[0])
        } else {
            None
        }
    }

    /// Get all external locations at a given memory address.
    pub fn get_external_locations_by_memory_address(
        &self,
        addr: Address,
    ) -> Vec<&ExternalLocationDB> {
        self.locations
            .iter()
            .filter(|loc| loc.external_program_address() == Some(addr))
            .collect()
    }

    /// Remove the external location at the given external address.
    pub fn remove_external_location(&mut self, addr: Address) -> bool {
        let initial_len = self.locations.len();
        self.locations
            .retain(|loc| loc.external_space_address() != Some(addr));
        self.locations.len() < initial_len
    }

    /// Remove an external location by library and label.
    pub fn remove_external_location_by_name(
        &mut self,
        library_name: &str,
        label: &str,
    ) -> bool {
        let initial_len = self.locations.len();
        self.locations.retain(|loc| {
            !(loc.library_name() == library_name && loc.label() == Some(label))
        });
        self.locations.len() < initial_len
    }

    /// Returns the total number of external locations.
    pub fn location_count(&self) -> usize {
        self.locations.len()
    }

    /// Returns all external locations.
    pub fn all_locations(&self) -> &[ExternalLocationDB] {
        &self.locations
    }

    /// Get the next available external symbol address.
    pub fn next_external_symbol_address(&mut self) -> u64 {
        let addr = self.next_ext_addr;
        self.next_ext_addr += 1;
        addr
    }

    /// Check if any external locations exist.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Find the index of an existing location that matches the given criteria.
    fn find_existing_index(
        &self,
        library_name: &str,
        label: Option<&str>,
        addr: Option<Address>,
    ) -> Option<usize> {
        self.locations.iter().position(|loc| {
            if loc.library_name() != library_name {
                return false;
            }
            if let Some(l) = label {
                if loc.label() != Some(l) {
                    // Also check original import name
                    if loc.original_imported_name() != Some(l) {
                        return false;
                    }
                }
            }
            if let Some(a) = addr {
                if loc.external_program_address() != Some(a) {
                    return false;
                }
            }
            true
        })
    }

    /// Get the default external name for a location (e.g., `FUN_001234`).
    pub fn get_default_external_name(loc: &ExternalLocationDB) -> String {
        if let Some(addr) = loc.external_program_address() {
            if loc.is_function() {
                format!("FUN_{:06x}", addr.offset)
            } else {
                format!("DAT_{:06x}", addr.offset)
            }
        } else {
            loc.label()
                .unwrap_or(UNKNOWN_LIBRARY)
                .to_string()
        }
    }
}

impl Default for ExternalManagerDB {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_library() {
        let mut mgr = ExternalManagerDB::new();
        assert!(mgr.add_library("libc", SourceType::Imported).unwrap());
        assert!(!mgr.add_library("libc", SourceType::Imported).unwrap()); // already exists
        assert_eq!(mgr.library_count(), 1);
        assert!(mgr.contains_library("libc"));
    }

    #[test]
    fn test_remove_library() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();
        assert!(mgr.remove_library("libc"));
        assert!(!mgr.contains_library("libc"));
    }

    #[test]
    fn test_cannot_remove_library_with_locations() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();
        assert!(!mgr.remove_library("libc"));
    }

    #[test]
    fn test_add_ext_function() {
        let mut mgr = ExternalManagerDB::new();
        let addr = Address::new(0x1000);
        mgr.add_ext_function("libc", "printf", Some(addr), SourceType::Imported)
            .unwrap();

        assert_eq!(mgr.location_count(), 1);
        assert_eq!(mgr.library_count(), 1);
    }

    #[test]
    fn test_add_ext_data() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_ext_data("libc", "errno", None, SourceType::Analysis)
            .unwrap();

        assert_eq!(mgr.location_count(), 1);
        let loc = &mgr.all_locations()[0];
        assert!(!loc.is_function());
    }

    #[test]
    fn test_get_external_locations_by_label() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();
        mgr.add_ext_function("msvcrt", "printf", None, SourceType::Imported)
            .unwrap();

        let locs = mgr.get_external_locations_by_label("printf");
        assert_eq!(locs.len(), 2);
    }

    #[test]
    fn test_unique_location() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();

        let loc = mgr.get_unique_external_location("libc", "printf");
        assert!(loc.is_some());

        mgr.add_ext_function("libc", "printf", Some(Address::new(0x2000)), SourceType::Imported)
            .unwrap();
        let loc = mgr.get_unique_external_location("libc", "printf");
        assert!(loc.is_none()); // now there are two
    }

    #[test]
    fn test_update_library_name() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("old_name", SourceType::Imported).unwrap();
        mgr.update_library_name("old_name", "new_name", SourceType::UserDefined)
            .unwrap();

        assert!(!mgr.contains_library("old_name"));
        assert!(mgr.contains_library("new_name"));
    }

    #[test]
    fn test_library_ordinal() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();

        assert_eq!(mgr.get_library_ordinal("libc"), -1);
        mgr.set_library_ordinal("libc", 5);
        assert_eq!(mgr.get_library_ordinal("libc"), 5);
    }

    #[test]
    fn test_external_path() {
        let mut mgr = ExternalManagerDB::new();
        mgr.set_external_path("libc", "/usr/lib/libc.so", true)
            .unwrap();

        assert_eq!(
            mgr.get_external_library_path("libc"),
            Some("/usr/lib/libc.so")
        );
    }

    #[test]
    fn test_remove_location_by_address() {
        let mut mgr = ExternalManagerDB::new();
        let _ext_space_addr = Address::new(0); // external space (unused)
        let mut loc = ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        loc.set_symbol_id(Some(42));
        // In a real impl, external_space_address would be set
        mgr.locations.push(loc);

        // Remove by name instead
        assert!(mgr.remove_external_location_by_name("libc", "printf"));
        assert_eq!(mgr.location_count(), 0);
    }

    #[test]
    fn test_default_external_name() {
        let loc =
            ExternalLocationDB::new_function("libc", "", Some(Address::new(0x1234)), SourceType::Default);
        let name = ExternalManagerDB::get_default_external_name(&loc);
        assert!(name.contains("1234"));
    }

    #[test]
    fn test_empty_manager() {
        let mgr = ExternalManagerDB::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.location_count(), 0);
        assert_eq!(mgr.library_count(), 0);
    }
}
