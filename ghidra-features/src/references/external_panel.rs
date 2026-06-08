//! External reference editing panel.
//!
//! Ported from `EditExternalReferencePanel.java`. Manages the state for
//! adding and editing external references to library functions and data.

use ghidra_core::symbol::{DataRefType, RefType, SourceType};
use serde::{Deserialize, Serialize};

/// Represents an external library entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalLibraryEntry {
    /// The library name.
    pub name: String,
    /// The library file path (if associated).
    pub path: Option<String>,
}

impl ExternalLibraryEntry {
    /// Create a new external library entry.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            path: None,
        }
    }

    /// Create an entry with a path.
    pub fn with_path(name: &str, path: &str) -> Self {
        Self {
            name: name.to_string(),
            path: Some(path.to_string()),
        }
    }

    /// Returns true if this is the "UNKNOWN" library.
    pub fn is_unknown(&self) -> bool {
        self.name == "UNKNOWN"
    }
}

impl std::fmt::Display for ExternalLibraryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// External reference editing panel.
///
/// Manages the state for adding and editing external references.
/// Corresponds to `EditExternalReferencePanel.java`.
#[derive(Debug, Clone)]
pub struct ExternalRefPanel {
    /// The source code unit address.
    from_address: Option<u64>,
    /// The operand index.
    op_index: i32,
    /// The selected external library name.
    ext_library_name: String,
    /// The external library file path.
    ext_library_path: Option<String>,
    /// The external label.
    ext_label: Option<String>,
    /// The external address.
    ext_address: Option<u64>,
    /// Available external libraries.
    available_libraries: Vec<ExternalLibraryEntry>,
    /// Whether the panel is in a valid state.
    is_valid: bool,
    /// Whether we are editing an existing reference (vs. adding new).
    is_editing: bool,
}

impl ExternalRefPanel {
    /// Create a new external reference panel.
    pub fn new() -> Self {
        Self {
            from_address: None,
            op_index: -1,
            ext_library_name: "UNKNOWN".to_string(),
            ext_library_path: None,
            ext_label: None,
            ext_address: None,
            available_libraries: Vec::new(),
            is_valid: false,
            is_editing: false,
        }
    }

    /// Initialize the panel for editing an existing external reference.
    ///
    /// Corresponds to `EditExternalReferencePanel.initialize(CodeUnit, Reference)`.
    pub fn initialize_for_edit(
        &mut self,
        from_addr: u64,
        library_name: &str,
        library_path: Option<&str>,
        label: Option<&str>,
        address: Option<u64>,
        libraries: Vec<ExternalLibraryEntry>,
    ) {
        self.is_valid = false;
        self.from_address = Some(from_addr);
        self.is_editing = true;

        self.available_libraries = libraries;
        self.ext_library_name = library_name.to_string();
        self.ext_library_path = library_path.map(|s| s.to_string());
        self.ext_label = label.map(|s| s.to_string());
        self.ext_address = address;

        self.is_valid = true;
    }

    /// Initialize the panel for adding a new external reference.
    ///
    /// Corresponds to `EditExternalReferencePanel.initialize(CodeUnit, int, int)`.
    pub fn initialize_for_add(
        &mut self,
        from_addr: u64,
        op_index: i32,
        libraries: Vec<ExternalLibraryEntry>,
    ) -> bool {
        self.is_valid = false;
        self.is_editing = false;
        self.from_address = Some(from_addr);
        self.op_index = op_index;

        self.available_libraries = libraries;
        self.ext_library_name = "UNKNOWN".to_string();
        self.ext_library_path = None;
        self.ext_label = None;
        self.ext_address = None;

        self.is_valid = true;
        true
    }

    /// Set the external library name.
    pub fn set_library_name(&mut self, name: String) {
        self.ext_library_name = name;
        // Clear the path when name changes.
        self.ext_library_path = None;
    }

    /// Get the external library name.
    pub fn library_name(&self) -> &str {
        &self.ext_library_name
    }

    /// Set the external library path.
    pub fn set_library_path(&mut self, path: Option<String>) {
        self.ext_library_path = path;
    }

    /// Get the external library path.
    pub fn library_path(&self) -> Option<&str> {
        self.ext_library_path.as_deref()
    }

    /// Set the external label.
    pub fn set_label(&mut self, label: Option<String>) {
        self.ext_label = label;
    }

    /// Get the external label.
    pub fn label(&self) -> Option<&str> {
        self.ext_label.as_deref()
    }

    /// Set the external address.
    pub fn set_address(&mut self, addr: Option<u64>) {
        self.ext_address = addr;
    }

    /// Get the external address.
    pub fn address(&self) -> Option<u64> {
        self.ext_address
    }

    /// Set the available libraries.
    pub fn set_available_libraries(&mut self, libraries: Vec<ExternalLibraryEntry>) {
        self.available_libraries = libraries;
    }

    /// Get the available libraries.
    pub fn available_libraries(&self) -> &[ExternalLibraryEntry] {
        &self.available_libraries
    }

    /// Check if the panel is in a valid state.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Check if the panel is in edit mode.
    pub fn is_editing(&self) -> bool {
        self.is_editing
    }

    /// Get the operand index.
    pub fn op_index(&self) -> i32 {
        self.op_index
    }

    /// Get the source address.
    pub fn from_address(&self) -> Option<u64> {
        self.from_address
    }

    /// Update the library path from the available libraries list.
    ///
    /// Looks up the current library name and sets the path accordingly.
    pub fn update_library_path_from_list(&mut self) {
        let name = self.ext_library_name.trim();
        if name.is_empty() {
            self.ext_library_path = None;
            return;
        }

        self.ext_library_path = self.available_libraries
            .iter()
            .find(|lib| lib.name == name)
            .and_then(|lib| lib.path.clone());
    }

    /// Check if the library name has text.
    pub fn has_library_name(&self) -> bool {
        !self.ext_library_name.trim().is_empty()
    }

    /// Validate the current state and return the resolved parameters.
    pub fn validate_and_get_params(&self) -> Result<ExternalRefParams, String> {
        if !self.is_valid {
            return Err("Panel is not in a valid state".to_string());
        }

        let name = self.ext_library_name.trim();
        if name.is_empty() {
            return Err("An external program 'Name' must be specified.".to_string());
        }

        let label = self.ext_label.as_ref().map(|s| s.trim().to_string());
        let addr = self.ext_address;

        if addr.is_none() && (label.is_none() || label.as_ref().map_or(true, |s| s.is_empty())) {
            return Err(
                "Either (or both) an external 'Label' and/or 'Address' must be specified."
                    .to_string(),
            );
        }

        Ok(ExternalRefParams {
            library_name: name.to_string(),
            library_path: self.ext_library_path.clone(),
            label,
            address: addr,
            ref_type: RefType::Data(DataRefType::Data),
            source_type: SourceType::UserDefined,
        })
    }

    /// Apply the reference (add or update).
    ///
    /// Returns the parameters needed by the plugin to execute the command.
    pub fn apply_reference(&self) -> Result<ExternalRefApplyResult, String> {
        let params = self.validate_and_get_params()?;

        Ok(ExternalRefApplyResult {
            from_addr: self.from_address.unwrap(),
            op_index: self.op_index,
            params,
            is_edit: self.is_editing,
        })
    }

    /// Clean up the panel state.
    pub fn cleanup(&mut self) {
        self.is_valid = false;
        self.from_address = None;
        self.is_editing = false;
    }

    /// Set the operand index (only for ADD case).
    ///
    /// Returns true if the operand supports external references.
    pub fn set_op_index(&mut self, op_index: i32) -> bool {
        if self.is_editing {
            return false;
        }

        self.is_valid = false;
        self.op_index = op_index;

        // External references require an operand (not mnemonic).
        if op_index < 0 {
            return false;
        }

        self.is_valid = true;
        true
    }

    /// Populate the available libraries list from an external manager.
    ///
    /// Filters out the "UNKNOWN" library.
    pub fn populate_libraries(&mut self, library_names: &[&str], paths: &[Option<&str>]) {
        self.available_libraries.clear();
        self.available_libraries.push(ExternalLibraryEntry::new("UNKNOWN"));

        for (i, name) in library_names.iter().enumerate() {
            if *name == "UNKNOWN" {
                continue;
            }
            let path = paths.get(i).and_then(|p| *p);
            match path {
                Some(p) => self.available_libraries.push(ExternalLibraryEntry::with_path(name, p)),
                None => self.available_libraries.push(ExternalLibraryEntry::new(name)),
            }
        }
    }
}

impl Default for ExternalRefPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Parameters for creating/updating an external reference.
#[derive(Debug, Clone)]
pub struct ExternalRefParams {
    /// The library name.
    pub library_name: String,
    /// The library file path (optional).
    pub library_path: Option<String>,
    /// The label (optional).
    pub label: Option<String>,
    /// The address (optional).
    pub address: Option<u64>,
    /// The reference type.
    pub ref_type: RefType,
    /// The source type.
    pub source_type: SourceType,
}

/// Result of applying an external reference from the panel.
#[derive(Debug, Clone)]
pub struct ExternalRefApplyResult {
    /// The source address.
    pub from_addr: u64,
    /// The operand index.
    pub op_index: i32,
    /// The external reference parameters.
    pub params: ExternalRefParams,
    /// Whether this is an edit (vs. add).
    pub is_edit: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_ref_panel_new() {
        let panel = ExternalRefPanel::new();
        assert!(!panel.is_valid());
        assert!(!panel.is_editing());
        assert_eq!(panel.library_name(), "UNKNOWN");
        assert!(panel.library_path().is_none());
        assert!(panel.label().is_none());
        assert!(panel.address().is_none());
    }

    #[test]
    fn test_external_ref_panel_initialize_for_add() {
        let mut panel = ExternalRefPanel::new();
        let libs = vec![
            ExternalLibraryEntry::new("UNKNOWN"),
            ExternalLibraryEntry::with_path("libc", "/lib/libc.so"),
        ];
        assert!(panel.initialize_for_add(0x400000, 1, libs));
        assert!(panel.is_valid());
        assert!(!panel.is_editing());
        assert_eq!(panel.from_address(), Some(0x400000));
        assert_eq!(panel.op_index(), 1);
        assert_eq!(panel.available_libraries().len(), 2);
    }

    #[test]
    fn test_external_ref_panel_initialize_for_edit() {
        let mut panel = ExternalRefPanel::new();
        let libs = vec![
            ExternalLibraryEntry::new("UNKNOWN"),
            ExternalLibraryEntry::with_path("libc", "/lib/libc.so"),
        ];
        panel.initialize_for_edit(
            0x400000,
            "libc",
            Some("/lib/libc.so"),
            Some("printf"),
            Some(0x1000),
            libs,
        );
        assert!(panel.is_valid());
        assert!(panel.is_editing());
        assert_eq!(panel.library_name(), "libc");
        assert_eq!(panel.library_path(), Some("/lib/libc.so"));
        assert_eq!(panel.label(), Some("printf"));
        assert_eq!(panel.address(), Some(0x1000));
    }

    #[test]
    fn test_external_ref_panel_set_library_name() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        panel.set_library_path(Some("/old/path".to_string()));
        panel.set_library_name("libc".to_string());
        assert_eq!(panel.library_name(), "libc");
        // Path should be cleared when name changes.
        assert!(panel.library_path().is_none());
    }

    #[test]
    fn test_external_ref_panel_set_label() {
        let mut panel = ExternalRefPanel::new();
        panel.set_label(Some("printf".to_string()));
        assert_eq!(panel.label(), Some("printf"));
    }

    #[test]
    fn test_external_ref_panel_set_address() {
        let mut panel = ExternalRefPanel::new();
        panel.set_address(Some(0x1000));
        assert_eq!(panel.address(), Some(0x1000));
    }

    #[test]
    fn test_external_ref_panel_has_library_name() {
        let mut panel = ExternalRefPanel::new();
        // "UNKNOWN" is set by default, which is non-empty
        assert!(panel.has_library_name());
        panel.set_library_name("".to_string());
        assert!(!panel.has_library_name());
        panel.set_library_name("  ".to_string());
        assert!(!panel.has_library_name());
    }

    #[test]
    fn test_external_ref_panel_validate_no_name() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        panel.set_library_name("".to_string());
        assert!(panel.validate_and_get_params().is_err());
    }

    #[test]
    fn test_external_ref_panel_validate_no_label_or_address() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        panel.set_library_name("libc".to_string());
        // No label and no address.
        assert!(panel.validate_and_get_params().is_err());
    }

    #[test]
    fn test_external_ref_panel_validate_with_label() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        panel.set_library_name("libc".to_string());
        panel.set_label(Some("printf".to_string()));
        assert!(panel.validate_and_get_params().is_ok());
    }

    #[test]
    fn test_external_ref_panel_validate_with_address() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        panel.set_library_name("libc".to_string());
        panel.set_address(Some(0x1000));
        assert!(panel.validate_and_get_params().is_ok());
    }

    #[test]
    fn test_external_ref_panel_apply_valid() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        panel.set_library_name("libc".to_string());
        panel.set_label(Some("printf".to_string()));
        let result = panel.apply_reference().unwrap();
        assert_eq!(result.from_addr, 0x400000);
        assert_eq!(result.params.library_name, "libc");
        assert_eq!(result.params.label.as_deref(), Some("printf"));
        assert!(!result.is_edit);
    }

    #[test]
    fn test_external_ref_panel_apply_edit() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            "libc",
            Some("/lib/libc.so"),
            Some("printf"),
            Some(0x1000),
            vec![],
        );
        let result = panel.apply_reference().unwrap();
        assert!(result.is_edit);
        assert_eq!(result.params.library_name, "libc");
        assert_eq!(result.params.library_path.as_deref(), Some("/lib/libc.so"));
    }

    #[test]
    fn test_external_ref_panel_cleanup() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        assert!(panel.is_valid());
        panel.cleanup();
        assert!(!panel.is_valid());
        assert!(panel.from_address().is_none());
    }

    #[test]
    fn test_external_ref_panel_set_op_index() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        assert!(panel.set_op_index(2));
        assert_eq!(panel.op_index(), 2);
    }

    #[test]
    fn test_external_ref_panel_set_op_index_mnemonic() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_add(0x400000, 0, vec![]);
        assert!(!panel.set_op_index(-1)); // MNEMONIC not supported.
    }

    #[test]
    fn test_external_ref_panel_set_op_index_edit_mode() {
        let mut panel = ExternalRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            "libc",
            None,
            Some("printf"),
            None,
            vec![],
        );
        assert!(!panel.set_op_index(2));
    }

    #[test]
    fn test_external_ref_panel_update_library_path() {
        let mut panel = ExternalRefPanel::new();
        let libs = vec![
            ExternalLibraryEntry::new("UNKNOWN"),
            ExternalLibraryEntry::with_path("libc", "/lib/libc.so"),
        ];
        panel.initialize_for_add(0x400000, 0, libs);
        panel.set_library_name("libc".to_string());
        panel.update_library_path_from_list();
        assert_eq!(panel.library_path(), Some("/lib/libc.so"));
    }

    #[test]
    fn test_external_ref_panel_update_library_path_unknown_lib() {
        let mut panel = ExternalRefPanel::new();
        let libs = vec![
            ExternalLibraryEntry::new("UNKNOWN"),
            ExternalLibraryEntry::with_path("libc", "/lib/libc.so"),
        ];
        panel.initialize_for_add(0x400000, 0, libs);
        panel.set_library_name("nonexistent".to_string());
        panel.update_library_path_from_list();
        assert!(panel.library_path().is_none());
    }

    #[test]
    fn test_external_ref_panel_populate_libraries() {
        let mut panel = ExternalRefPanel::new();
        let names = vec!["UNKNOWN", "libc", "libm"];
        let paths = vec![None, Some("/lib/libc.so"), Some("/lib/libm.so")];
        panel.populate_libraries(&names, &paths);
        assert_eq!(panel.available_libraries().len(), 3); // UNKNOWN + libc + libm
        assert_eq!(panel.available_libraries()[0].name, "UNKNOWN");
        assert_eq!(panel.available_libraries()[1].name, "libc");
        assert_eq!(panel.available_libraries()[1].path.as_deref(), Some("/lib/libc.so"));
    }

    #[test]
    fn test_external_library_entry_new() {
        let entry = ExternalLibraryEntry::new("libc");
        assert_eq!(entry.name, "libc");
        assert!(entry.path.is_none());
        assert!(!entry.is_unknown());
    }

    #[test]
    fn test_external_library_entry_with_path() {
        let entry = ExternalLibraryEntry::with_path("libc", "/lib/libc.so");
        assert_eq!(entry.name, "libc");
        assert_eq!(entry.path.as_deref(), Some("/lib/libc.so"));
    }

    #[test]
    fn test_external_library_entry_is_unknown() {
        let entry = ExternalLibraryEntry::new("UNKNOWN");
        assert!(entry.is_unknown());
        let entry = ExternalLibraryEntry::new("libc");
        assert!(!entry.is_unknown());
    }

    #[test]
    fn test_external_library_entry_display() {
        let entry = ExternalLibraryEntry::new("libc");
        assert_eq!(format!("{}", entry), "libc");
    }

    #[test]
    fn test_external_ref_panel_default() {
        let panel = ExternalRefPanel::default();
        assert!(!panel.is_valid());
        assert_eq!(panel.library_name(), "UNKNOWN");
    }

    #[test]
    fn test_external_ref_params_debug() {
        let params = ExternalRefParams {
            library_name: "libc".to_string(),
            library_path: Some("/lib/libc.so".to_string()),
            label: Some("printf".to_string()),
            address: Some(0x1000),
            ref_type: RefType::Data(DataRefType::Data),
            source_type: SourceType::UserDefined,
        };
        let debug = format!("{:?}", params);
        assert!(debug.contains("libc"));
        assert!(debug.contains("printf"));
    }
}
