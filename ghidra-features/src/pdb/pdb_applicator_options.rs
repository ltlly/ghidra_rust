//! PDB Applicator Options -- configuration for PDB application.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions`,
//! `PdbApplicatorControl`, and `ObjectOrientedClassLayout`.

use std::fmt;

/// Processing control for the PDB applicator.
///
/// Determines what aspects of the PDB to apply to the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbApplicatorControl {
    /// Process all PDB data (types, symbols, debug info).
    All,
    /// Process data types only.
    DataTypesOnly,
    /// Process public symbols only.
    PublicSymbolsOnly,
}

impl PdbApplicatorControl {
    /// Get the display label for this control.
    pub fn label(&self) -> &'static str {
        match self {
            PdbApplicatorControl::All => "Process All",
            PdbApplicatorControl::DataTypesOnly => "Data Types Only",
            PdbApplicatorControl::PublicSymbolsOnly => "Public Symbols Only",
        }
    }
}

impl fmt::Display for PdbApplicatorControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Object-oriented class layout algorithm choice.
///
/// Determines how C++ class hierarchies are represented in the data type manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectOrientedClassLayout {
    /// Process members of the current class only (legacy behavior).
    MembersOnly,
    /// Include base class hierarchies in a nested layout.
    ///
    /// This is more suitable for understanding class composition from the
    /// Structure Editor perspective.
    ClassHierarchy,
    /// Same as ClassHierarchy, but also performs speculative virtual class
    /// placement if an in-memory Virtual Base Table is not found.
    ///
    /// This is risky and not advised.
    ClassHierarchySpeculative,
}

impl ObjectOrientedClassLayout {
    /// Get the display label for this layout.
    pub fn label(&self) -> &'static str {
        match self {
            ObjectOrientedClassLayout::MembersOnly => "No C++ Hierarchy (Legacy)",
            ObjectOrientedClassLayout::ClassHierarchy => "Class Hierarchy (Experimental)",
            ObjectOrientedClassLayout::ClassHierarchySpeculative => {
                "Class Hierarchy (Missing VBT Speculation - Risky)"
            }
        }
    }
}

impl fmt::Display for ObjectOrientedClassLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Options used by the PDB applicator when applying PDB data to a Ghidra program.
///
/// These options control various aspects of the PDB application process,
/// including what data to apply and how to handle various edge cases.
#[derive(Debug, Clone)]
pub struct PdbApplicatorOptions {
    /// Processing control.
    control: PdbApplicatorControl,
    /// Whether to apply source line numbers.
    apply_source_line_numbers: bool,
    /// Whether to apply code scope block comments.
    apply_code_scope_block_comments: bool,
    /// Whether to apply instruction labels.
    apply_instruction_labels: bool,
    /// Regular expression for excluding instruction labels.
    exclude_instruction_labels: String,
    /// Whether to attempt address remapping using existing symbols.
    remap_address_using_existing_symbols: bool,
    /// Whether to allow demoting mangled primary symbols.
    allow_demote_primary_mangled_symbols: bool,
    /// Whether to apply function parameters and local variables.
    apply_function_variables: bool,
    /// The composite layout algorithm.
    composite_layout: ObjectOrientedClassLayout,
}

impl PdbApplicatorOptions {
    /// Default exclude instruction labels pattern (never matches).
    const DEFAULT_EXCLUDE_LABELS: &'static str = "$a";

    /// Create a new PdbApplicatorOptions with default values.
    pub fn new() -> Self {
        Self {
            control: PdbApplicatorControl::All,
            apply_source_line_numbers: true,
            apply_code_scope_block_comments: false,
            apply_instruction_labels: false,
            exclude_instruction_labels: Self::DEFAULT_EXCLUDE_LABELS.to_string(),
            remap_address_using_existing_symbols: false,
            allow_demote_primary_mangled_symbols: true,
            apply_function_variables: false,
            composite_layout: ObjectOrientedClassLayout::MembersOnly,
        }
    }

    /// Get the processing control.
    pub fn control(&self) -> PdbApplicatorControl {
        self.control
    }

    /// Set the processing control.
    pub fn set_control(&mut self, control: PdbApplicatorControl) {
        self.control = control;
    }

    /// Check if source line numbers should be applied.
    pub fn apply_source_line_numbers(&self) -> bool {
        self.apply_source_line_numbers
    }

    /// Set whether to apply source line numbers.
    pub fn set_apply_source_line_numbers(&mut self, apply: bool) {
        self.apply_source_line_numbers = apply;
    }

    /// Check if code scope block comments should be applied.
    pub fn apply_code_scope_block_comments(&self) -> bool {
        self.apply_code_scope_block_comments
    }

    /// Set whether to apply code scope block comments.
    pub fn set_apply_code_scope_block_comments(&mut self, apply: bool) {
        self.apply_code_scope_block_comments = apply;
    }

    /// Check if instruction labels should be applied.
    pub fn apply_instruction_labels(&self) -> bool {
        self.apply_instruction_labels
    }

    /// Set whether to apply instruction labels.
    pub fn set_apply_instruction_labels(&mut self, apply: bool) {
        self.apply_instruction_labels = apply;
    }

    /// Get the exclude instruction labels pattern.
    pub fn exclude_instruction_labels(&self) -> &str {
        &self.exclude_instruction_labels
    }

    /// Set the exclude instruction labels pattern.
    pub fn set_exclude_instruction_labels(&mut self, pattern: String) {
        self.exclude_instruction_labels = pattern;
    }

    /// Check if address remapping using existing symbols is enabled.
    pub fn remap_address_using_existing_symbols(&self) -> bool {
        self.remap_address_using_existing_symbols
    }

    /// Set whether to remap addresses using existing symbols.
    pub fn set_remap_address_using_existing_symbols(&mut self, enable: bool) {
        self.remap_address_using_existing_symbols = enable;
    }

    /// Check if demoting mangled primary symbols is allowed.
    pub fn allow_demote_primary_mangled_symbols(&self) -> bool {
        self.allow_demote_primary_mangled_symbols
    }

    /// Set whether to allow demoting mangled primary symbols.
    pub fn set_allow_demote_primary_mangled_symbols(&mut self, allow: bool) {
        self.allow_demote_primary_mangled_symbols = allow;
    }

    /// Check if function variables should be applied.
    pub fn apply_function_variables(&self) -> bool {
        self.apply_function_variables
    }

    /// Set whether to apply function variables.
    pub fn set_apply_function_variables(&mut self, apply: bool) {
        self.apply_function_variables = apply;
    }

    /// Get the composite layout algorithm.
    pub fn composite_layout(&self) -> ObjectOrientedClassLayout {
        self.composite_layout
    }

    /// Set the composite layout algorithm.
    pub fn set_composite_layout(&mut self, layout: ObjectOrientedClassLayout) {
        self.composite_layout = layout;
    }

    /// Reset all options to their default values.
    pub fn set_defaults(&mut self) {
        *self = Self::new();
    }
}

impl Default for PdbApplicatorOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PdbApplicatorOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdbApplicatorOptions [control={}, lines={}, layout={}]",
            self.control, self.apply_source_line_numbers, self.composite_layout
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = PdbApplicatorOptions::new();
        assert_eq!(opts.control(), PdbApplicatorControl::All);
        assert!(opts.apply_source_line_numbers());
        assert!(!opts.apply_code_scope_block_comments());
        assert!(!opts.apply_instruction_labels());
        assert!(!opts.remap_address_using_existing_symbols());
        assert!(opts.allow_demote_primary_mangled_symbols());
        assert!(!opts.apply_function_variables());
        assert_eq!(opts.composite_layout(), ObjectOrientedClassLayout::MembersOnly);
    }

    #[test]
    fn test_set_control() {
        let mut opts = PdbApplicatorOptions::new();
        opts.set_control(PdbApplicatorControl::DataTypesOnly);
        assert_eq!(opts.control(), PdbApplicatorControl::DataTypesOnly);
    }

    #[test]
    fn test_set_source_line_numbers() {
        let mut opts = PdbApplicatorOptions::new();
        opts.set_apply_source_line_numbers(false);
        assert!(!opts.apply_source_line_numbers());
    }

    #[test]
    fn test_set_composite_layout() {
        let mut opts = PdbApplicatorOptions::new();
        opts.set_composite_layout(ObjectOrientedClassLayout::ClassHierarchy);
        assert_eq!(opts.composite_layout(), ObjectOrientedClassLayout::ClassHierarchy);
    }

    #[test]
    fn test_set_defaults() {
        let mut opts = PdbApplicatorOptions::new();
        opts.set_control(PdbApplicatorControl::PublicSymbolsOnly);
        opts.set_apply_source_line_numbers(false);
        opts.set_defaults();
        assert_eq!(opts.control(), PdbApplicatorControl::All);
        assert!(opts.apply_source_line_numbers());
    }

    #[test]
    fn test_control_display() {
        assert_eq!(format!("{}", PdbApplicatorControl::All), "Process All");
        assert_eq!(format!("{}", PdbApplicatorControl::DataTypesOnly), "Data Types Only");
    }

    #[test]
    fn test_layout_display() {
        assert_eq!(
            format!("{}", ObjectOrientedClassLayout::MembersOnly),
            "No C++ Hierarchy (Legacy)"
        );
        assert_eq!(
            format!("{}", ObjectOrientedClassLayout::ClassHierarchy),
            "Class Hierarchy (Experimental)"
        );
    }

    #[test]
    fn test_options_display() {
        let opts = PdbApplicatorOptions::new();
        let s = format!("{}", opts);
        assert!(s.contains("PdbApplicatorOptions"));
        assert!(s.contains("Process All"));
    }

    #[test]
    fn test_exclude_labels() {
        let opts = PdbApplicatorOptions::new();
        assert_eq!(opts.exclude_instruction_labels(), "$a");
    }

    #[test]
    fn test_set_exclude_labels() {
        let mut opts = PdbApplicatorOptions::new();
        opts.set_exclude_instruction_labels("^__.*".to_string());
        assert_eq!(opts.exclude_instruction_labels(), "^__.*");
    }
}
