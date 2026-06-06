//! Code unit formatting for listing display.
//!
//! Ported from `ghidra.program.model.listing`:
//! - [`CodeUnitFormat`] -- formats code units (instructions, data) as display strings
//! - [`CodeUnitFormatOptions`] -- options controlling how code units are formatted

use std::fmt;

// ---------------------------------------------------------------------------
// CodeUnitFormatOptions
// ---------------------------------------------------------------------------

/// Whether to show block name prefixes in formatted addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShowBlockName {
    /// Never show the block name.
    Never,
    /// Always show the block name.
    Always,
    /// Show the block name only for non-local addresses.
    SegmentNonLocal,
}

impl Default for ShowBlockName {
    fn default() -> Self {
        Self::Never
    }
}

/// Whether to show namespace qualifiers on labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShowNamespace {
    /// Never show namespaces.
    Never,
    /// Always show full namespace path.
    Always,
    /// Show namespace only for non-local labels.
    NonLocal,
    /// Show the containing namespace only.
    Containing,
}

impl Default for ShowNamespace {
    fn default() -> Self {
        Self::Never
    }
}

/// Options controlling how code units are rendered as text.
///
/// Ported from `ghidra.program.model.listing.CodeUnitFormatOptions`.
#[derive(Debug, Clone)]
pub struct CodeUnitFormatOptions {
    /// When to show block name prefixes.
    pub show_block_name: ShowBlockName,
    /// When to show namespace qualifiers.
    pub show_namespace: ShowNamespace,
    /// Whether to show extended reference markup (`=>` notation).
    pub show_extended_ref: bool,
    /// Whether to show the address in the representation.
    pub show_address: bool,
    /// Whether to show offcut (mid-instruction) labels.
    pub show_offcut: bool,
    /// Whether to show the default label if no label exists.
    pub show_default_label: bool,
    /// Whether to include data type names in data representations.
    pub include_data_type: bool,
}

impl Default for CodeUnitFormatOptions {
    fn default() -> Self {
        Self {
            show_block_name: ShowBlockName::default(),
            show_namespace: ShowNamespace::default(),
            show_extended_ref: true,
            show_address: false,
            show_offcut: false,
            show_default_label: true,
            include_data_type: true,
        }
    }
}

impl CodeUnitFormatOptions {
    /// Create options with block name and namespace display settings.
    pub fn new(show_block_name: ShowBlockName, show_namespace: ShowNamespace) -> Self {
        Self {
            show_block_name,
            show_namespace,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// CodeUnitFormat
// ---------------------------------------------------------------------------

/// A code unit representation (instruction or data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitRepresentation {
    /// The mnemonic (e.g. `"MOV"`, `"DB"`).
    pub mnemonic: String,
    /// Formatted operand strings.
    pub operands: Vec<String>,
    /// The full address label (with block prefix if configured).
    pub label: Option<String>,
    /// Optional comment text.
    pub comment: Option<String>,
}

impl fmt::Display for CodeUnitRepresentation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref label) = self.label {
            write!(f, "{}: ", label)?;
        }
        write!(f, "{}", self.mnemonic)?;
        if !self.operands.is_empty() {
            write!(f, " {}", self.operands.join(", "))?;
        }
        if let Some(ref comment) = self.comment {
            write!(f, "  // {}", comment)?;
        }
        Ok(())
    }
}

/// Label type for symbol display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelType {
    /// Primary label at this address.
    Primary,
    /// Alternate (local) label.
    Alternate,
    /// Offcut (mid-instruction) label.
    Offcut,
    /// Default auto-generated label (e.g. `LAB_00401000`).
    Default,
    /// External label (library function).
    External,
    /// Entry point label.
    EntryPoint,
    /// Function name.
    Function,
}

/// Delimiter used for extended references.
pub const EXTENDED_REFERENCE_DELIMITER: &str = "=>";

/// Delimiter used for indirect extended references.
pub const EXTENDED_INDIRECT_REFERENCE_DELIMITER: &str = "->";

/// Supported memory address shift cases (bits).
pub const SHIFT_CASES: &[u32] = &[1, 2, 8, 16];

/// Supported memory address mask cases (mask value).
pub const MASK_CASES: &[u64] = &[0x0FFFF, 0x0FFFFFFFF];

/// Default code unit format (never show block, never show namespace).
pub static DEFAULT_FORMAT: CodeUnitFormatOptions = CodeUnitFormatOptions {
    show_block_name: ShowBlockName::Never,
    show_namespace: ShowNamespace::Never,
    show_extended_ref: true,
    show_address: false,
    show_offcut: false,
    show_default_label: true,
    include_data_type: true,
};

/// Formatter for code units.
///
/// Ported from `ghidra.program.model.listing.CodeUnitFormat`.
///
/// Produces human-readable text representations of instructions and data
/// items in the listing, with configurable block-name and namespace display.
#[derive(Debug, Clone)]
pub struct CodeUnitFormat {
    /// Formatting options.
    pub options: CodeUnitFormatOptions,
}

impl CodeUnitFormat {
    /// Create a format with default options.
    pub fn new() -> Self {
        Self {
            options: CodeUnitFormatOptions::default(),
        }
    }

    /// Create a format with specific options.
    pub fn with_options(options: CodeUnitFormatOptions) -> Self {
        Self { options }
    }

    /// Create a format with block name and namespace settings.
    pub fn with_display(
        show_block_name: ShowBlockName,
        show_namespace: ShowNamespace,
    ) -> Self {
        Self {
            options: CodeUnitFormatOptions::new(show_block_name, show_namespace),
        }
    }

    /// Format a mnemonic and operands into a single string.
    pub fn format_mnemonic_operands(&self, mnemonic: &str, operands: &[&str]) -> String {
        if operands.is_empty() {
            mnemonic.to_string()
        } else {
            format!("{} {}", mnemonic, operands.join(", "))
        }
    }

    /// Format a label with optional namespace and block prefix.
    pub fn format_label(
        &self,
        name: &str,
        namespace: Option<&str>,
        block_name: Option<&str>,
        label_type: LabelType,
    ) -> String {
        let mut result = String::new();

        // Block name prefix
        match self.options.show_block_name {
            ShowBlockName::Always => {
                if let Some(bn) = block_name {
                    result.push_str(bn);
                    result.push(':');
                }
            }
            ShowBlockName::SegmentNonLocal => {
                if label_type == LabelType::External || label_type == LabelType::Default {
                    if let Some(bn) = block_name {
                        result.push_str(bn);
                        result.push(':');
                    }
                }
            }
            ShowBlockName::Never => {}
        }

        // Namespace qualifier
        match self.options.show_namespace {
            ShowNamespace::Always => {
                if let Some(ns) = namespace {
                    if !ns.is_empty() {
                        result.push_str(ns);
                        result.push_str("::");
                    }
                }
            }
            ShowNamespace::NonLocal => {
                if label_type != LabelType::Primary && label_type != LabelType::Alternate {
                    if let Some(ns) = namespace {
                        if !ns.is_empty() {
                            result.push_str(ns);
                            result.push_str("::");
                        }
                    }
                }
            }
            ShowNamespace::Containing => {
                // Show only the immediate parent namespace
                if let Some(ns) = namespace {
                    if let Some(last) = ns.rsplit("::").next() {
                        if !last.is_empty() {
                            result.push_str(last);
                            result.push_str("::");
                        }
                    }
                }
            }
            ShowNamespace::Never => {}
        }

        result.push_str(name);
        result
    }

    /// Format an extended reference (e.g. `=>SUB_00401000` or `->local_8`).
    pub fn format_extended_reference(
        &self,
        ref_name: &str,
        is_indirect: bool,
    ) -> String {
        if !self.options.show_extended_ref {
            return String::new();
        }
        let delimiter = if is_indirect {
            EXTENDED_INDIRECT_REFERENCE_DELIMITER
        } else {
            EXTENDED_REFERENCE_DELIMITER
        };
        format!("{}{}", delimiter, ref_name)
    }

    /// Produce a full [`CodeUnitRepresentation`] for a code unit.
    pub fn get_representation(
        &self,
        mnemonic: &str,
        operands: Vec<String>,
        label: Option<String>,
        comment: Option<String>,
    ) -> CodeUnitRepresentation {
        CodeUnitRepresentation {
            mnemonic: mnemonic.to_string(),
            operands,
            label,
            comment,
        }
    }
}

impl Default for CodeUnitFormat {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_format() {
        let fmt = CodeUnitFormat::new();
        assert_eq!(fmt.options.show_block_name, ShowBlockName::Never);
        assert_eq!(fmt.options.show_namespace, ShowNamespace::Never);
        assert!(fmt.options.show_extended_ref);
    }

    #[test]
    fn test_format_mnemonic_operands() {
        let fmt = CodeUnitFormat::new();
        assert_eq!(fmt.format_mnemonic_operands("NOP", &[]), "NOP");
        assert_eq!(
            fmt.format_mnemonic_operands("MOV", &["EAX", "EBX"]),
            "MOV EAX, EBX"
        );
        assert_eq!(
            fmt.format_mnemonic_operands("PUSH", &["[RBP-0x8]"]),
            "PUSH [RBP-0x8]"
        );
    }

    #[test]
    fn test_format_label_never_namespace() {
        let fmt = CodeUnitFormat::new();
        let label = fmt.format_label("main", Some("libc"), Some(".text"), LabelType::Function);
        assert_eq!(label, "main");
    }

    #[test]
    fn test_format_label_always_namespace() {
        let fmt = CodeUnitFormat::with_display(ShowBlockName::Always, ShowNamespace::Always);
        let label = fmt.format_label("main", Some("libc"), Some(".text"), LabelType::Function);
        assert_eq!(label, ".text:libc::main");
    }

    #[test]
    fn test_format_label_non_local_namespace() {
        let fmt = CodeUnitFormat::with_display(ShowBlockName::Never, ShowNamespace::NonLocal);
        // Primary label: no namespace
        let label = fmt.format_label("main", Some("libc"), None, LabelType::Primary);
        assert_eq!(label, "main");
        // External label: with namespace
        let label = fmt.format_label("printf", Some("libc"), None, LabelType::External);
        assert_eq!(label, "libc::printf");
    }

    #[test]
    fn test_format_label_containing_namespace() {
        let fmt = CodeUnitFormat::with_display(ShowBlockName::Never, ShowNamespace::Containing);
        let label =
            fmt.format_label("func", Some("std::io::util"), None, LabelType::Function);
        assert_eq!(label, "util::func");
    }

    #[test]
    fn test_format_label_block_non_local() {
        let fmt = CodeUnitFormat::with_display(ShowBlockName::SegmentNonLocal, ShowNamespace::Never);
        // Default label: show block
        let label = fmt.format_label("LAB_00401000", None, Some(".text"), LabelType::Default);
        assert_eq!(label, ".text:LAB_00401000");
        // Primary label: no block
        let label = fmt.format_label("main", None, Some(".text"), LabelType::Primary);
        assert_eq!(label, "main");
    }

    #[test]
    fn test_format_extended_reference() {
        let fmt = CodeUnitFormat::new();
        assert_eq!(
            fmt.format_extended_reference("SUB_00401000", false),
            "=>SUB_00401000"
        );
        assert_eq!(
            fmt.format_extended_reference("local_8", true),
            "->local_8"
        );
    }

    #[test]
    fn test_format_extended_reference_disabled() {
        let mut fmt = CodeUnitFormat::new();
        fmt.options.show_extended_ref = false;
        assert_eq!(fmt.format_extended_reference("SUB_00401000", false), "");
    }

    #[test]
    fn test_code_unit_representation_display() {
        let repr = CodeUnitRepresentation {
            mnemonic: "MOV".into(),
            operands: vec!["EAX".into(), "0x1".into()],
            label: Some("main".into()),
            comment: Some("set return code".into()),
        };
        let s = format!("{}", repr);
        assert_eq!(s, "main: MOV EAX, 0x1  // set return code");
    }

    #[test]
    fn test_code_unit_representation_no_label() {
        let repr = CodeUnitRepresentation {
            mnemonic: "NOP".into(),
            operands: vec![],
            label: None,
            comment: None,
        };
        assert_eq!(format!("{}", repr), "NOP");
    }

    #[test]
    fn test_show_block_name_default() {
        assert_eq!(ShowBlockName::default(), ShowBlockName::Never);
    }

    #[test]
    fn test_show_namespace_default() {
        assert_eq!(ShowNamespace::default(), ShowNamespace::Never);
    }

    #[test]
    fn test_format_options_new() {
        let opts = CodeUnitFormatOptions::new(ShowBlockName::Always, ShowNamespace::Always);
        assert_eq!(opts.show_block_name, ShowBlockName::Always);
        assert_eq!(opts.show_namespace, ShowNamespace::Always);
        assert!(opts.show_extended_ref); // default
    }

    #[test]
    fn test_label_type_variants() {
        // Ensure all label types are distinguishable
        let types = vec![
            LabelType::Primary,
            LabelType::Alternate,
            LabelType::Offcut,
            LabelType::Default,
            LabelType::External,
            LabelType::EntryPoint,
            LabelType::Function,
        ];
        for (i, a) in types.iter().enumerate() {
            for (j, b) in types.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
