//! ProgramTextOptions — configurable layout options for text-based exporters.
//!
//! Ported from Ghidra's `ProgramTextOptions.java`. Controls field widths,
//! inclusion of comments/properties/structures, and formatting prefixes.

use super::traits::{ExporterOption, ExporterException};

// ---------------------------------------------------------------------------
// Constants: field width option names
// ---------------------------------------------------------------------------

const OPTION_FIELD_WIDTHS: &str = "Field Widths";
const OPTION_WIDTH_ADDR: &str = " Address ";
const OPTION_WIDTH_BYTES: &str = " Bytes ";
const OPTION_WIDTH_PREMNEMONIC: &str = " PreMnemonic ";
const OPTION_WIDTH_MNEMONIC: &str = " Mnemonic ";
const OPTION_WIDTH_OPERAND: &str = " Operand ";
const OPTION_WIDTH_EOL: &str = " End of Line ";
const OPTION_WIDTH_LABEL: &str = " Labels ";
const OPTION_WIDTH_REF: &str = " References ";
const OPTION_WIDTH_DATA_FIELD: &str = " Data Field Name ";

const OPTION_INCLUDED_TYPES: &str = "Included Types";
const OPTION_SHOW_COMMENTS: &str = " Comments ";
const OPTION_SHOW_PROPERTIES: &str = " Properties ";
const OPTION_SHOW_STRUCTURES: &str = " Structures ";
const OPTION_SHOW_UNDEFINED: &str = " Undefined Data ";
const OPTION_SHOW_REF_HEADER: &str = " Ref Headers ";
const OPTION_SHOW_BACK_REFS: &str = " Back Refs ";
const OPTION_SHOW_FORWARD_REFS: &str = " Forward Refs ";
const OPTION_SHOW_FUNCTIONS: &str = " Functions ";
const OPTION_SHOW_BLOCK_NAMES: &str = " Block Names ";

const OPTION_PREFIXES: &str = "Special Prefixes";
const OPTION_ADV_LABEL_SUFFIX: &str = " Label Suffix ";
const OPTION_ADV_COMMENT_SUFFIX: &str = " Comment Prefix ";

// Default widths
const DEFAULT_ADDR_WIDTH: usize = 16;
const DEFAULT_BYTES_WIDTH: usize = 12;
const DEFAULT_LABEL_WIDTH: usize = 30;
const DEFAULT_PREMNEMONIC_WIDTH: usize = 4;
const DEFAULT_MNEMONIC_WIDTH: usize = 12;
const DEFAULT_OPERAND_WIDTH: usize = 40;
const DEFAULT_EOL_WIDTH: usize = 40;
const DEFAULT_REF_HEADER_WIDTH: usize = 13;
const DEFAULT_REF_WIDTH: usize = 50;
const DEFAULT_DATA_FIELD_NAME_WIDTH: usize = 12;

const DEFAULT_STACK_VAR_PRENAME_WIDTH: usize = 10;
const DEFAULT_STACK_VAR_NAME_WIDTH: usize = 15;
const DEFAULT_STACK_VAR_DATATYPE_WIDTH: usize = 15;
const DEFAULT_STACK_VAR_OFFSET_WIDTH: usize = 8;
const DEFAULT_STACK_VAR_COMMENT_WIDTH: usize = 20;
const DEFAULT_STACK_VAR_XREF_WIDTH: usize = 60;

const DEFAULT_LABEL_SUFFIX: &str = ":";
const DEFAULT_COMMENT_PREFIX: &str = ";";

// ---------------------------------------------------------------------------
// ProgramTextOptions
// ---------------------------------------------------------------------------

/// Configurable options controlling the layout of text-based program listings.
///
/// This struct mirrors Ghidra's `ProgramTextOptions` class and drives the
/// formatting of the [`ProgramTextWriter`](super::program_text_writer::ProgramTextWriter).
#[derive(Debug, Clone)]
pub struct ProgramTextOptions {
    /// Whether to emit HTML output (anchors, links, font tags).
    pub is_html: bool,

    // Field widths
    pub addr_width: usize,
    pub bytes_width: usize,
    pub label_width: usize,
    pub pre_mnemonic_width: usize,
    pub mnemonic_width: usize,
    pub operand_width: usize,
    pub eol_width: usize,
    pub ref_header_width: usize,
    pub ref_width: usize,
    pub data_field_name_width: usize,

    // Stack variable widths
    pub stack_var_prename_width: usize,
    pub stack_var_name_width: usize,
    pub stack_var_datatype_width: usize,
    pub stack_var_offset_width: usize,
    pub stack_var_comment_width: usize,
    pub stack_var_xref_width: usize,

    // Inclusion flags
    pub show_comments: bool,
    pub show_properties: bool,
    pub show_structures: bool,
    pub show_undefined_data: bool,
    pub show_reference_headers: bool,
    pub show_back_references: bool,
    pub show_forward_references: bool,
    pub show_functions: bool,
    pub show_block_name_in_operands: bool,

    // Prefixes
    pub label_suffix: String,
    pub comment_prefix: String,
}

impl Default for ProgramTextOptions {
    fn default() -> Self {
        Self {
            is_html: false,
            addr_width: DEFAULT_ADDR_WIDTH,
            bytes_width: DEFAULT_BYTES_WIDTH,
            label_width: DEFAULT_LABEL_WIDTH,
            pre_mnemonic_width: DEFAULT_PREMNEMONIC_WIDTH,
            mnemonic_width: DEFAULT_MNEMONIC_WIDTH,
            operand_width: DEFAULT_OPERAND_WIDTH,
            eol_width: DEFAULT_EOL_WIDTH,
            ref_header_width: DEFAULT_REF_HEADER_WIDTH,
            ref_width: DEFAULT_REF_WIDTH,
            data_field_name_width: DEFAULT_DATA_FIELD_NAME_WIDTH,
            stack_var_prename_width: DEFAULT_STACK_VAR_PRENAME_WIDTH,
            stack_var_name_width: DEFAULT_STACK_VAR_NAME_WIDTH,
            stack_var_datatype_width: DEFAULT_STACK_VAR_DATATYPE_WIDTH,
            stack_var_offset_width: DEFAULT_STACK_VAR_OFFSET_WIDTH,
            stack_var_comment_width: DEFAULT_STACK_VAR_COMMENT_WIDTH,
            stack_var_xref_width: DEFAULT_STACK_VAR_XREF_WIDTH,
            show_comments: true,
            show_properties: true,
            show_structures: true,
            show_undefined_data: true,
            show_reference_headers: true,
            show_back_references: true,
            show_forward_references: true,
            show_functions: true,
            show_block_name_in_operands: true,
            label_suffix: DEFAULT_LABEL_SUFFIX.to_string(),
            comment_prefix: DEFAULT_COMMENT_PREFIX.to_string(),
        }
    }
}

impl ProgramTextOptions {
    /// Create options for plain-text output.
    pub fn plaintext() -> Self {
        Self {
            is_html: false,
            ..Default::default()
        }
    }

    /// Create options for HTML output.
    pub fn html() -> Self {
        Self {
            is_html: true,
            ..Default::default()
        }
    }

    /// Get the list of options as `ExporterOption` values (for the UI/API).
    pub fn to_options(&self) -> Vec<ExporterOption> {
        let mut opts = Vec::new();

        // Included types group
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_COMMENTS, self.show_comments)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_PROPERTIES, self.show_properties)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_STRUCTURES, self.show_structures)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_UNDEFINED, self.show_undefined_data)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_REF_HEADER, self.show_reference_headers)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_BACK_REFS, self.show_back_references)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_FORWARD_REFS, self.show_forward_references)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_FUNCTIONS, self.show_functions)
                .with_group(OPTION_INCLUDED_TYPES),
        );
        opts.push(
            ExporterOption::boolean(OPTION_SHOW_BLOCK_NAMES, self.show_block_name_in_operands)
                .with_group(OPTION_INCLUDED_TYPES),
        );

        // Field widths group
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_LABEL, self.label_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_ADDR, self.addr_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_BYTES, self.bytes_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_PREMNEMONIC, self.pre_mnemonic_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_MNEMONIC, self.mnemonic_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_OPERAND, self.operand_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_EOL, self.eol_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_REF, self.ref_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );
        opts.push(
            ExporterOption::integer(OPTION_WIDTH_DATA_FIELD, self.data_field_name_width as i64)
                .with_group(OPTION_FIELD_WIDTHS),
        );

        // Prefixes group
        opts.push(
            ExporterOption::string(OPTION_ADV_LABEL_SUFFIX, &self.label_suffix)
                .with_group(OPTION_PREFIXES),
        );
        opts.push(
            ExporterOption::string(OPTION_ADV_COMMENT_SUFFIX, &self.comment_prefix)
                .with_group(OPTION_PREFIXES),
        );

        opts
    }

    /// Apply a list of `ExporterOption` values to this struct.
    pub fn apply_options(&mut self, options: &[ExporterOption]) -> Result<(), ExporterException> {
        for opt in options {
            let group = opt.group().unwrap_or("");
            let name = opt.name();

            match opt {
                ExporterOption::Boolean { value, .. } => match (group, name) {
                    (g, n) if g == OPTION_INCLUDED_TYPES => match n {
                        _ if n == OPTION_SHOW_COMMENTS => self.show_comments = *value,
                        _ if n == OPTION_SHOW_PROPERTIES => self.show_properties = *value,
                        _ if n == OPTION_SHOW_STRUCTURES => self.show_structures = *value,
                        _ if n == OPTION_SHOW_UNDEFINED => self.show_undefined_data = *value,
                        _ if n == OPTION_SHOW_REF_HEADER => {
                            self.show_reference_headers = *value
                        }
                        _ if n == OPTION_SHOW_BACK_REFS => self.show_back_references = *value,
                        _ if n == OPTION_SHOW_FORWARD_REFS => {
                            self.show_forward_references = *value
                        }
                        _ if n == OPTION_SHOW_FUNCTIONS => self.show_functions = *value,
                        _ if n == OPTION_SHOW_BLOCK_NAMES => {
                            self.show_block_name_in_operands = *value
                        }
                        _ => {
                            return Err(ExporterException::Message(format!(
                                "Unknown option: {} in group: {}",
                                name, group
                            )))
                        }
                    },
                    _ => {
                        return Err(ExporterException::Message(format!(
                            "Unknown option: {} in group: {}",
                            name, group
                        )))
                    }
                },
                ExporterOption::Integer { value, .. } => {
                    let v = *value as usize;
                    match (group, name) {
                        (g, n) if g == OPTION_FIELD_WIDTHS => match n {
                            _ if n == OPTION_WIDTH_LABEL => self.label_width = v,
                            _ if n == OPTION_WIDTH_ADDR => self.addr_width = v,
                            _ if n == OPTION_WIDTH_BYTES => self.bytes_width = v,
                            _ if n == OPTION_WIDTH_PREMNEMONIC => self.pre_mnemonic_width = v,
                            _ if n == OPTION_WIDTH_MNEMONIC => self.mnemonic_width = v,
                            _ if n == OPTION_WIDTH_OPERAND => self.operand_width = v,
                            _ if n == OPTION_WIDTH_EOL => self.eol_width = v,
                            _ if n == OPTION_WIDTH_REF => self.ref_width = v,
                            _ if n == OPTION_WIDTH_DATA_FIELD => self.data_field_name_width = v,
                            _ => {
                                return Err(ExporterException::Message(format!(
                                    "Unknown option: {} in group: {}",
                                    name, group
                                )))
                            }
                        },
                        _ => {
                            return Err(ExporterException::Message(format!(
                                "Unknown option: {} in group: {}",
                                name, group
                            )))
                        }
                    }
                }
                ExporterOption::String { value, .. } => {
                    match (group, name) {
                        (g, n) if g == OPTION_PREFIXES => match n {
                            _ if n == OPTION_ADV_LABEL_SUFFIX => {
                                self.label_suffix = value.clone()
                            }
                            _ if n == OPTION_ADV_COMMENT_SUFFIX => {
                                self.comment_prefix = value.clone()
                            }
                            _ => {
                                return Err(ExporterException::Message(format!(
                                    "Unknown option: {} in group: {}",
                                    name, group
                                )))
                            }
                        },
                        _ => {
                            return Err(ExporterException::Message(format!(
                                "Unknown option: {} in group: {}",
                                name, group
                            )))
                        }
                    }
                }
            }
        }

        // Sanity check: ensure total width is at least 1
        let total = self.addr_width
            + self.bytes_width
            + self.pre_mnemonic_width
            + self.mnemonic_width
            + self.operand_width
            + self.eol_width
            + self.data_field_name_width
            + self.ref_width
            + self.label_width;
        if total < 1 {
            return Err(ExporterException::Message(
                "Need some width values.".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let opts = ProgramTextOptions::default();
        assert_eq!(opts.addr_width, 16);
        assert_eq!(opts.bytes_width, 12);
        assert_eq!(opts.label_width, 30);
        assert_eq!(opts.mnemonic_width, 12);
        assert_eq!(opts.operand_width, 40);
        assert_eq!(opts.comment_prefix, ";");
        assert_eq!(opts.label_suffix, ":");
        assert!(opts.show_comments);
        assert!(!opts.is_html);
    }

    #[test]
    fn test_plaintext_and_html() {
        let pt = ProgramTextOptions::plaintext();
        assert!(!pt.is_html);
        let html = ProgramTextOptions::html();
        assert!(html.is_html);
    }

    #[test]
    fn test_to_options_roundtrip() {
        let mut opts = ProgramTextOptions::default();
        opts.show_comments = false;
        opts.addr_width = 8;
        opts.label_suffix = ":\n".to_string();

        let exported = opts.to_options();
        assert!(!exported.is_empty());

        let mut opts2 = ProgramTextOptions::default();
        opts2.apply_options(&exported).unwrap();

        assert_eq!(opts2.show_comments, false);
        assert_eq!(opts2.addr_width, 8);
        assert_eq!(opts2.label_suffix, ":\n");
    }

    #[test]
    fn test_apply_unknown_option_fails() {
        let mut opts = ProgramTextOptions::default();
        let bad = vec![ExporterOption::boolean("Unknown", true).with_group("Included Types")];
        assert!(opts.apply_options(&bad).is_err());
    }
}
