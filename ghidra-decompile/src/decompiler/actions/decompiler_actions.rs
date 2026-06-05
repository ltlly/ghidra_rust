//! Decompiler-specific actions (rename, retype, convert).
//!
//! Ports Ghidra's `ghidra.app.plugin.core.decompile.actions` package.

/// Types of rename actions in the decompiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameTarget {
    /// Rename a local variable.
    Local,
    /// Rename a global symbol.
    Global,
    /// Rename a function.
    Function,
    /// Rename a label.
    Label,
    /// Rename a struct field.
    Field,
    /// Rename a union field.
    UnionField,
    /// Rename a bit field.
    BitField,
}

/// A rename action in the decompiler.
#[derive(Debug, Clone)]
pub struct RenameAction {
    /// What is being renamed.
    pub target: RenameTarget,
    /// The current name.
    pub current_name: String,
    /// The proposed new name.
    pub new_name: String,
    /// The address of the token being renamed.
    pub address: u64,
    /// The function entry point.
    pub function_entry: u64,
}

impl RenameAction {
    /// Create a new rename action.
    pub fn new(
        target: RenameTarget,
        current_name: impl Into<String>,
        new_name: impl Into<String>,
        address: u64,
        function_entry: u64,
    ) -> Self {
        Self {
            target,
            current_name: current_name.into(),
            new_name: new_name.into(),
            address,
            function_entry,
        }
    }

    /// Validate the new name (basic checks).
    pub fn is_valid_name(&self) -> bool {
        let name = &self.new_name;
        if name.is_empty() {
            return false;
        }
        // Must start with letter or underscore
        if !name.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
            return false;
        }
        // Must contain only alphanumeric + underscore
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
}

/// Types of retype actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetypeTarget {
    /// Retype a local variable.
    Local,
    /// Retype a global variable.
    Global,
    /// Retype a struct field.
    Field,
    /// Retype a union field.
    UnionField,
    /// Retype the return value.
    ReturnValue,
}

/// A retype action in the decompiler.
#[derive(Debug, Clone)]
pub struct RetypeAction {
    /// What is being retyped.
    pub target: RetypeTarget,
    /// The current type name.
    pub current_type: String,
    /// The new type name.
    pub new_type: String,
    /// The address of the token.
    pub address: u64,
    /// The function entry point.
    pub function_entry: u64,
}

/// Numeric conversion actions (hex, decimal, octal, binary, char, float).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionFormat {
    /// Hexadecimal (0x...).
    Hex,
    /// Decimal.
    Decimal,
    /// Octal (0...).
    Octal,
    /// Binary (0b...).
    Binary,
    /// Character literal ('...').
    Char,
    /// Floating point.
    Float,
    /// Equate (named constant).
    Equate,
}

impl ConversionFormat {
    /// Get the display name for this format.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Hex => "Hexadecimal",
            Self::Decimal => "Decimal",
            Self::Octal => "Octal",
            Self::Binary => "Binary",
            Self::Char => "Character",
            Self::Float => "Floating Point",
            Self::Equate => "Equate",
        }
    }

    /// Get the action name for this format.
    pub fn action_name(&self) -> &str {
        match self {
            Self::Hex => "ConvertHexAction",
            Self::Decimal => "ConvertDecAction",
            Self::Octal => "ConvertOctAction",
            Self::Binary => "ConvertBinaryAction",
            Self::Char => "ConvertCharAction",
            Self::Float => "ConvertFloatAction",
            Self::Equate => "ConvertConstantEquateTask",
        }
    }
}

/// A numeric conversion action.
#[derive(Debug, Clone)]
pub struct ConversionAction {
    /// The target format.
    pub format: ConversionFormat,
    /// The address of the constant.
    pub address: u64,
    /// The current value (as integer).
    pub value: i64,
    /// The function entry point.
    pub function_entry: u64,
}

impl ConversionAction {
    /// Format the value in the target format.
    pub fn format_value(&self) -> String {
        match self.format {
            ConversionFormat::Hex => format!("0x{:X}", self.value),
            ConversionFormat::Decimal => format!("{}", self.value),
            ConversionFormat::Octal => format!("0{:o}", self.value),
            ConversionFormat::Binary => format!("0b{:b}", self.value),
            ConversionFormat::Char => {
                if self.value >= 0x20 && self.value <= 0x7E {
                    format!("'{}'", self.value as u8 as char)
                } else {
                    format!("'\\x{:02x}'", self.value)
                }
            }
            ConversionFormat::Float => {
                // Reinterpret the bits as float
                let bits = self.value as u32;
                let f = f32::from_bits(bits);
                format!("{}", f)
            }
            ConversionFormat::Equate => format!("EQUATE_{}", self.value),
        }
    }
}

/// Debug decompiler action.
#[derive(Debug, Clone)]
pub struct DebugDecompilerAction {
    /// The function entry point being debugged.
    pub function_entry: u64,
    /// Whether to dump Pcode.
    pub dump_pcode: bool,
    /// Whether to dump the AST.
    pub dump_ast: bool,
}

impl DebugDecompilerAction {
    pub fn new(function_entry: u64) -> Self {
        Self {
            function_entry,
            dump_pcode: false,
            dump_ast: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rename_valid() {
        let action = RenameAction::new(RenameTarget::Local, "old", "new_name", 0x1000, 0x8000);
        assert!(action.is_valid_name());
    }

    #[test]
    fn test_rename_invalid() {
        let action = RenameAction::new(RenameTarget::Local, "old", "", 0x1000, 0x8000);
        assert!(!action.is_valid_name());
        let action2 = RenameAction::new(RenameTarget::Local, "old", "123bad", 0x1000, 0x8000);
        assert!(!action2.is_valid_name());
        let action3 = RenameAction::new(RenameTarget::Local, "old", "a-b", 0x1000, 0x8000);
        assert!(!action3.is_valid_name());
    }

    #[test]
    fn test_conversion_format_display() {
        assert_eq!(ConversionFormat::Hex.display_name(), "Hexadecimal");
        assert_eq!(ConversionFormat::Char.display_name(), "Character");
    }

    #[test]
    fn test_conversion_format_value() {
        let action = ConversionAction {
            format: ConversionFormat::Hex,
            address: 0x1000,
            value: 255,
            function_entry: 0x8000,
        };
        assert_eq!(action.format_value(), "0xFF");

        let action2 = ConversionAction {
            format: ConversionFormat::Octal,
            address: 0x1000,
            value: 8,
            function_entry: 0x8000,
        };
        assert_eq!(action2.format_value(), "010");

        let action3 = ConversionAction {
            format: ConversionFormat::Char,
            address: 0x1000,
            value: 65,
            function_entry: 0x8000,
        };
        assert_eq!(action3.format_value(), "'A'");
    }

    #[test]
    fn test_rename_targets() {
        assert_eq!(RenameTarget::Local as u8 != RenameTarget::Global as u8, true);
    }
}
