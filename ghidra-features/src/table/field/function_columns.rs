//! Function-related table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `FunctionNameTableColumn` -- displays the function name at a location.
//! - `FunctionSignatureTableColumn` -- displays the function signature.
//! - `FunctionCallingConventionTableColumn` -- displays calling convention.
//! - `FunctionPurgeTableColumn` -- displays stack purge size.
//! - `FunctionParameterCountTableColumn` -- displays parameter count.
//! - `FunctionParameterStackSizeColumn` -- displays parameter stack size.
//! - `FunctionLocalStackSizeColumn` -- displays local stack size.
//! - `FunctionBodySizeTableColumn` -- displays function body size.
//! - `FunctionTagTableColumn` -- displays function tags.
//! - `IsFunctionInlineTableColumn` -- displays inline status.
//! - `IsFunctionNonReturningTableColumn` -- displays no-return status.
//! - `IsFunctionVarargsTableColumn` -- displays varargs status.
//! - `IsFunctionCustomStorageTableColumn` -- displays custom storage status.

use ghidra_core::addr::Address;

use super::traits::{ProgramBasedDynamicTableColumn, ProgramInfo, ProgramLocationTableColumn,
                    ProgramLocationTableColumnExt, ServiceProvider, Settings};
use super::super::mapper::ProgramLocation;

// ---------------------------------------------------------------------------
// FunctionInfo (lightweight function representation)
// ---------------------------------------------------------------------------

/// Lightweight function representation for table column values.
///
/// Stand-in for `ghidra.program.model.listing.Function`.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function entry point.
    pub entry: Address,
    /// Function name.
    pub name: String,
    /// Calling convention name (e.g., "__cdecl", "__stdcall").
    pub calling_convention: String,
    /// Stack purge size (bytes cleaned up by callee on return).
    pub stack_purge_size: i32,
    /// Number of parameters.
    pub parameter_count: usize,
    /// Total size of parameters on the stack.
    pub parameter_stack_size: i32,
    /// Size of local stack frame.
    pub local_stack_size: i32,
    /// Body size in bytes.
    pub body_size: u64,
    /// Whether the function is inline.
    pub is_inline: bool,
    /// Whether the function does not return.
    pub has_no_return: bool,
    /// Whether the function is a thunk.
    pub is_thunk: bool,
    /// Whether the function uses custom storage.
    pub has_custom_storage: bool,
    /// Whether the function is varargs.
    pub is_varargs: bool,
    /// Function tags (e.g., "library", "decompiler").
    pub tags: Vec<String>,
    /// Full signature string.
    pub signature: String,
}

impl FunctionInfo {
    /// Create a new function info with default values.
    pub fn new(entry: Address, name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            entry,
            name: name.clone(),
            calling_convention: "default".into(),
            stack_purge_size: 0,
            parameter_count: 0,
            parameter_stack_size: 0,
            local_stack_size: 0,
            body_size: 0,
            is_inline: false,
            has_no_return: false,
            is_thunk: false,
            has_custom_storage: false,
            is_varargs: false,
            tags: Vec::new(),
            signature: name,
        }
    }

    /// Returns the prototype string (signature without annotations).
    pub fn prototype_string(&self) -> &str {
        &self.signature
    }

    /// Returns the full display signature with annotations.
    pub fn display_signature(&self, show_inline: bool, show_thunk: bool,
                             show_noreturn: bool) -> String {
        let mut buf = String::new();
        if self.is_inline && show_inline {
            buf.push_str("inline ");
        }
        if self.is_thunk && show_thunk {
            buf.push_str("thunk ");
        }
        if self.has_no_return && show_noreturn {
            buf.push_str("noreturn ");
        }
        buf.push_str(&self.signature);
        buf
    }

    /// Returns the stack purge size as a display string.
    pub fn purge_display(&self) -> String {
        match self.stack_purge_size {
            i32::MIN..=-2 => format!("INV"),
            -1 => "UNK".to_string(),
            0 => "UNK".to_string(),
            v if v > 0 => format!("{:x}", v),
            _ => "UNK".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionNameTableColumn
// ---------------------------------------------------------------------------

/// Displays the function name containing the address.
///
/// Ported from `ghidra.util.table.field.FunctionNameTableColumn`.
#[derive(Debug)]
pub struct FunctionNameTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for FunctionNameTableColumn {
    fn column_name(&self) -> &str { "Function Name" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, look up the function containing the address.
        None
    }

    fn preferred_width(&self) -> usize { 200 }
}

impl ProgramLocationTableColumn<Address> for FunctionNameTableColumn {
    fn get_program_location(&self, row: &Address, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(*row))
    }
}

impl ProgramLocationTableColumnExt<Address> for FunctionNameTableColumn {}

// ---------------------------------------------------------------------------
// FunctionSignatureTableColumn
// ---------------------------------------------------------------------------

/// Displays the function signature, optionally with inline/thunk/noreturn annotations.
///
/// Ported from `ghidra.util.table.field.FunctionSignatureTableColumn`.
#[derive(Debug)]
pub struct FunctionSignatureTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionSignatureTableColumn {
    fn column_name(&self) -> &str { "Function Signature" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(row.display_signature(true, true, true))
    }

    fn preferred_width(&self) -> usize { 200 }
}

impl ProgramLocationTableColumn<FunctionInfo> for FunctionSignatureTableColumn {
    fn get_program_location(&self, row: &FunctionInfo, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(row.entry))
    }
}

impl ProgramLocationTableColumnExt<FunctionInfo> for FunctionSignatureTableColumn {}

// ---------------------------------------------------------------------------
// FunctionCallingConventionTableColumn
// ---------------------------------------------------------------------------

/// Displays the calling convention for a function.
///
/// Ported from `ghidra.util.table.field.FunctionCallingConventionTableColumn`.
#[derive(Debug)]
pub struct FunctionCallingConventionTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionCallingConventionTableColumn {
    fn column_name(&self) -> &str { "Calling Convention" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(row.calling_convention.clone())
    }
}

// ---------------------------------------------------------------------------
// FunctionPurgeTableColumn
// ---------------------------------------------------------------------------

/// Displays the stack purge size for a function.
///
/// Ported from `ghidra.util.table.field.FunctionPurgeTableColumn`.
#[derive(Debug)]
pub struct FunctionPurgeTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionPurgeTableColumn {
    fn column_name(&self) -> &str { "Function Purge" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(row.purge_display())
    }
}

// ---------------------------------------------------------------------------
// FunctionParameterCountTableColumn
// ---------------------------------------------------------------------------

/// Displays the number of parameters for a function.
///
/// Ported from `ghidra.util.table.field.FunctionParameterCountTableColumn`.
#[derive(Debug)]
pub struct FunctionParameterCountTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionParameterCountTableColumn {
    fn column_name(&self) -> &str { "Param Count" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(row.parameter_count.to_string())
    }
}

// ---------------------------------------------------------------------------
// FunctionParameterStackSizeColumn
// ---------------------------------------------------------------------------

/// Displays the total size of function parameters on the stack.
///
/// Ported from `ghidra.util.table.field.FunctionParameterStackSizeColumn`.
#[derive(Debug)]
pub struct FunctionParameterStackSizeColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionParameterStackSizeColumn {
    fn column_name(&self) -> &str { "Param Stack Size" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(format!("{}", row.parameter_stack_size))
    }
}

// ---------------------------------------------------------------------------
// FunctionLocalStackSizeColumn
// ---------------------------------------------------------------------------

/// Displays the local stack frame size.
///
/// Ported from `ghidra.util.table.field.FunctionLocalStackSizeColumn`.
#[derive(Debug)]
pub struct FunctionLocalStackSizeColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionLocalStackSizeColumn {
    fn column_name(&self) -> &str { "Local Stack Size" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(format!("{}", row.local_stack_size))
    }
}

// ---------------------------------------------------------------------------
// FunctionBodySizeTableColumn
// ---------------------------------------------------------------------------

/// Displays the function body size in bytes.
///
/// Ported from `ghidra.util.table.field.FunctionBodySizeTableColumn`.
#[derive(Debug)]
pub struct FunctionBodySizeTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionBodySizeTableColumn {
    fn column_name(&self) -> &str { "Body Size" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(format!("{}", row.body_size))
    }
}

// ---------------------------------------------------------------------------
// FunctionTagTableColumn
// ---------------------------------------------------------------------------

/// Displays the function tags as a comma-separated string.
///
/// Ported from `ghidra.util.table.field.FunctionTagTableColumn`.
#[derive(Debug)]
pub struct FunctionTagTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for FunctionTagTableColumn {
    fn column_name(&self) -> &str { "Tags" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        if row.tags.is_empty() {
            None
        } else {
            Some(row.tags.join(", "))
        }
    }
}

// ---------------------------------------------------------------------------
// IsFunctionInlineTableColumn
// ---------------------------------------------------------------------------

/// Displays whether a function is inline.
///
/// Ported from `ghidra.util.table.field.IsFunctionInlineTableColumn`.
#[derive(Debug)]
pub struct IsFunctionInlineTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for IsFunctionInlineTableColumn {
    fn column_name(&self) -> &str { "Inline" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(if row.is_inline { "true".into() } else { "false".into() })
    }
}

// ---------------------------------------------------------------------------
// IsFunctionNonReturningTableColumn
// ---------------------------------------------------------------------------

/// Displays whether a function does not return.
///
/// Ported from `ghidra.util.table.field.IsFunctionNonReturningTableColumn`.
#[derive(Debug)]
pub struct IsFunctionNonReturningTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for IsFunctionNonReturningTableColumn {
    fn column_name(&self) -> &str { "No Return" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(if row.has_no_return { "true".into() } else { "false".into() })
    }
}

// ---------------------------------------------------------------------------
// IsFunctionVarargsTableColumn
// ---------------------------------------------------------------------------

/// Displays whether a function is varargs.
///
/// Ported from `ghidra.util.table.field.IsFunctionVarargsTableColumn`.
#[derive(Debug)]
pub struct IsFunctionVarargsTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for IsFunctionVarargsTableColumn {
    fn column_name(&self) -> &str { "Varargs" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(if row.is_varargs { "true".into() } else { "false".into() })
    }
}

// ---------------------------------------------------------------------------
// IsFunctionCustomStorageTableColumn
// ---------------------------------------------------------------------------

/// Displays whether a function uses custom storage.
///
/// Ported from `ghidra.util.table.field.IsFunctionCustomStorageTableColumn`.
#[derive(Debug)]
pub struct IsFunctionCustomStorageTableColumn;

impl ProgramBasedDynamicTableColumn<FunctionInfo> for IsFunctionCustomStorageTableColumn {
    fn column_name(&self) -> &str { "Custom Storage" }

    fn get_value(&self, row: &FunctionInfo, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(if row.has_custom_storage { "true".into() } else { "false".into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fn() -> FunctionInfo {
        let mut f = FunctionInfo::new(Address::new(0x401000), "main");
        f.signature = "int main(int argc, char **argv)".into();
        f.calling_convention = "__cdecl".into();
        f.parameter_count = 2;
        f.parameter_stack_size = 8;
        f.local_stack_size = 64;
        f.body_size = 256;
        f.stack_purge_size = 8;
        f.tags = vec!["entry".into(), "main".into()];
        f
    }

    fn test_program() -> ProgramInfo {
        ProgramInfo::new("test", "x86:LE:64:default")
    }

    fn test_sp() -> ServiceProvider {
        ServiceProvider::new("TestTool")
    }

    #[test]
    fn test_function_name_column() {
        let col = FunctionNameTableColumn;
        assert_eq!(col.column_name(), "Function Name");
        assert_eq!(col.preferred_width(), 200);
    }

    #[test]
    fn test_function_signature_column() {
        let col = FunctionSignatureTableColumn;
        assert_eq!(col.column_name(), "Function Signature");
        let f = test_fn();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert!(val.contains("int main"));
    }

    #[test]
    fn test_function_signature_with_annotations() {
        let mut f = test_fn();
        f.is_inline = true;
        f.has_no_return = true;
        let sig = f.display_signature(true, true, true);
        assert!(sig.starts_with("inline noreturn "));
    }

    #[test]
    fn test_function_calling_convention() {
        let col = FunctionCallingConventionTableColumn;
        let f = test_fn();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "__cdecl");
    }

    #[test]
    fn test_function_purge_normal() {
        let col = FunctionPurgeTableColumn;
        let f = test_fn();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "8");
    }

    #[test]
    fn test_function_purge_unknown() {
        let col = FunctionPurgeTableColumn;
        let mut f = test_fn();
        f.stack_purge_size = -1;
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "UNK");
    }

    #[test]
    fn test_function_parameter_count() {
        let col = FunctionParameterCountTableColumn;
        let f = test_fn();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "2");
    }

    #[test]
    fn test_function_body_size() {
        let col = FunctionBodySizeTableColumn;
        let f = test_fn();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "256");
    }

    #[test]
    fn test_function_tag_column() {
        let col = FunctionTagTableColumn;
        let f = test_fn();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "entry, main");
    }

    #[test]
    fn test_function_tag_empty() {
        let col = FunctionTagTableColumn;
        let mut f = test_fn();
        f.tags.clear();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp());
        assert!(val.is_none());
    }

    #[test]
    fn test_is_function_inline() {
        let col = IsFunctionInlineTableColumn;
        let mut f = test_fn();
        f.is_inline = true;
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "true");
    }

    #[test]
    fn test_is_function_no_return() {
        let col = IsFunctionNonReturningTableColumn;
        let mut f = test_fn();
        f.has_no_return = true;
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "true");
    }

    #[test]
    fn test_is_function_varargs() {
        let col = IsFunctionVarargsTableColumn;
        let f = test_fn();
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "false");
    }

    #[test]
    fn test_function_info_signature_location() {
        let col = FunctionSignatureTableColumn;
        let f = test_fn();
        let loc = col.get_program_location(&f, &Settings::new(), &test_program(), &test_sp());
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().address.offset, 0x401000);
    }

    #[test]
    fn test_function_purge_negative() {
        let col = FunctionPurgeTableColumn;
        let mut f = test_fn();
        f.stack_purge_size = -5;
        let val = col.get_value(&f, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "INV");
    }
}
