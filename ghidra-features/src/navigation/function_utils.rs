//! Function signature parsing utilities -- ported from
//! `ghidra.app.plugin.core.navigation.FunctionUtils`.
//!
//! Provides helpers for extracting field location information from
//! function signatures, including return type, function name, calling
//! convention, and parameter string positions within the signature
//! string.
//!
//! These utilities are used by the code browser's "find field"
//! infrastructure and by the listing field navigation system.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FieldStringInfo
// ---------------------------------------------------------------------------

/// Describes the location of a substring within a function signature.
///
/// Ported from `ghidra.app.util.viewer.field.FieldStringInfo`.
///
/// When the code browser renders a function signature, each field
/// (return type, name, parameters) occupies a substring.  This struct
/// records one such substring's text, field name, and character offset
/// within the full signature string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldStringInfo {
    /// The full function signature string.
    pub full_string: String,
    /// The substring identifying this field (e.g., "int", "myFunc").
    pub field_string: String,
    /// The character offset of `field_string` within `full_string`.
    /// A negative value means the field was not found.
    pub start_index: i32,
}

impl FieldStringInfo {
    /// Create a new field string info.
    pub fn new(
        full_string: impl Into<String>,
        field_string: impl Into<String>,
        start_index: i32,
    ) -> Self {
        Self {
            full_string: full_string.into(),
            field_string: field_string.into(),
            start_index,
        }
    }

    /// Whether this field was successfully located in the signature.
    pub fn is_valid(&self) -> bool {
        self.start_index >= 0
    }

    /// The end offset of this field within the signature (exclusive).
    pub fn end_index(&self) -> i32 {
        self.start_index + self.field_string.len() as i32
    }
}

// ---------------------------------------------------------------------------
// Function signature model
// ---------------------------------------------------------------------------

/// Minimal model of a function signature for field-position extraction.
///
/// This mirrors the Ghidra `Function` interface fields consumed by
/// `FunctionUtils`.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// The return type name (e.g., "int", "void *").
    pub return_type: String,
    /// The function name.
    pub name: String,
    /// The calling convention name (e.g., "__stdcall"), or `None` for
    /// the default convention.
    pub calling_convention: Option<String>,
    /// Parameters: each entry is `(data_type_name, parameter_name)`.
    pub parameters: Vec<(String, String)>,
    /// The full rendered signature string.
    pub signature_string: String,
}

impl FunctionSignature {
    /// Create a new function signature model.
    pub fn new(
        return_type: impl Into<String>,
        name: impl Into<String>,
        calling_convention: Option<String>,
        parameters: Vec<(String, String)>,
        signature_string: impl Into<String>,
    ) -> Self {
        Self {
            return_type: return_type.into(),
            name: name.into(),
            calling_convention,
            parameters,
            signature_string: signature_string.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionUtils
// ---------------------------------------------------------------------------

/// Utility methods for extracting field string information from function
/// signatures.
///
/// Ported from `ghidra.app.plugin.core.navigation.FunctionUtils`.
///
/// Each method returns a [`FieldStringInfo`] (or array thereof) that
/// locates a specific field (return type, name, parameters) within the
/// rendered function signature string.
pub struct FunctionUtils;

impl FunctionUtils {
    /// Returns a [`FieldStringInfo`] for the function's return type.
    ///
    /// Ported from `FunctionUtils.getFunctionReturnTypeStringInfo()`.
    ///
    /// The return type name is always at offset 0 in the signature
    /// string (by convention, the signature starts with the return type).
    pub fn get_return_type_string_info(sig: &FunctionSignature) -> FieldStringInfo {
        FieldStringInfo::new(&sig.signature_string, &sig.return_type, 0)
    }

    /// Returns a [`FieldStringInfo`] for the function's name.
    ///
    /// Ported from `FunctionUtils.getFunctionNameStringInfo()`.
    ///
    /// Searches for the function name in the signature string.  If the
    /// fully qualified name is not found, falls back to the unqualified
    /// name.
    pub fn get_name_string_info(sig: &FunctionSignature) -> FieldStringInfo {
        let signature = &sig.signature_string;

        // Try the full (possibly qualified) name first.
        if let Some(offset) = signature.find(&sig.name) {
            return FieldStringInfo::new(signature, &sig.name, offset as i32);
        }

        // Fall back to the short name.
        let short = sig.name.rsplit("::").next().unwrap_or(&sig.name);
        let offset = signature.find(short).map(|o| o as i32).unwrap_or(-1);
        FieldStringInfo::new(signature, short, offset)
    }

    /// Returns the character offset of the calling convention name in
    /// the signature, or 0 if no calling convention is present.
    ///
    /// Ported from `FunctionUtils.getCallingConventionSignatureOffset()`.
    pub fn get_calling_convention_offset(sig: &FunctionSignature) -> usize {
        sig.calling_convention
            .as_ref()
            .map(|cc| {
                if cc == "unknown" || cc.is_empty() {
                    0
                } else {
                    // The convention name plus a trailing space.
                    cc.len() + 1
                }
            })
            .unwrap_or(0)
    }

    /// Returns [`FieldStringInfo`]s for each parameter in the function
    /// signature.
    ///
    /// Ported from `FunctionUtils.getFunctionParameterStringInfos()`.
    ///
    /// Each parameter occupies a substring of the form
    /// `"data_type_name parameter_name"` within the parenthesized
    /// parameter list.  The search begins after the opening `(` and
    /// advances through each parameter sequentially.
    pub fn get_parameter_string_infos(sig: &FunctionSignature) -> Vec<FieldStringInfo> {
        let signature = &sig.signature_string;
        let mut result = Vec::new();

        // Find the start of the parameter list.
        let paren_pos = match signature.find('(') {
            Some(p) => p + 1,
            None => return result,
        };
        let mut search_start = paren_pos;

        for (dt_name, param_name) in &sig.parameters {
            // Locate the data type name.
            if let Some(dt_pos) = signature[search_start..].find(dt_name.as_str()) {
                let dt_abs = search_start + dt_pos;
                // The field string is "data_type_name parameter_name".
                let combined = format!("{} {}", dt_name, param_name);
                result.push(FieldStringInfo::new(signature, &combined, dt_abs as i32));

                // Advance past the parameter name.
                if let Some(pn_pos) = signature[dt_abs..].find(param_name.as_str()) {
                    search_start = dt_abs + pn_pos + param_name.len();
                } else {
                    search_start = dt_abs + dt_name.len();
                }
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sig() -> FunctionSignature {
        FunctionSignature::new(
            "int",
            "myFunction",
            Some("__cdecl".into()),
            vec![
                ("char *".into(), "buffer".into()),
                ("int".into(), "size".into()),
            ],
            "int __cdecl myFunction(char * buffer, int size)",
        )
    }

    #[test]
    fn test_field_string_info_valid() {
        let info = FieldStringInfo::new("int foo()", "int", 0);
        assert!(info.is_valid());
        assert_eq!(info.end_index(), 3);
    }

    #[test]
    fn test_field_string_info_invalid() {
        let info = FieldStringInfo::new("int foo()", "long", -1);
        assert!(!info.is_valid());
    }

    #[test]
    fn test_get_return_type() {
        let sig = sample_sig();
        let info = FunctionUtils::get_return_type_string_info(&sig);
        assert_eq!(info.field_string, "int");
        assert_eq!(info.start_index, 0);
    }

    #[test]
    fn test_get_name_simple() {
        let sig = sample_sig();
        let info = FunctionUtils::get_name_string_info(&sig);
        assert_eq!(info.field_string, "myFunction");
        assert!(info.start_index > 0);
    }

    #[test]
    fn test_get_name_qualified() {
        let sig = FunctionSignature::new(
            "void",
            "NS::Class::method",
            None,
            vec![],
            "void NS::Class::method()",
        );
        let info = FunctionUtils::get_name_string_info(&sig);
        assert_eq!(info.field_string, "NS::Class::method");
        assert!(info.start_index > 0);
    }

    #[test]
    fn test_get_name_fallback_short() {
        // If the qualified name isn't in the signature, fall back to the
        // short name.
        let sig = FunctionSignature::new(
            "void",
            "NS::method",
            None,
            vec![],
            "void method()",
        );
        let info = FunctionUtils::get_name_string_info(&sig);
        assert_eq!(info.field_string, "method");
        assert!(info.start_index > 0);
    }

    #[test]
    fn test_get_calling_convention_offset() {
        let sig = sample_sig();
        // "__cdecl" is 7 chars + 1 space = 8
        assert_eq!(FunctionUtils::get_calling_convention_offset(&sig), 8);
    }

    #[test]
    fn test_get_calling_convention_offset_unknown() {
        let sig = FunctionSignature::new(
            "void", "foo", Some("unknown".into()), vec![], "void foo()",
        );
        assert_eq!(FunctionUtils::get_calling_convention_offset(&sig), 0);
    }

    #[test]
    fn test_get_calling_convention_offset_none() {
        let sig = FunctionSignature::new(
            "void", "foo", None, vec![], "void foo()",
        );
        assert_eq!(FunctionUtils::get_calling_convention_offset(&sig), 0);
    }

    #[test]
    fn test_get_parameter_string_infos() {
        let sig = sample_sig();
        let infos = FunctionUtils::get_parameter_string_infos(&sig);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].field_string, "char * buffer");
        assert!(infos[0].start_index > 0);
        assert_eq!(infos[1].field_string, "int size");
        assert!(infos[1].start_index > infos[0].start_index);
    }

    #[test]
    fn test_get_parameter_string_infos_empty() {
        let sig = FunctionSignature::new(
            "void", "foo", None, vec![], "void foo()",
        );
        let infos = FunctionUtils::get_parameter_string_infos(&sig);
        assert!(infos.is_empty());
    }

    #[test]
    fn test_get_parameter_string_infos_no_paren() {
        let sig = FunctionSignature::new(
            "void", "foo", None, vec![("int".into(), "x".into())], "void foo -- missing parens",
        );
        let infos = FunctionUtils::get_parameter_string_infos(&sig);
        assert!(infos.is_empty());
    }
}
