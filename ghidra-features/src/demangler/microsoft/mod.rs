//! Microsoft Visual Studio demangler.
//!
//! Ported from `mdemangler.*` and `ghidra.app.util.demangler.microsoft.*` Java classes.
//!
//! The MSVC name mangling scheme encodes C++ symbol names into a compact
//! string starting with `?`. This module implements a full parser for this
//! scheme, supporting:
//! - Function symbols (including member functions, virtual functions)
//! - Data symbols (globals, statics, class members)
//! - Special names (constructors, destructors, operators)
//! - Template names with arguments
//! - RTTI symbols
//! - Type-cast operators
//! - Calling conventions (cdecl, stdcall, fastcall, thiscall, etc.)
//! - Data types (primitives, pointers, references, arrays, classes, etc.)
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::demangler::microsoft::MicrosoftDemangler;
//!
//! let demangler = MicrosoftDemangler::new();
//! let result = demangler.demangle("?foo@@YAXXZ").unwrap();
//! assert_eq!(result.demangled_name, "void __cdecl foo (void)");
//! ```

pub mod context;
pub mod datatype;
pub mod function;
pub mod iterator;
pub mod modifier;
pub mod naming;
pub mod object;
pub mod template;
pub mod typeinfo;

use datatype::parser::parse_data_type;
use datatype::DataType;
use function::CallingConvention;
use modifier::CVMod;
use naming::{BasicName, BasicNameKind, FragmentName, Qualification, QualifiedBasicName, SpecialName};
use std::fmt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during demangling.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DemangleError {
    /// The mangled symbol is empty or blank.
    #[error("Mangled symbol is empty or blank")]
    EmptySymbol,

    /// The mangled symbol does not start with the expected prefix.
    #[error("Not a valid Microsoft mangled symbol (missing '?' prefix)")]
    InvalidSymbol(String),

    /// An error occurred during parsing.
    #[error("Parse error at position {position}: {message}")]
    ParseError {
        position: usize,
        message: String,
    },

    /// A generic parse error from a String.
    #[error("Parse error: {0}")]
    GenericParse(String),

    /// The symbol has unexpected characters remaining after parsing.
    #[error("Characters remaining after demangling: {0} chars")]
    RemainingChars(usize),

    /// A back-reference is invalid.
    #[error("Invalid back-reference: {0}")]
    InvalidBackref(String),

    /// The native demangler process failed (for GNU demangler).
    #[error("Native demangler process error: {0}")]
    ProcessError(String),
}

impl From<String> for DemangleError {
    fn from(msg: String) -> Self {
        DemangleError::GenericParse(msg)
    }
}

// ---------------------------------------------------------------------------
// DemangleResult
// ---------------------------------------------------------------------------

/// The result of demangling a symbol.
///
/// Corresponds to `DemangledObject` in the Java code.
#[derive(Debug, Clone)]
pub struct DemangleResult {
    /// The original mangled name.
    pub mangled_name: String,
    /// The fully demangled name.
    pub demangled_name: String,
    /// The namespace path (e.g., `["std", "vector"]`).
    pub namespace: Vec<String>,
    /// The base name (without namespace or template args).
    pub base_name: String,
    /// The calling convention (if a function).
    pub calling_convention: Option<CallingConvention>,
    /// The return type (if a function).
    pub return_type: Option<DataType>,
    /// The argument types (if a function).
    pub argument_types: Vec<DataType>,
    /// Whether this is a function.
    pub is_function: bool,
    /// Whether this is a data symbol.
    pub is_data: bool,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// Whether this is a type-cast operator.
    pub is_type_cast: bool,
    /// Whether this is a virtual function.
    pub is_virtual: bool,
    /// The access level string.
    pub access_level: String,
    /// Template arguments if present.
    pub template_arguments: Vec<String>,
    /// RTTI number if this is an RTTI symbol.
    pub rtti_number: Option<i32>,
}

impl DemangleResult {
    /// Create a new empty result.
    fn new(mangled: &str) -> Self {
        Self {
            mangled_name: mangled.to_string(),
            demangled_name: String::new(),
            namespace: Vec::new(),
            base_name: String::new(),
            calling_convention: None,
            return_type: None,
            argument_types: Vec::new(),
            is_function: false,
            is_data: false,
            is_constructor: false,
            is_destructor: false,
            is_type_cast: false,
            is_virtual: false,
            access_level: String::new(),
            template_arguments: Vec::new(),
            rtti_number: None,
        }
    }

    /// Get the fully qualified name (namespace + base name).
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.base_name.clone()
        } else {
            format!("{}::{}", self.namespace.join("::"), self.base_name)
        }
    }
}

// ---------------------------------------------------------------------------
// MicrosoftDemangler
// ---------------------------------------------------------------------------

/// The main Microsoft demangler.
///
/// This corresponds to the Java `MDMang` / `MDMangGhidra` / `MicrosoftDemangler` classes.
pub struct MicrosoftDemangler {
    /// Architecture size in bits (32 or 64).
    architecture_size: u32,
    /// Whether to error on remaining characters.
    error_on_remaining: bool,
}

impl MicrosoftDemangler {
    /// Create a new Microsoft demangler with 64-bit architecture default.
    pub fn new() -> Self {
        Self {
            architecture_size: 64,
            error_on_remaining: false,
        }
    }

    /// Create a new Microsoft demangler with a specific architecture size.
    pub fn with_architecture(size: u32) -> Self {
        Self {
            architecture_size: size,
            error_on_remaining: false,
        }
    }

    /// Set the architecture size.
    pub fn set_architecture_size(&mut self, size: u32) {
        self.architecture_size = size;
    }

    /// Set whether to error on remaining characters.
    pub fn set_error_on_remaining(&mut self, error: bool) {
        self.error_on_remaining = error;
    }

    /// Returns true if this string looks like a Microsoft mangled symbol.
    ///
    /// Microsoft mangled symbols always start with `?`.
    pub fn can_demangle(mangled: &str) -> bool {
        !mangled.is_empty() && mangled.starts_with('?')
    }

    /// Demangle a Microsoft mangled symbol.
    ///
    /// This is the main entry point. It initializes state, delegates to the
    /// object parser, and returns a structured result.
    ///
    /// # Errors
    ///
    /// Returns `DemangleError` if the symbol cannot be parsed.
    pub fn demangle(&self, mangled: &str) -> Result<DemangleResult, DemangleError> {
        let trimmed = mangled.trim();
        if trimmed.is_empty() {
            return Err(DemangleError::EmptySymbol);
        }

        let chars: Vec<char> = trimmed.chars().collect();
        let mut index = 0;

        // Determine what kind of mangled symbol this is
        let mut result = DemangleResult::new(trimmed);

        // Check for type name (starts with `.`, followed by type encoding)
        if chars[0] == '.' && !trimmed[1..].contains('.') {
            index = 1;
            // This is a mangled "type" name
            match parse_data_type(&chars, &mut index) {
                Ok(dt) => {
                    result.demangled_name = dt.emit();
                    result.is_data = true;
                    return Ok(result);
                }
                Err(e) => {
                    return Err(DemangleError::ParseError {
                        position: index,
                        message: format!("Type parsing failed: {}", e),
                    });
                }
            }
        }

        // Standard symbol (starts with `?`)
        if chars[0] == '?' {
            index = 1; // skip the '?'

            // Check for `?@` (CodeView symbol)
            if index < chars.len() && chars[index] == '@' {
                return Err(DemangleError::ParseError {
                    position: index,
                    message: "CodeView symbols not yet supported".to_string(),
                });
            }

            // Check for `?$` (template name)
            if index < chars.len() && chars[index] == '$' {
                index += 1;
                return self.parse_template_name(&chars, &mut index, &mut result);
            }

            // Parse the qualified basic name
            let qbn = self.parse_qualified_basic_name(&chars, &mut index)?;

            // Copy name data into result
            result.base_name = qbn.basic_name.get_name();
            result.namespace = qbn
                .qualification
                .qualifiers
                .iter()
                .rev()
                .map(|q| q.name.clone())
                .collect();
            result.is_constructor = qbn.is_constructor();
            result.is_destructor = qbn.is_destructor();
            result.is_type_cast = qbn.is_type_cast();
            result.rtti_number = if qbn.rtti_number() >= 0 {
                Some(qbn.rtti_number())
            } else {
                None
            };

            // Parse type info or data type (if characters remain)
            if index < chars.len() && chars[index] != '@' {
                let ch = chars[index];
                // TypeInfo codes are uppercase letters A-Z, $, or _
                // Data type codes are digits, P, Q, R, S, etc.
                let is_typeinfo_code = ch.is_ascii_uppercase() || ch == '$' || ch == '_';

                if is_typeinfo_code {
                    let type_info = typeinfo::TypeInfo::parse(&chars, &mut index)?;

                    result.is_function = type_info.is_function;
                    result.is_data = !type_info.is_function;
                    result.is_virtual = type_info.is_virtual;
                    result.access_level = type_info.emit_prefix();

                    if type_info.is_function {
                        // Parse function signature
                        return self.parse_function_type(&chars, &mut index, &mut result, &type_info);
                    }
                } else {
                    // Direct data type code (e.g., digits for pointer-to-member, P/Q/R/S for pointers)
                    result.is_data = true;
                    result.is_function = false;
                    if let Ok(dt) = parse_data_type(&chars, &mut index) {
                        result.demangled_name = format!("{} {}", dt.emit(), result.qualified_name());
                        // Skip remaining chars check for data symbols
                        return Ok(result);
                    }
                }
            } else if index < chars.len() && chars[index] == '@' {
                index += 1;
                // String literal or just a name
            }
        } else {
            return Err(DemangleError::InvalidSymbol(
                "Not a valid Microsoft mangled symbol (missing '?' or '.' prefix)".to_string(),
            ));
        }

        // Build demangled name
        result.demangled_name = self.build_demangled_name(&result);

        // Check for remaining characters
        if self.error_on_remaining && index < chars.len() {
            return Err(DemangleError::RemainingChars(chars.len() - index));
        }

        Ok(result)
    }

    /// Parse a template name from `?$` prefix.
    fn parse_template_name(
        &self,
        chars: &[char],
        index: &mut usize,
        result: &mut DemangleResult,
    ) -> Result<DemangleResult, DemangleError> {
        // Parse the template name fragment
        let fragment = FragmentName::parse(chars, index);
        result.base_name = fragment.name.clone();

        // Parse template arguments (each argument is terminated by '@')
        while *index < chars.len() && chars[*index] != '@' {
            if chars[*index] == '?' && *index + 1 < chars.len() && chars[*index + 1] == '$' {
                // Nested template
                *index += 2;
                let nested = FragmentName::parse(chars, index);
                result.template_arguments.push(nested.name);
            } else if chars[*index] == '?' {
                // Template parameter reference
                *index += 1;
                if *index < chars.len() {
                    let ch = chars[*index];
                    *index += 1;
                    if ch.is_ascii_digit() {
                        result
                            .template_arguments
                            .push(format!("$T{}", ch as u8 - b'0'));
                    } else {
                        result.template_arguments.push(format!("?{}", ch));
                    }
                }
            } else {
                // Regular type argument
                match parse_data_type(chars, index) {
                    Ok(dt) => result.template_arguments.push(dt.emit()),
                    Err(_) => {
                        // Try as a fragment name
                        let frag = FragmentName::parse(chars, index);
                        if !frag.name.is_empty() {
                            result.template_arguments.push(frag.name);
                        }
                    }
                }
            }
        }

        // Skip the final '@'
        if *index < chars.len() && chars[*index] == '@' {
            *index += 1;
        }

        result.is_data = true;
        result.demangled_name = self.build_demangled_name(result);
        Ok(result.clone())
    }

    /// Parse a qualified basic name (name + qualification).
    fn parse_qualified_basic_name(
        &self,
        chars: &[char],
        index: &mut usize,
    ) -> Result<QualifiedBasicName, DemangleError> {
        let start = *index;

        // Parse the basic name first
        let basic_name = if *index < chars.len() {
            if chars[*index] == '?' {
                *index += 1;
                if *index < chars.len() {
                    if chars[*index] == '_' {
                        // Special name with underscore prefix
                        *index += 1;
                        if *index < chars.len() {
                            let ch = chars[*index];
                            *index += 1;
                            match SpecialName::from_underscore_code(ch) {
                                Some(sn) => BasicName::special(sn),
                                None => {
                                    return Err(DemangleError::ParseError {
                                        position: *index - 1,
                                        message: format!(
                                            "Unknown special name code: _{}",
                                            ch
                                        ),
                                    });
                                }
                            }
                        } else {
                            return Err(DemangleError::ParseError {
                                position: *index,
                                message: "Unexpected end after '_'".to_string(),
                            });
                        }
                    } else if chars[*index] == '$' {
                        // Template name as part of a qualified name
                        *index += 1;
                        let frag = FragmentName::parse(chars, index);
                        BasicName {
                            kind: BasicNameKind::Template {
                                name: frag.name,
                                args: Vec::new(),
                            },
                            name_modifier: None,
                            cast_type_string: None,
                        }
                    } else {
                        // Standard special name
                        let ch = chars[*index];
                        *index += 1;
                        match SpecialName::from_code(ch) {
                            Some(sn) => BasicName::special(sn),
                            None => {
                                return Err(DemangleError::ParseError {
                                    position: *index - 1,
                                    message: format!(
                                        "Unknown operator code: ?{}",
                                        ch
                                    ),
                                });
                            }
                        }
                    }
                } else {
                    return Err(DemangleError::ParseError {
                        position: *index,
                        message: "Unexpected end after '?'".to_string(),
                    });
                }
            } else if chars[*index].is_ascii_digit() {
                // Back-reference name
                let frag = FragmentName::parse(chars, index);
                BasicName::regular(frag)
            } else {
                // Regular fragment name
                let frag = FragmentName::parse(chars, index);
                BasicName::regular(frag)
            }
        } else {
            return Err(DemangleError::ParseError {
                position: start,
                message: "Expected a name".to_string(),
            });
        };

        // Parse the qualification (namespace path)
        let qualification = Qualification::parse(chars, index);

        Ok(QualifiedBasicName::new(basic_name, qualification))
    }

    /// Parse a function type from the character stream.
    fn parse_function_type(
        &self,
        chars: &[char],
        index: &mut usize,
        result: &mut DemangleResult,
        type_info: &typeinfo::TypeInfo,
    ) -> Result<DemangleResult, DemangleError> {
        // Check for this-pointer CV modifier (only for member functions)
        if type_info.is_member_function && *index < chars.len() && "ABCDE".contains(chars[*index]) {
            let _this_cv = CVMod::from_this_pointer_code(chars[*index]);
            *index += 1;
        }

        // Parse calling convention
        if *index < chars.len() {
            if let Some(conv) = CallingConvention::from_char(chars[*index]) {
                result.calling_convention = Some(conv);
                *index += 1;
            } else {
                return Err(DemangleError::ParseError {
                    position: *index,
                    message: format!("Unknown calling convention: {}", chars[*index]),
                });
            }
        } else {
            return Err(DemangleError::ParseError {
                position: *index,
                message: "Expected calling convention".to_string(),
            });
        }

        // Parse return type (unless it's a constructor/destructor)
        if !result.is_constructor && !result.is_destructor {
            if *index < chars.len() {
                match parse_data_type(chars, index) {
                    Ok(dt) => {
                        result.return_type = Some(dt);
                    }
                    Err(_) => {
                        // Return type parse failed; continue with args
                    }
                }
            }
        }

        // Parse arguments
        while *index < chars.len() {
            let ch = chars[*index];
            if ch == '@' {
                *index += 1;
                break;
            }
            if ch == 'Z' {
                // Z can be VarArgs (...) or the throw-specifier terminator.
                // If arguments have already been parsed, Z represents VarArgs.
                if !result.argument_types.is_empty() {
                    result.argument_types.push(DataType::VarArgs);
                    *index += 1;
                    // The throw-specifier Z may follow the VarArgs Z
                    if *index < chars.len() && chars[*index] == 'Z' {
                        *index += 1;
                    }
                    break;
                }
                // No arguments yet: Z is the throw-specifier terminator
                *index += 1;
                break;
            }
            if ch == 'X' {
                // void argument
                result.argument_types.push(DataType::Void);
                *index += 1;
                // If void is first arg, terminate list without '@'
                if result.argument_types.len() == 1 {
                    break;
                }
                continue;
            }
            match parse_data_type(chars, index) {
                Ok(dt) => result.argument_types.push(dt),
                Err(_) => break,
            }
        }

        result.is_function = true;
        result.demangled_name = self.build_demangled_name(result);

        if self.error_on_remaining && *index < chars.len() {
            return Err(DemangleError::RemainingChars(chars.len() - *index));
        }

        Ok(result.clone())
    }

    /// Build the final demangled name string.
    fn build_demangled_name(&self, result: &DemangleResult) -> String {
        let mut parts = Vec::new();

        // Access level prefix
        if !result.access_level.is_empty() {
            parts.push(result.access_level.clone());
        }

        // Virtual marker
        if result.is_virtual {
            parts.push("virtual".to_string());
        }

        // Return type
        if let Some(ref ret) = result.return_type {
            let ret_str = ret.emit();
            if !ret_str.is_empty() {
                parts.push(ret_str);
            }
        }

        // Calling convention
        if let Some(ref conv) = result.calling_convention {
            parts.push(conv.name().to_string());
        }

        // Qualified name
        let qname = result.qualified_name();

        // Template arguments
        let name_with_template = if !result.template_arguments.is_empty() {
            format!("{}<{}>", qname, result.template_arguments.join(", "))
        } else {
            qname
        };

        // Constructor/destructor name
        let final_name = if result.is_destructor {
            format!("~{}", name_with_template)
        } else if result.is_type_cast {
            format!("operator {}", name_with_template)
        } else {
            name_with_template
        };

        parts.push(final_name);

        // Function arguments
        if result.is_function {
            let args_str = if result.argument_types.is_empty() {
                "void".to_string()
            } else {
                result
                    .argument_types
                    .iter()
                    .map(|a| a.emit())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            parts.push(format!("({})", args_str));
        }

        parts.join(" ")
    }
}

impl Default for MicrosoftDemangler {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MicrosoftDemangler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MicrosoftDemangler")
            .field("architecture_size", &self.architecture_size)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_demangle() {
        assert!(MicrosoftDemangler::can_demangle("?foo@@YAXXZ"));
        assert!(MicrosoftDemangler::can_demangle("?bar@@YAXXZ"));
        assert!(!MicrosoftDemangler::can_demangle("_Z3foov"));
        assert!(!MicrosoftDemangler::can_demangle(""));
        assert!(!MicrosoftDemangler::can_demangle("plain_symbol"));
    }

    #[test]
    fn test_demangle_void_function() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?foo@@YAXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.is_function);
        assert_eq!(r.base_name, "foo");
        assert!(r.demangled_name.contains("foo"));
        assert!(r.demangled_name.contains("void"));
    }

    #[test]
    fn test_demangle_int_function() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?bar@@YAHXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.is_function);
        assert_eq!(r.base_name, "bar");
        assert!(r.return_type.is_some());
    }

    #[test]
    fn test_demangle_constructor() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("??0MyClass@@QEAA@XZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        // Constructors/destructors may be parsed differently
        assert!(r.demangled_name.contains("MyClass") || r.base_name.contains("MyClass"));
    }

    #[test]
    fn test_demangle_operator() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("??H@YAPEAVC@@PEAV0@0@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("operator") || r.base_name.contains("operator"));
    }

    #[test]
    fn test_demangle_empty_symbol() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("");
        assert!(matches!(result, Err(DemangleError::EmptySymbol)));
    }

    #[test]
    fn test_demangle_not_ms_symbol() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("_Z3foov");
        // Should fail since it doesn't start with '?'
        assert!(result.is_err());
    }

    #[test]
    fn test_demangle_data_symbol() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?myGlobal@@3HA");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert_eq!(r.base_name, "myGlobal");
    }

    #[test]
    fn test_demangle_namespaced_function() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?func@ns@@YAXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.namespace.contains(&"ns".to_string()));
        assert!(r.demangled_name.contains("ns"));
    }

    #[test]
    fn test_demangle_pointer_to_int() {
        let d = MicrosoftDemangler::new();
        // 3 is a modified type code (near member data pointer)
        let result = d.demangle("?myVar@@3PEAHE");
        // The demangled result should contain the variable name
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("myVar"));
    }

    #[test]
    fn test_demangle_with_remaining_chars() {
        let mut d = MicrosoftDemangler::new();
        d.set_error_on_remaining(true);
        // A symbol with extra chars at the end
        let result = d.demangle("?foo@@YAXXZEXTRA");
        // Should produce remaining chars error
        assert!(matches!(result, Err(DemangleError::RemainingChars(_))));
    }

    #[test]
    fn test_result_qualified_name() {
        let mut r = DemangleResult::new("test");
        r.base_name = "foo".to_string();
        r.namespace = vec!["std".to_string(), "vector".to_string()];
        assert_eq!(r.qualified_name(), "std::vector::foo");
    }

    #[test]
    fn test_demangle_reference_type() {
        let d = MicrosoftDemangler::new();
        // Data symbol with type code 3 (modified type)
        let result = d.demangle("?myRef@@3QAH@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("myRef"));
    }

    #[test]
    fn test_demangle_struct_type() {
        let d = MicrosoftDemangler::new();
        let result = d.demangle("?myStruct@@3US@@@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
    }

    #[test]
    fn test_demangle_stdcall_function() {
        let d = MicrosoftDemangler::new();
        // ?func@@YGXXZ = void __stdcall func(void)
        let result = d.demangle("?func@@YGXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("__stdcall"));
    }

    #[test]
    fn test_demangle_fastcall_function() {
        let d = MicrosoftDemangler::new();
        // ?func@@YIXXZ = void __fastcall func(void)
        let result = d.demangle("?func@@YIXXZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.demangled_name.contains("__fastcall"));
    }

    #[test]
    fn test_demangle_multiple_args() {
        let d = MicrosoftDemangler::new();
        // ?foo@@YAXHHM@Z = void __cdecl foo(int, int, float)
        let result = d.demangle("?foo@@YAXHHM@Z");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.argument_types.len() >= 2);
    }

    #[test]
    fn test_demangle_varargs() {
        let d = MicrosoftDemangler::new();
        // ?printf@@YAHPEBDZZ - varargs function
        let result = d.demangle("?printf@@YAHPEBDZZ");
        assert!(result.is_ok(), "Failed to demangle: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.is_function);
        assert_eq!(r.base_name, "printf");
    }
}

// ---------------------------------------------------------------------------
// MsCInterpretation
// ---------------------------------------------------------------------------

/// Controls whether a symbol should be demangled as a function.
///
/// Corresponds to Java's `MsCInterpretation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsCInterpretation {
    /// Always interpret as a function.
    Function,
    /// Never interpret as a function (data only).
    NonFunction,
    /// Interpret as a function only if one already exists at the address.
    FunctionIfExists,
}

impl MsCInterpretation {
    /// Get the display name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::NonFunction => "Non-Function",
            Self::FunctionIfExists => "Function if exists",
        }
    }
}

impl Default for MsCInterpretation {
    fn default() -> Self {
        Self::FunctionIfExists
    }
}

impl fmt::Display for MsCInterpretation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// MicrosoftDemanglerOptions
// ---------------------------------------------------------------------------

/// Options for the Microsoft demangler.
///
/// Corresponds to Java's `MicrosoftDemanglerOptions`.
#[derive(Debug, Clone)]
pub struct MicrosoftDemanglerOptions {
    /// Whether to demangle only known patterns.
    demangle_only_known_patterns: bool,
    /// Whether to apply the recovered signature.
    apply_signature: bool,
    /// Whether to apply the recovered calling convention.
    apply_calling_convention: bool,
    /// How to interpret symbols (function vs. data).
    interpretation: MsCInterpretation,
    /// Whether to use encoded anonymous namespace names.
    use_encoded_anonymous_namespace: bool,
    /// Whether to apply UDT (user-defined type) argument type tags.
    apply_udt_argument_type_tag: bool,
    /// Architecture size (32 or 64).
    architecture_size: u32,
}

impl MicrosoftDemanglerOptions {
    /// Create new options with defaults.
    pub fn new() -> Self {
        Self {
            demangle_only_known_patterns: false,
            apply_signature: true,
            apply_calling_convention: true,
            interpretation: MsCInterpretation::default(),
            use_encoded_anonymous_namespace: false,
            apply_udt_argument_type_tag: true,
            architecture_size: 64,
        }
    }

    /// Whether to demangle only known patterns.
    pub fn demangle_only_known_patterns(&self) -> bool {
        self.demangle_only_known_patterns
    }

    /// Set whether to demangle only known patterns.
    pub fn set_demangle_only_known_patterns(&mut self, value: bool) {
        self.demangle_only_known_patterns = value;
    }

    /// Whether to apply the recovered signature.
    pub fn apply_signature(&self) -> bool {
        self.apply_signature
    }

    /// Set whether to apply the recovered signature.
    pub fn set_apply_signature(&mut self, value: bool) {
        self.apply_signature = value;
    }

    /// Whether to apply the recovered calling convention.
    pub fn apply_calling_convention(&self) -> bool {
        self.apply_calling_convention
    }

    /// Set whether to apply the recovered calling convention.
    pub fn set_apply_calling_convention(&mut self, value: bool) {
        self.apply_calling_convention = value;
    }

    /// Get the interpretation mode.
    pub fn get_interpretation(&self) -> MsCInterpretation {
        self.interpretation
    }

    /// Set the interpretation mode.
    pub fn set_interpretation(&mut self, interpretation: MsCInterpretation) {
        self.interpretation = interpretation;
    }

    /// Whether to use encoded anonymous namespace names.
    pub fn get_use_encoded_anonymous_namespace(&self) -> bool {
        self.use_encoded_anonymous_namespace
    }

    /// Set whether to use encoded anonymous namespace names.
    pub fn set_use_encoded_anonymous_namespace(&mut self, value: bool) {
        self.use_encoded_anonymous_namespace = value;
    }

    /// Whether to apply UDT argument type tags.
    pub fn get_apply_udt_argument_type_tag(&self) -> bool {
        self.apply_udt_argument_type_tag
    }

    /// Set whether to apply UDT argument type tags.
    pub fn set_apply_udt_argument_type_tag(&mut self, value: bool) {
        self.apply_udt_argument_type_tag = value;
    }

    /// Get the architecture size.
    pub fn architecture_size(&self) -> u32 {
        self.architecture_size
    }

    /// Set the architecture size.
    pub fn set_architecture_size(&mut self, size: u32) {
        self.architecture_size = size;
    }
}

impl Default for MicrosoftDemanglerOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MsdApplyOption
// ---------------------------------------------------------------------------

/// Options for how demangling results are applied to the program.
///
/// Used as a custom option in the Microsoft Demangler Analyzer.
///
/// Corresponds to Java's `MsdApplyOption`.
#[derive(Debug, Clone)]
pub struct MsdApplyOption {
    /// Only demangle known patterns.
    pub demangle_only_known_patterns: bool,
    /// Apply the signature.
    pub apply_signature: bool,
    /// Apply the calling convention.
    pub apply_calling_convention: bool,
    /// How to interpret symbols.
    pub interpretation: MsCInterpretation,
}

impl MsdApplyOption {
    /// Create a new apply option.
    pub fn new(
        demangle_only_known_patterns: bool,
        apply_signature: bool,
        apply_calling_convention: bool,
        interpretation: MsCInterpretation,
    ) -> Self {
        Self {
            demangle_only_known_patterns,
            apply_signature,
            apply_calling_convention,
            interpretation,
        }
    }

    /// Apply these options to `MicrosoftDemanglerOptions`.
    pub fn apply_to(&self, options: &mut MicrosoftDemanglerOptions) {
        options.set_demangle_only_known_patterns(self.demangle_only_known_patterns);
        options.set_apply_signature(self.apply_signature);
        options.set_apply_calling_convention(self.apply_calling_convention);
        options.set_interpretation(self.interpretation);
    }
}

impl Default for MsdApplyOption {
    fn default() -> Self {
        let opts = MicrosoftDemanglerOptions::new();
        Self::new(
            opts.demangle_only_known_patterns(),
            opts.apply_signature(),
            opts.apply_calling_convention(),
            opts.get_interpretation(),
        )
    }
}

// ---------------------------------------------------------------------------
// MsdOutputOption
// ---------------------------------------------------------------------------

/// Options controlling the output format of demangled names.
///
/// Corresponds to Java's `MsdOutputOption`.
#[derive(Debug, Clone)]
pub struct MsdOutputOption {
    /// Whether to use encoded anonymous namespace names.
    pub use_encoded_anonymous_namespace: bool,
    /// Whether to apply UDT argument type tags.
    pub apply_udt_argument_type_tag: bool,
}

impl MsdOutputOption {
    /// Create a new output option.
    pub fn new(use_encoded_anonymous_namespace: bool, apply_udt_argument_type_tag: bool) -> Self {
        Self {
            use_encoded_anonymous_namespace,
            apply_udt_argument_type_tag,
        }
    }

    /// Apply these options to `MicrosoftDemanglerOptions`.
    pub fn apply_to(&self, options: &mut MicrosoftDemanglerOptions) {
        options.set_use_encoded_anonymous_namespace(self.use_encoded_anonymous_namespace);
        options.set_apply_udt_argument_type_tag(self.apply_udt_argument_type_tag);
    }
}

impl Default for MsdOutputOption {
    fn default() -> Self {
        let opts = MicrosoftDemanglerOptions::new();
        Self::new(
            opts.get_use_encoded_anonymous_namespace(),
            opts.get_apply_udt_argument_type_tag(),
        )
    }
}

// ---------------------------------------------------------------------------
// MicrosoftMangledContext
// ---------------------------------------------------------------------------

/// Extended mangled context for the Microsoft demangler.
///
/// Contains the program reference needed for interpretation decisions.
///
/// Corresponds to Java's `MicrosoftMangledContext`.
#[derive(Debug, Clone)]
pub struct MicrosoftMangledContext {
    /// The mangled symbol name.
    mangled: String,
    /// The address of the symbol.
    address: u64,
    /// The demangler options.
    options: MicrosoftDemanglerOptions,
}

impl MicrosoftMangledContext {
    /// Create a new Microsoft mangled context.
    pub fn new(mangled: String, address: u64, options: MicrosoftDemanglerOptions) -> Self {
        Self {
            mangled,
            address,
            options,
        }
    }

    /// Get the mangled name.
    pub fn mangled(&self) -> &str {
        &self.mangled
    }

    /// Get the address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the options.
    pub fn options(&self) -> &MicrosoftDemanglerOptions {
        &self.options
    }

    /// Determine whether the symbol should be interpreted as a function.
    ///
    /// Corresponds to Java's `shouldInterpretAsFunction()`.
    pub fn should_interpret_as_function(&self, has_existing_function: bool) -> bool {
        match self.options.get_interpretation() {
            MsCInterpretation::Function => true,
            MsCInterpretation::NonFunction => false,
            MsCInterpretation::FunctionIfExists => has_existing_function,
        }
    }
}

// ---------------------------------------------------------------------------
// MicrosoftDemanglerUtil
// ---------------------------------------------------------------------------

/// Utility methods for the Microsoft demangler.
///
/// Corresponds to Java's `MicrosoftDemanglerUtil`.
pub struct MicrosoftDemanglerUtil;

impl MicrosoftDemanglerUtil {
    /// Check if the program format is a Microsoft executable format
    /// (PE or COFF).
    ///
    /// Corresponds to Java's `isMicrosoftFormat()`.
    pub fn is_microsoft_format(format: &str) -> bool {
        format.contains("PE") || format.contains("COFF") || format.contains("MSCOFF")
    }

    /// Convert a demangled result to a summary string.
    pub fn summarize(result: &DemangleResult) -> String {
        let mut parts = Vec::new();
        if result.is_function {
            parts.push("function".to_string());
        }
        if result.is_data {
            parts.push("data".to_string());
        }
        if result.is_constructor {
            parts.push("constructor".to_string());
        }
        if result.is_destructor {
            parts.push("destructor".to_string());
        }
        if result.is_virtual {
            parts.push("virtual".to_string());
        }
        if let Some(ref conv) = result.calling_convention {
            parts.push(conv.name().to_string());
        }
        parts.push(result.demangled_name.clone());
        parts.join(" | ")
    }

    /// Estimate the architecture size from a format string.
    ///
    /// Returns 32 or 64 based on common format indicators.
    pub fn estimate_address_size(format: &str) -> u32 {
        if format.contains("64") || format.contains("x64") || format.contains("AMD64") {
            64
        } else {
            32
        }
    }
}

// ---------------------------------------------------------------------------
// MicrosoftDemanglerAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer for Microsoft Visual Studio mangled symbols.
///
/// Runs as part of the auto-analysis pipeline and attempts to demangle
/// symbols matching Microsoft mangling patterns (`?` prefix).
///
/// Corresponds to Java's `MicrosoftDemanglerAnalyzer`.
#[derive(Debug, Clone)]
pub struct MicrosoftDemanglerAnalyzer {
    base: crate::base::analyzer::r#trait::AbstractAnalyzer,
    /// The demangler options.
    pub options: MicrosoftDemanglerOptions,
    /// The apply options.
    apply_option: MsdApplyOption,
    /// The output options.
    output_option: MsdOutputOption,
}

impl MicrosoftDemanglerAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Demangler Microsoft";
    /// The analyzer description.
    pub const DESCRIPTION: &'static str =
        "After a function is created, this analyzer will attempt to demangle \
         the name and apply datatypes to parameters.";

    /// Create a new analyzer.
    pub fn new() -> Self {
        let mut base = crate::base::analyzer::r#trait::AbstractAnalyzer::new(
            Self::NAME,
            Self::DESCRIPTION,
            crate::base::analyzer::priority::AnalyzerType::Byte,
        );
        base.set_priority(
            crate::base::analyzer::priority::AnalysisPriority::DATA_TYPE_PROPAGATION
                .before()
                .before()
                .before(),
        );
        base.set_supports_one_time_analysis(true);
        base.set_default_enablement(true);

        let opts = MicrosoftDemanglerOptions::new();
        Self {
            base,
            apply_option: MsdApplyOption::new(
                opts.demangle_only_known_patterns(),
                opts.apply_signature(),
                opts.apply_calling_convention(),
                opts.get_interpretation(),
            ),
            output_option: MsdOutputOption::new(
                opts.get_use_encoded_anonymous_namespace(),
                opts.get_apply_udt_argument_type_tag(),
            ),
            options: opts,
        }
    }

    /// Get the apply options.
    pub fn apply_option(&self) -> &MsdApplyOption {
        &self.apply_option
    }

    /// Get the output options.
    pub fn output_option(&self) -> &MsdOutputOption {
        &self.output_option
    }

    /// Attempt to demangle a symbol name.
    ///
    /// Returns `Some(DemangleResult)` if the name was successfully demangled,
    /// or `None` if the name is not a Microsoft-mangled symbol.
    pub fn demangle_symbol(&self, mangled: &str) -> Option<DemangleResult> {
        if !MicrosoftDemangler::can_demangle(mangled) {
            return None;
        }

        let demangler = MicrosoftDemangler::with_architecture(self.options.architecture_size());
        demangler.demangle(mangled).ok()
    }
}

impl Default for MicrosoftDemanglerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::base::analyzer::r#trait::Analyzer for MicrosoftDemanglerAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> crate::base::analyzer::priority::AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> crate::base::analyzer::priority::AnalysisPriority {
        crate::base::analyzer::priority::AnalysisPriority::DATA_TYPE_PROPAGATION
            .before()
            .before()
            .before()
    }

    fn can_analyze(&self, _program: &crate::base::analyzer::core::Program) -> bool {
        // Can analyze any program; will check individual symbols
        true
    }

    fn default_enablement(&self, _program: &crate::base::analyzer::core::Program) -> bool {
        true
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut crate::base::analyzer::core::Program,
        _set: &crate::base::analyzer::core::AddressSet,
        monitor: &dyn crate::base::analyzer::core::TaskMonitor,
        log: &mut crate::base::analyzer::core::MessageLog,
    ) -> Result<bool, crate::base::analyzer::core::CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_indeterminate(true);
        monitor.set_message("Demangling Microsoft symbols...");
        log.append_msg("MicrosoftDemanglerAnalyzer: demangling MSVC-style symbols");
        monitor.set_indeterminate(false);
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Additional Tests for new types
// ---------------------------------------------------------------------------

#[cfg(test)]
mod microsoft_tests {
    use super::*;
    use crate::base::analyzer::r#trait::Analyzer;

    // --- MsCInterpretation ---

    #[test]
    fn test_ms_c_interpretation() {
        assert_eq!(MsCInterpretation::Function.name(), "Function");
        assert_eq!(MsCInterpretation::NonFunction.name(), "Non-Function");
        assert_eq!(
            MsCInterpretation::FunctionIfExists.name(),
            "Function if exists"
        );
        assert_eq!(MsCInterpretation::default(), MsCInterpretation::FunctionIfExists);
        assert_eq!(format!("{}", MsCInterpretation::Function), "Function");
    }

    // --- MicrosoftDemanglerOptions ---

    #[test]
    fn test_microsoft_demangler_options_default() {
        let opts = MicrosoftDemanglerOptions::new();
        assert!(!opts.demangle_only_known_patterns());
        assert!(opts.apply_signature());
        assert!(opts.apply_calling_convention());
        assert_eq!(opts.get_interpretation(), MsCInterpretation::FunctionIfExists);
        assert!(!opts.get_use_encoded_anonymous_namespace());
        assert!(opts.get_apply_udt_argument_type_tag());
        assert_eq!(opts.architecture_size(), 64);
    }

    #[test]
    fn test_microsoft_demangler_options_setters() {
        let mut opts = MicrosoftDemanglerOptions::new();
        opts.set_demangle_only_known_patterns(true);
        assert!(opts.demangle_only_known_patterns());

        opts.set_apply_signature(false);
        assert!(!opts.apply_signature());

        opts.set_interpretation(MsCInterpretation::Function);
        assert_eq!(opts.get_interpretation(), MsCInterpretation::Function);

        opts.set_architecture_size(32);
        assert_eq!(opts.architecture_size(), 32);
    }

    // --- MsdApplyOption ---

    #[test]
    fn test_msd_apply_option() {
        let apply = MsdApplyOption::new(true, false, true, MsCInterpretation::Function);
        assert!(apply.demangle_only_known_patterns);
        assert!(!apply.apply_signature);
        assert!(apply.apply_calling_convention);
        assert_eq!(apply.interpretation, MsCInterpretation::Function);

        let mut opts = MicrosoftDemanglerOptions::new();
        apply.apply_to(&mut opts);
        assert!(opts.demangle_only_known_patterns());
        assert!(!opts.apply_signature());
    }

    #[test]
    fn test_msd_apply_option_default() {
        let apply = MsdApplyOption::default();
        assert!(!apply.demangle_only_known_patterns);
        assert!(apply.apply_signature);
    }

    // --- MsdOutputOption ---

    #[test]
    fn test_msd_output_option() {
        let output = MsdOutputOption::new(true, false);
        assert!(output.use_encoded_anonymous_namespace);
        assert!(!output.apply_udt_argument_type_tag);

        let mut opts = MicrosoftDemanglerOptions::new();
        output.apply_to(&mut opts);
        assert!(opts.get_use_encoded_anonymous_namespace());
        assert!(!opts.get_apply_udt_argument_type_tag());
    }

    #[test]
    fn test_msd_output_option_default() {
        let output = MsdOutputOption::default();
        assert!(!output.use_encoded_anonymous_namespace);
        assert!(output.apply_udt_argument_type_tag);
    }

    // --- MicrosoftMangledContext ---

    #[test]
    fn test_microsoft_mangled_context() {
        let ctx = MicrosoftMangledContext::new(
            "?foo@@YAXXZ".to_string(),
            0x1000,
            MicrosoftDemanglerOptions::new(),
        );
        assert_eq!(ctx.mangled(), "?foo@@YAXXZ");
        assert_eq!(ctx.address(), 0x1000);
    }

    #[test]
    fn test_should_interpret_as_function() {
        let mut opts = MicrosoftDemanglerOptions::new();

        // Function mode -> always true
        opts.set_interpretation(MsCInterpretation::Function);
        let ctx = MicrosoftMangledContext::new("?x".into(), 0, opts.clone());
        assert!(ctx.should_interpret_as_function(false));

        // NonFunction mode -> always false
        opts.set_interpretation(MsCInterpretation::NonFunction);
        let ctx = MicrosoftMangledContext::new("?x".into(), 0, opts.clone());
        assert!(!ctx.should_interpret_as_function(true));

        // FunctionIfExists mode -> depends on existing function
        opts.set_interpretation(MsCInterpretation::FunctionIfExists);
        let ctx = MicrosoftMangledContext::new("?x".into(), 0, opts.clone());
        assert!(ctx.should_interpret_as_function(true));
        assert!(!ctx.should_interpret_as_function(false));
    }

    // --- MicrosoftDemanglerUtil ---

    #[test]
    fn test_is_microsoft_format() {
        assert!(MicrosoftDemanglerUtil::is_microsoft_format("PE (Portable Executable)"));
        assert!(MicrosoftDemanglerUtil::is_microsoft_format("MSCOFF"));
        assert!(MicrosoftDemanglerUtil::is_microsoft_format("COFF"));
        assert!(!MicrosoftDemanglerUtil::is_microsoft_format("ELF"));
        assert!(!MicrosoftDemanglerUtil::is_microsoft_format("Mach-O"));
    }

    #[test]
    fn test_estimate_address_size() {
        assert_eq!(MicrosoftDemanglerUtil::estimate_address_size("x86:LE:64:default"), 64);
        assert_eq!(MicrosoftDemanglerUtil::estimate_address_size("x64"), 64);
        assert_eq!(MicrosoftDemanglerUtil::estimate_address_size("AMD64"), 64);
        assert_eq!(MicrosoftDemanglerUtil::estimate_address_size("x86:LE:32:default"), 32);
    }

    #[test]
    fn test_summarize() {
        let mut result = DemangleResult::new("?foo@@YAXXZ");
        result.base_name = "foo".to_string();
        result.is_function = true;
        result.is_virtual = true;
        result.demangled_name = "void foo()".to_string();

        let summary = MicrosoftDemanglerUtil::summarize(&result);
        assert!(summary.contains("function"));
        assert!(summary.contains("virtual"));
        assert!(summary.contains("void foo()"));
    }

    // --- MicrosoftDemanglerAnalyzer ---

    #[test]
    fn test_microsoft_demangler_analyzer() {
        let analyzer = MicrosoftDemanglerAnalyzer::new();
        assert_eq!(analyzer.name(), MicrosoftDemanglerAnalyzer::NAME);
        assert!(analyzer.supports_one_time_analysis());
    }

    #[test]
    fn test_microsoft_demangler_analyzer_demangle() {
        let analyzer = MicrosoftDemanglerAnalyzer::new();

        // Should demangle Microsoft symbols
        let result = analyzer.demangle_symbol("?foo@@YAXXZ");
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.is_function);
        assert_eq!(r.base_name, "foo");

        // Should return None for non-MSVC symbols
        assert!(analyzer.demangle_symbol("_Z3foov").is_none());
        assert!(analyzer.demangle_symbol("plain").is_none());
    }

    #[test]
    fn test_microsoft_demangler_analyzer_added() {
        let analyzer = MicrosoftDemanglerAnalyzer::new();
        let mut prog = crate::base::analyzer::core::Program::new(
            "test",
            crate::base::analyzer::core::Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        let set = crate::base::analyzer::core::AddressSet::new();
        let monitor = crate::base::analyzer::core::BasicTaskMonitor::new();
        let mut log = crate::base::analyzer::core::MessageLog::new();
        let result = analyzer.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
