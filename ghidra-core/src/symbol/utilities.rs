//! Symbol name utilities for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.symbol.SymbolUtilities`.
//!
//! Provides static utility methods for working with symbol names: validation,
//! default name generation, dynamic symbol detection, and name cleaning.

use crate::addr::Address;

/// Maximum allowed length of a symbol name.
///
/// Corresponds to `SymbolUtilities.MAX_SYMBOL_NAME_LENGTH` in Java.
pub const MAX_SYMBOL_NAME_LENGTH: usize = 2000;

/// Minimum number of hex digits in a dynamic label address suffix.
///
/// Corresponds to `SymbolUtilities.MIN_LABEL_ADDRESS_DIGITS` in Java.
pub const MIN_LABEL_ADDRESS_DIGITS: usize = 4;

/// The standard prefix for denoting ordinal values of a symbol.
pub const ORDINAL_PREFIX: &str = "Ordinal_";

/// Default prefix for a function.
pub const DEFAULT_FUNCTION_PREFIX: &str = "FUN_";

/// Default prefix for a subroutine.
pub const DEFAULT_SUBROUTINE_PREFIX: &str = "SUB_";

/// Default prefix for a reference that has flow but is not a call.
pub const DEFAULT_SYMBOL_PREFIX: &str = "LAB_";

/// Default prefix for a data reference.
pub const DEFAULT_DATA_PREFIX: &str = "DAT_";

/// Default prefix for a reference that is unknown.
pub const DEFAULT_UNKNOWN_PREFIX: &str = "UNK_";

/// Default prefix for an entry point.
pub const DEFAULT_EXTERNAL_ENTRY_PREFIX: &str = "EXT_";

/// Default prefix for a reference that is offcut.
pub const DEFAULT_INTERNAL_REF_PREFIX: &str = "OFF_";

/// Unknown reference level.
pub const UNK_LEVEL: usize = 0;

/// Data reference level.
pub const DAT_LEVEL: usize = 1;

/// Label reference level.
pub const LAB_LEVEL: usize = 2;

/// Subroutine reference level.
pub const SUB_LEVEL: usize = 3;

/// External entry reference level.
pub const EXT_LEVEL: usize = 5;

/// Function reference level.
pub const FUN_LEVEL: usize = 6;

/// All dynamic prefix strings indexed by reference level.
const DYNAMIC_PREFIX_ARRAY: [&str; 7] = [
    DEFAULT_UNKNOWN_PREFIX,   // UNK_LEVEL = 0
    DEFAULT_DATA_PREFIX,      // DAT_LEVEL = 1
    DEFAULT_SYMBOL_PREFIX,    // LAB_LEVEL = 2
    DEFAULT_SUBROUTINE_PREFIX, // SUB_LEVEL = 3
    DEFAULT_UNKNOWN_PREFIX,   // 4 (unused)
    DEFAULT_EXTERNAL_ENTRY_PREFIX, // EXT_LEVEL = 5
    DEFAULT_FUNCTION_PREFIX,  // FUN_LEVEL = 6
];

/// Invalid characters for a symbol name (space is the only one by default).
const INVALID_CHARS: &[char] = &[' '];

/// The underscore separator.
#[allow(dead_code)]
const UNDERSCORE: &str = "_";

/// The plus separator for offcut references.
#[allow(dead_code)]
const PLUS: &str = "+";

// ============================================================================
// Validation
// ============================================================================

/// Check for invalid characters (space or unprintable ASCII below 0x20) in labels.
///
/// Corresponds to `SymbolUtilities.containsInvalidChars(String)` in Java.
pub fn contains_invalid_chars(s: &str) -> bool {
    s.chars().any(|c| is_invalid_char(c))
}

/// Returns true if the given character is not valid for use in a symbol name.
///
/// Corresponds to `SymbolUtilities.isInvalidChar(char)` in Java.
pub fn is_invalid_char(c: char) -> bool {
    c < ' ' || INVALID_CHARS.contains(&c)
}

/// Validate a symbol name: cannot be empty, cannot exceed max length, cannot
/// contain invalid characters.
///
/// Returns `Ok(())` if valid, or an error description.
///
/// Corresponds to `SymbolUtilities.validateName(String)` in Java.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Symbol name can't be empty string".to_string());
    }
    if name.len() > MAX_SYMBOL_NAME_LENGTH {
        return Err(format!(
            "Symbol name exceeds maximum length of {}, length={}",
            MAX_SYMBOL_NAME_LENGTH,
            name.len()
        ));
    }
    if contains_invalid_chars(name) {
        return Err(format!("Symbol name contains invalid characters: {}", name));
    }
    Ok(())
}

/// Removes from the given string any invalid characters or replaces them with
/// underscores.
///
/// Corresponds to `SymbolUtilities.replaceInvalidChars(String, boolean)` in Java.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(replace_invalid_chars("a:b*c", true), "a_b_c");
/// assert_eq!(replace_invalid_chars("a:b*c", false), "abc");
/// ```
pub fn replace_invalid_chars(s: &str, replace_with_underscore: bool) -> String {
    s.chars()
        .map(|c| {
            if is_invalid_char(c) {
                if replace_with_underscore {
                    '_'
                } else {
                    '\0' // will be filtered
                }
            } else {
                c
            }
        })
        .filter(|c| *c != '\0')
        .collect()
}

// ============================================================================
// Default name generation
// ============================================================================

/// Generates a default function name for a given address.
///
/// Corresponds to `SymbolUtilities.getDefaultFunctionName(Address)` in Java.
///
/// # Examples
///
/// ```ignore
/// let addr = Address::new(0x401000);
/// assert_eq!(get_default_function_name(&addr), "FUN_00401000");
/// ```
pub fn get_default_function_name(addr: &Address) -> String {
    format!("{}{}", DEFAULT_FUNCTION_PREFIX, get_address_string(addr))
}

/// Generates a default external name for an external function.
///
/// Corresponds to `SymbolUtilities.getDefaultExternalFunctionName(Address)` in Java.
pub fn get_default_external_function_name(addr: &Address) -> String {
    format!(
        "{}{}{}",
        DEFAULT_EXTERNAL_ENTRY_PREFIX,
        DEFAULT_FUNCTION_PREFIX,
        get_address_string(addr)
    )
}

/// Generates a default external name for a given external data/code location.
///
/// Corresponds to `SymbolUtilities.getDefaultExternalName(Address, DataType)` in Java.
pub fn get_default_external_name(addr: &Address, prefix: Option<&str>) -> String {
    match prefix {
        Some(p) => format!(
            "{}{}_{}",
            DEFAULT_EXTERNAL_ENTRY_PREFIX,
            p,
            get_address_string(addr)
        ),
        None => format!(
            "{}{}",
            DEFAULT_EXTERNAL_ENTRY_PREFIX,
            get_address_string(addr)
        ),
    }
}

/// Create a dynamic label name for an offcut reference.
///
/// Corresponds to `SymbolUtilities.getDynamicOffcutName(Address)` in Java.
pub fn get_dynamic_offcut_name(addr: &Address) -> String {
    format!(
        "{}{}",
        DEFAULT_INTERNAL_REF_PREFIX,
        get_address_string(addr)
    )
}

/// Create a name for a dynamic symbol with a 3-letter prefix based upon
/// reference level and an address.
///
/// Corresponds to `SymbolUtilities.getDynamicName(int, Address)` in Java.
///
/// Acceptable reference levels: [`UNK_LEVEL`], [`DAT_LEVEL`], [`LAB_LEVEL`],
/// [`SUB_LEVEL`], [`EXT_LEVEL`], [`FUN_LEVEL`].
pub fn get_dynamic_name(reference_level: usize, addr: &Address) -> String {
    let prefix = if reference_level < DYNAMIC_PREFIX_ARRAY.len() {
        DYNAMIC_PREFIX_ARRAY[reference_level]
    } else {
        DEFAULT_UNKNOWN_PREFIX
    };
    format!("{}{}", prefix, get_address_string(addr))
}

/// Returns the address string with colons replaced by underscores.
///
/// Corresponds to `SymbolUtilities.getAddressString(Address)` in Java.
pub fn get_address_string(addr: &Address) -> String {
    format!("{:08x}", addr.offset).replace(':', "_")
}

/// Returns a string representing an address offset.
///
/// If the offset is less than 10, it doesn't add a prefix; otherwise the
/// difference is shown in hex with the "0x" prefix.
///
/// Corresponds to `SymbolUtilities.getDiffString(long)` in Java.
pub fn get_diff_string(diff: i64) -> String {
    if diff < 10 {
        format!("{}", diff)
    } else {
        format!("0x{:x}", diff)
    }
}

/// Get the default parameter name for the given ordinal.
///
/// Corresponds to `SymbolUtilities.getDefaultParamName(int)` in Java.
pub fn get_default_param_name(ordinal: usize) -> String {
    format!("param_{}", ordinal + 1)
}

/// Returns true if the given name is a default parameter name.
///
/// Corresponds to `SymbolUtilities.isDefaultParameterName(String)` in Java.
pub fn is_default_parameter_name(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    if let Some(rest) = name.strip_prefix("param_") {
        rest.parse::<u32>().is_ok()
    } else {
        false
    }
}

// ============================================================================
// Dynamic symbol detection
// ============================================================================

/// Returns true if the given name starts with a possible default symbol prefix.
///
/// Corresponds to `SymbolUtilities.startsWithDefaultDynamicPrefix(String)` in Java.
pub fn starts_with_default_dynamic_prefix(name: &str) -> bool {
    DYNAMIC_PREFIX_ARRAY.iter().any(|prefix| name.starts_with(prefix))
}

/// Tests if the given name is a possible dynamic symbol name.
///
/// Corresponds to `SymbolUtilities.isDynamicSymbolPattern(String, boolean)` in Java.
///
/// This method should be used carefully since it will return true for any name
/// which starts with a known dynamic label prefix or ends with an underscore
/// followed by a valid hex value.
pub fn is_dynamic_symbol_pattern(name: &str, case_sensitive: bool) -> bool {
    let check_name = if case_sensitive {
        name.to_string()
    } else {
        name.to_uppercase()
    };

    if starts_with_default_dynamic_prefix(&check_name) {
        return true;
    }

    // Check for pattern: <prefix>_<hex_address>
    let last_underscore = check_name.rfind('_');
    match last_underscore {
        Some(idx) if idx > 0 => {
            let suffix = &check_name[idx + 1..];
            suffix.len() >= 3 && suffix.len() <= 16 && is_hex_digits(suffix)
        }
        _ => false,
    }
}

/// Returns true if the specified name is reserved as a default external name.
///
/// Corresponds to `SymbolUtilities.isReservedExternalDefaultName(String, AddressFactory)` in Java.
pub fn is_reserved_external_default_name(name: &str) -> bool {
    name.starts_with(DEFAULT_EXTERNAL_ENTRY_PREFIX)
}

/// Returns true if the given name could match a default dynamic label.
///
/// Corresponds to `SymbolUtilities.isReservedDynamicLabelName(String, AddressFactory)` in Java.
pub fn is_reserved_dynamic_label_name(name: &str) -> bool {
    let prefix = find_dynamic_prefix(name);
    match prefix {
        Some(p) => {
            let addr_part = &name[p.len()..];
            addr_part.len() >= MIN_LABEL_ADDRESS_DIGITS && is_hex_digits(addr_part)
        }
        None => false,
    }
}

/// Returns true if the given name is a possible default parameter name or local
/// variable name.
///
/// Corresponds to `SymbolUtilities.isPossibleDefaultLocalOrParamName(String)` in Java.
pub fn is_possible_default_local_or_param_name(name: &str) -> bool {
    if is_default_parameter_name(name) {
        return true;
    }
    name.starts_with("Var_") || name.starts_with("local_")
}

/// Returns true if the given name could be a default external location name.
///
/// Corresponds to `SymbolUtilities.isPossibleDefaultExternalName(String)` in Java.
pub fn is_possible_default_external_name(name: &str) -> bool {
    name.starts_with(DEFAULT_EXTERNAL_ENTRY_PREFIX)
}

/// Returns the ordinal value embedded in a symbol name.
///
/// Corresponds to `SymbolUtilities.getOrdinalValue(String)` in Java.
pub fn get_ordinal_value(symbol_name: &str) -> i32 {
    if let Some(rest) = symbol_name.strip_prefix(ORDINAL_PREFIX) {
        rest.parse().unwrap_or(-1)
    } else {
        -1
    }
}

/// Creates the standard symbol name with address appended using "@" separator.
///
/// Corresponds to `SymbolUtilities.getAddressAppendedName(String, Address)` in Java.
pub fn get_address_appended_name(name: &str, addr: &Address) -> String {
    format!("{}@{}", name, get_address_string(addr))
}

/// Gets the base symbol name by stripping any appended address suffix.
///
/// Corresponds to `SymbolUtilities.getCleanSymbolName(String, Address)` in Java.
pub fn get_clean_symbol_name(symbol_name: &str, addr: &Address) -> String {
    // Try "@" separator first
    if let Some(idx) = symbol_name.rfind('@') {
        let base = &symbol_name[..idx];
        if symbol_name == get_address_appended_name(base, addr) {
            return base.to_string();
        }
    }

    // Try "_" separator
    if let Some(idx) = symbol_name.rfind('_') {
        let base = &symbol_name[..idx];
        let expected = format!("{}_{}", base, get_address_string(addr));
        if symbol_name == expected {
            return base.to_string();
        }
    }

    symbol_name.to_string()
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Find the dynamic prefix that matches the start of the given name.
fn find_dynamic_prefix(name: &str) -> Option<&'static str> {
    DYNAMIC_PREFIX_ARRAY
        .iter()
        .find(|prefix| name.starts_with(*prefix))
        .copied()
}

/// Returns true if all characters in the string are hex digits.
fn is_hex_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_invalid_chars() {
        assert!(!contains_invalid_chars("hello"));
        assert!(contains_invalid_chars("hello world"));
        assert!(contains_invalid_chars("hello\tworld"));
    }

    #[test]
    fn test_is_invalid_char() {
        assert!(!is_invalid_char('a'));
        assert!(!is_invalid_char('Z'));
        assert!(!is_invalid_char('0'));
        assert!(is_invalid_char(' '));
        assert!(is_invalid_char('\t'));
        assert!(is_invalid_char('\0'));
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("hello").is_ok());
        assert!(validate_name("FUN_00401000").is_ok());
    }

    #[test]
    fn test_validate_name_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn test_validate_name_invalid_chars() {
        assert!(validate_name("hello world").is_err());
    }

    #[test]
    fn test_validate_name_too_long() {
        let long_name = "a".repeat(MAX_SYMBOL_NAME_LENGTH + 1);
        assert!(validate_name(&long_name).is_err());
    }

    #[test]
    fn test_replace_invalid_chars() {
        assert_eq!(replace_invalid_chars("a:b*c", true), "a:b*c");
        assert_eq!(replace_invalid_chars("hello world", true), "hello_world");
        assert_eq!(replace_invalid_chars("hello world", false), "helloworld");
    }

    #[test]
    fn test_get_default_function_name() {
        let addr = Address::new(0x401000);
        assert_eq!(get_default_function_name(&addr), "FUN_00401000");
    }

    #[test]
    fn test_get_default_external_function_name() {
        let addr = Address::new(0x401000);
        assert_eq!(
            get_default_external_function_name(&addr),
            "EXT_FUN_00401000"
        );
    }

    #[test]
    fn test_get_default_external_name() {
        let addr = Address::new(0x401000);
        assert_eq!(
            get_default_external_name(&addr, Some("DAT")),
            "EXT_DAT_00401000"
        );
        assert_eq!(
            get_default_external_name(&addr, None),
            "EXT_00401000"
        );
    }

    #[test]
    fn test_get_dynamic_offcut_name() {
        let addr = Address::new(0x401000);
        assert_eq!(get_dynamic_offcut_name(&addr), "OFF_00401000");
    }

    #[test]
    fn test_get_dynamic_name() {
        let addr = Address::new(0x401000);
        assert_eq!(get_dynamic_name(FUN_LEVEL, &addr), "FUN_00401000");
        assert_eq!(get_dynamic_name(LAB_LEVEL, &addr), "LAB_00401000");
        assert_eq!(get_dynamic_name(DAT_LEVEL, &addr), "DAT_00401000");
        assert_eq!(get_dynamic_name(SUB_LEVEL, &addr), "SUB_00401000");
        assert_eq!(get_dynamic_name(EXT_LEVEL, &addr), "EXT_00401000");
        assert_eq!(get_dynamic_name(UNK_LEVEL, &addr), "UNK_00401000");
    }

    #[test]
    fn test_get_address_string() {
        let addr = Address::new(0x401000);
        assert_eq!(get_address_string(&addr), "00401000");
    }

    #[test]
    fn test_get_diff_string() {
        assert_eq!(get_diff_string(0), "0");
        assert_eq!(get_diff_string(5), "5");
        assert_eq!(get_diff_string(9), "9");
        assert_eq!(get_diff_string(10), "0xa");
        assert_eq!(get_diff_string(255), "0xff");
    }

    #[test]
    fn test_get_default_param_name() {
        assert_eq!(get_default_param_name(0), "param_1");
        assert_eq!(get_default_param_name(1), "param_2");
        assert_eq!(get_default_param_name(4), "param_5");
    }

    #[test]
    fn test_is_default_parameter_name() {
        assert!(is_default_parameter_name(""));
        assert!(is_default_parameter_name("param_1"));
        assert!(is_default_parameter_name("param_42"));
        assert!(!is_default_parameter_name("param_abc"));
        assert!(!is_default_parameter_name("hello"));
    }

    #[test]
    fn test_starts_with_default_dynamic_prefix() {
        assert!(starts_with_default_dynamic_prefix("FUN_00401000"));
        assert!(starts_with_default_dynamic_prefix("LAB_00401000"));
        assert!(starts_with_default_dynamic_prefix("DAT_00401000"));
        assert!(starts_with_default_dynamic_prefix("SUB_00401000"));
        assert!(starts_with_default_dynamic_prefix("EXT_00401000"));
        assert!(starts_with_default_dynamic_prefix("UNK_00401000"));
        assert!(!starts_with_default_dynamic_prefix("hello"));
    }

    #[test]
    fn test_is_dynamic_symbol_pattern() {
        assert!(is_dynamic_symbol_pattern("FUN_00401000", true));
        assert!(is_dynamic_symbol_pattern("FUN_00401000", false));
        assert!(!is_dynamic_symbol_pattern("hello", true));
        // Pattern with hex suffix
        assert!(is_dynamic_symbol_pattern("myvar_dead", true));
    }

    #[test]
    fn test_is_reserved_external_default_name() {
        assert!(is_reserved_external_default_name("EXT_FUN_00401000"));
        assert!(is_reserved_external_default_name("EXT_00401000"));
        assert!(!is_reserved_external_default_name("FUN_00401000"));
    }

    #[test]
    fn test_is_reserved_dynamic_label_name() {
        assert!(is_reserved_dynamic_label_name("FUN_00401000"));
        assert!(is_reserved_dynamic_label_name("LAB_00401000"));
        // Too short address
        assert!(!is_reserved_dynamic_label_name("FUN_001"));
        // Not a hex address
        assert!(!is_reserved_dynamic_label_name("FUN_not_hex!"));
    }

    #[test]
    fn test_get_ordinal_value() {
        assert_eq!(get_ordinal_value("Ordinal_0"), 0);
        assert_eq!(get_ordinal_value("Ordinal_42"), 42);
        assert_eq!(get_ordinal_value("Ordinal_abc"), -1);
        assert_eq!(get_ordinal_value("hello"), -1);
    }

    #[test]
    fn test_get_address_appended_name() {
        let addr = Address::new(0x401000);
        assert_eq!(
            get_address_appended_name("myFunc", &addr),
            "myFunc@00401000"
        );
    }

    #[test]
    fn test_get_clean_symbol_name() {
        let addr = Address::new(0x401000);
        // With "@" separator
        assert_eq!(
            get_clean_symbol_name("myFunc@00401000", &addr),
            "myFunc"
        );
        // Without appended address
        assert_eq!(
            get_clean_symbol_name("myFunc", &addr),
            "myFunc"
        );
    }

    #[test]
    fn test_is_possible_default_local_or_param_name() {
        assert!(is_possible_default_local_or_param_name("param_1"));
        assert!(is_possible_default_local_or_param_name("Var_10"));
        assert!(!is_possible_default_local_or_param_name("myVar"));
    }

    #[test]
    fn test_is_possible_default_external_name() {
        assert!(is_possible_default_external_name("EXT_FUN_00401000"));
        assert!(!is_possible_default_external_name("FUN_00401000"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_SYMBOL_NAME_LENGTH, 2000);
        assert_eq!(MIN_LABEL_ADDRESS_DIGITS, 4);
        assert_eq!(ORDINAL_PREFIX, "Ordinal_");
        assert_eq!(DEFAULT_FUNCTION_PREFIX, "FUN_");
        assert_eq!(DEFAULT_SUBROUTINE_PREFIX, "SUB_");
        assert_eq!(DEFAULT_SYMBOL_PREFIX, "LAB_");
        assert_eq!(DEFAULT_DATA_PREFIX, "DAT_");
        assert_eq!(DEFAULT_UNKNOWN_PREFIX, "UNK_");
        assert_eq!(DEFAULT_EXTERNAL_ENTRY_PREFIX, "EXT_");
        assert_eq!(DEFAULT_INTERNAL_REF_PREFIX, "OFF_");
    }
}
