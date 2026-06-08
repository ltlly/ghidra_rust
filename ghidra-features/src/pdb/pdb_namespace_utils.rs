//! PDB Namespace Utilities -- namespace path fixing and unnamed tag handling.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.PdbNamespaceUtils`.

use super::pdb_categories::SymbolPath;

/// Fix unnamed tags and types in a symbol path.
///
/// Replaces `<unnamed-tag>`, `<anonymous-tag>`, `<unnamed-type>`, and `__unnamed`
/// with unique names incorporating the given index number.
///
/// For example, `<unnamed-tag>` becomes `<unnamed-tag_00000001>` when index is 1.
pub fn fix_unnamed(name: &str, index: u32) -> String {
    match name {
        "<unnamed-tag>" => format!("<unnamed-tag_{:08X}>", index),
        "<anonymous-tag>" => format!("<anonymous-tag_{:08X}>", index),
        "<unnamed-type>" => format!("<unnamed-type_{:08X}>", index),
        "__unnamed" => format!("__unnamed_{:08X}", index),
        _ => name.to_string(),
    }
}

/// Convert a symbol path to a Ghidra-compatible path name.
///
/// Replaces invalid characters and fixes unnamed components using the
/// given index for uniqueness.
pub fn convert_to_ghidra_path_name(symbol_path: &SymbolPath, index: u32) -> SymbolPath {
    // Fix unnamed first (before replace_invalid_chars destroys the pattern)
    let name = symbol_path.name();
    let fixed_name = if is_unnamed(name) {
        fix_unnamed(name, index)
    } else {
        replace_invalid_chars(name)
    };
    if let Some(parent) = symbol_path.parent_path() {
        parent.replace_invalid_chars().child(&fixed_name)
    } else {
        SymbolPath::from_components(vec![fixed_name])
    }
}

/// Convert a symbol path to a Ghidra-compatible path (without index).
///
/// Replaces invalid characters only.
pub fn convert_to_ghidra_path_name_simple(symbol_path: &SymbolPath) -> SymbolPath {
    symbol_path.replace_invalid_chars()
}

/// Convert a symbol path to a Ghidra-compatible path, fixing all unnamed components.
///
/// Each component in the path is checked for unnamed tags and replaced
/// with a unique name using the given index.
pub fn convert_to_ghidra_path(symbol_path: &SymbolPath, index: u32) -> SymbolPath {
    // Fix unnamed first, then replace invalid chars for non-unnamed components
    let components: Vec<String> = symbol_path
        .as_list()
        .iter()
        .map(|s| {
            if is_unnamed(s) {
                fix_unnamed(s, index)
            } else {
                replace_invalid_chars(s)
            }
        })
        .collect();
    SymbolPath::from_components(components)
}

/// Replace invalid characters in a symbol name.
///
/// Characters that are not alphanumeric or underscore are replaced with underscores.
pub fn replace_invalid_chars(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '<' || c == '>' { c } else { '_' })
        .collect()
}

/// Check if a name is an unnamed/anonymous tag.
pub fn is_unnamed(name: &str) -> bool {
    matches!(
        name,
        "<unnamed-tag>" | "<anonymous-tag>" | "<unnamed-type>" | "__unnamed"
    )
}

/// Strip namespace prefix from a name.
///
/// For example, `"Namespace::ClassName"` returns `"ClassName"`.
pub fn strip_namespace(name: &str) -> &str {
    if let Some(pos) = name.rfind("::") {
        &name[pos + 2..]
    } else {
        name
    }
}

/// Parse a namespace-qualified name into components.
///
/// For example, `"std::vector::iterator"` returns `["std", "vector", "iterator"]`.
pub fn parse_namespace(name: &str) -> Vec<&str> {
    name.split("::").collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_unnamed_tag() {
        assert_eq!(fix_unnamed("<unnamed-tag>", 0x42), "<unnamed-tag_00000042>");
        assert_eq!(fix_unnamed("<anonymous-tag>", 1), "<anonymous-tag_00000001>");
    }

    #[test]
    fn test_fix_unnamed_type() {
        assert_eq!(fix_unnamed("<unnamed-type>", 0xFF), "<unnamed-type_000000FF>");
    }

    #[test]
    fn test_fix_unnamed_dunder() {
        assert_eq!(fix_unnamed("__unnamed", 0), "__unnamed_00000000");
    }

    #[test]
    fn test_fix_unnamed_regular_name() {
        assert_eq!(fix_unnamed("normal_name", 5), "normal_name");
    }

    #[test]
    fn test_convert_to_ghidra_path_name() {
        let sp = SymbolPath::new("MyClass::<unnamed-tag>");
        let fixed = convert_to_ghidra_path_name(&sp, 0x10);
        assert_eq!(fixed.as_list().last().unwrap(), "<unnamed-tag_00000010>");
    }

    #[test]
    fn test_convert_to_ghidra_path() {
        let sp = SymbolPath::new("Outer::<unnamed-tag>::Inner");
        let fixed = convert_to_ghidra_path(&sp, 5);
        let components = fixed.as_list();
        assert_eq!(components[0], "Outer");
        assert_eq!(components[1], "<unnamed-tag_00000005>");
        assert_eq!(components[2], "Inner");
    }

    #[test]
    fn test_replace_invalid_chars() {
        assert_eq!(replace_invalid_chars("my-type"), "my_type");
        assert_eq!(replace_invalid_chars("a::b::c"), "a__b__c");
        assert_eq!(replace_invalid_chars("valid_name"), "valid_name");
    }

    #[test]
    fn test_is_unnamed() {
        assert!(is_unnamed("<unnamed-tag>"));
        assert!(is_unnamed("<anonymous-tag>"));
        assert!(is_unnamed("<unnamed-type>"));
        assert!(is_unnamed("__unnamed"));
        assert!(!is_unnamed("normal_name"));
    }

    #[test]
    fn test_strip_namespace() {
        assert_eq!(strip_namespace("Namespace::ClassName"), "ClassName");
        assert_eq!(strip_namespace("a::b::c"), "c");
        assert_eq!(strip_namespace("simple"), "simple");
    }

    #[test]
    fn test_parse_namespace() {
        assert_eq!(parse_namespace("std::vector::iterator"), vec!["std", "vector", "iterator"]);
        assert_eq!(parse_namespace("simple"), vec!["simple"]);
    }
}
