//! Extension traits and additional functionality for Clang token types.
//!
//! Provides convenience methods for the token types defined in `clang_node`:
//! - [`ClangOpTokenExt`] -- extension methods for operator tokens
//! - [`ClangTypeTokenExt`] -- extension methods for type name tokens
//! - [`ClangVariableDeclExt`] -- extension methods for variable declarations
//!
//! Also provides `ClangTokenClassifier` for categorizing operator tokens.

use super::clang_node::{ClangOpTokenData, ClangTypeTokenData, ClangVariableDeclData};

// ============================================================================
// ClangOpTokenExt -- extension methods for operator tokens
// ============================================================================

/// Extension trait for [`ClangOpTokenData`] adding operator classification.
pub trait ClangOpTokenExt {
    /// Get the operator text as a string slice.
    fn op_text(&self) -> Option<&str>;

    /// Whether this is an assignment operator.
    fn is_assignment(&self) -> bool {
        matches!(
            self.op_text(),
            Some("=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" | ">>>=")
        )
    }

    /// Whether this is a comparison operator.
    fn is_comparison(&self) -> bool {
        matches!(self.op_text(), Some("==" | "!=" | "<" | ">" | "<=" | ">="))
    }

    /// Whether this is an arithmetic operator.
    fn is_arithmetic(&self) -> bool {
        matches!(self.op_text(), Some("+" | "-" | "*" | "/" | "%"))
    }

    /// Whether this is a logical operator.
    fn is_logical(&self) -> bool {
        matches!(self.op_text(), Some("&&" | "||" | "!"))
    }

    /// Whether this is a bitwise operator.
    fn is_bitwise(&self) -> bool {
        matches!(self.op_text(), Some("&" | "|" | "^" | "~" | "<<" | ">>" | ">>>"))
    }

    /// Whether this is a member access operator.
    fn is_member_access(&self) -> bool {
        matches!(self.op_text(), Some("." | "->"))
    }

    /// Whether this is a unary prefix operator.
    fn is_unary_prefix(&self) -> bool {
        matches!(self.op_text(), Some("!" | "~" | "-" | "++" | "--" | "&" | "*" | "sizeof"))
    }

    /// Whether this is a ternary operator part.
    fn is_ternary(&self) -> bool {
        matches!(self.op_text(), Some("?"))
    }

    /// Whether this is a comma operator.
    fn is_comma(&self) -> bool {
        self.op_text() == Some(",")
    }

    /// Whether this is a semicolon.
    fn is_semicolon(&self) -> bool {
        self.op_text() == Some(";")
    }

    /// Get the operator precedence (lower = higher precedence). Returns None for unknown ops.
    fn precedence(&self) -> Option<u8> {
        match self.op_text() {
            Some("()" | "[]" | "." | "->") => Some(1),
            Some("++" | "--" | "!" | "~" | "sizeof" | "(cast)") => Some(2),
            Some("*" | "/" | "%") => Some(3),
            Some("+" | "-") => Some(4),
            Some("<<" | ">>" | ">>>") => Some(5),
            Some("<" | "<=" | ">" | ">=") => Some(6),
            Some("==" | "!=") => Some(7),
            Some("&") => Some(8),
            Some("^") => Some(9),
            Some("|") => Some(10),
            Some("&&") => Some(11),
            Some("||") => Some(12),
            Some("?") => Some(13),
            Some("=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=") => Some(14),
            Some(",") => Some(15),
            _ => None,
        }
    }

    /// Whether this operator is right-associative.
    fn is_right_associative(&self) -> bool {
        matches!(
            self.op_text(),
            Some("=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" | ">>>"
            | "?")
        )
    }
}

impl ClangOpTokenExt for ClangOpTokenData {
    fn op_text(&self) -> Option<&str> {
        self.text.as_deref()
    }
}

// ============================================================================
// ClangTypeTokenExt -- extension methods for type name tokens
// ============================================================================

/// Extension trait for [`ClangTypeTokenData`] adding type analysis.
pub trait ClangTypeTokenExt {
    /// Get the type name text.
    fn type_text(&self) -> Option<&str>;

    /// Whether this is a pointer type.
    fn is_pointer(&self) -> bool {
        self.type_text().map_or(false, |t| t.contains('*'))
    }

    /// Whether this is a const-qualified type.
    fn is_const(&self) -> bool {
        self.type_text().map_or(false, |t| t.starts_with("const") || t.contains(" const "))
    }

    /// Whether this is a volatile-qualified type.
    fn is_volatile(&self) -> bool {
        self.type_text().map_or(false, |t| t.starts_with("volatile") || t.contains(" volatile "))
    }

    /// Whether this is a void type.
    fn is_void(&self) -> bool {
        self.type_text() == Some("void")
    }

    /// Whether this is an integer type.
    fn is_integer(&self) -> bool {
        self.type_text().map_or(false, |t| {
            matches!(
                t,
                "char" | "short" | "int" | "long" | "long long"
                    | "signed" | "unsigned"
                    | "int8_t" | "int16_t" | "int32_t" | "int64_t"
                    | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t"
                    | "size_t" | "ssize_t" | "ptrdiff_t"
                    | "bool" | "_Bool"
            ) || t.starts_with("unsigned ") || t.starts_with("signed ")
        })
    }

    /// Whether this is a floating-point type.
    fn is_float(&self) -> bool {
        self.type_text().map_or(false, |t| matches!(t, "float" | "double" | "long double"))
    }

    /// Whether this is a struct/union type.
    fn is_struct_or_union(&self) -> bool {
        self.type_text().map_or(false, |t| t.starts_with("struct ") || t.starts_with("union "))
    }

    /// Whether this is an enum type.
    fn is_enum(&self) -> bool {
        self.type_text().map_or(false, |t| t.starts_with("enum "))
    }

    /// Strip pointer qualifiers and return the base type text.
    fn base_type(&self) -> Option<&str> {
        self.type_text().map(|t| t.trim_end_matches('*').trim_end())
    }
}

impl ClangTypeTokenExt for ClangTypeTokenData {
    fn type_text(&self) -> Option<&str> {
        self.token.text.as_deref()
    }
}

// ============================================================================
// ClangVariableDeclExt -- extension methods for variable declarations
// ============================================================================

/// Extension trait for [`ClangVariableDeclData`] adding declaration analysis.
pub trait ClangVariableDeclExt {
    /// Get the symbol reference id.
    fn sym_ref(&self) -> Option<u64>;

    /// Get the data type name.
    fn datatype_name(&self) -> Option<&str>;

    /// Get the data type id.
    fn datatype_id(&self) -> Option<u64>;

    /// Whether this declaration has a symbol reference.
    fn has_symbol(&self) -> bool {
        self.sym_ref().is_some()
    }

    /// Whether this has a data type assigned.
    fn has_datatype(&self) -> bool {
        self.datatype_name().is_some() || self.datatype_id().is_some()
    }
}

impl ClangVariableDeclExt for ClangVariableDeclData {
    fn sym_ref(&self) -> Option<u64> {
        self.sym_ref
    }

    fn datatype_name(&self) -> Option<&str> {
        self.datatype_name.as_deref()
    }

    fn datatype_id(&self) -> Option<u64> {
        self.datatype_id
    }
}

// ============================================================================
// ClangTokenClassifier -- utility for categorizing any Clang token
// ============================================================================

/// Classifies a text fragment into a token category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenCategory {
    /// A keyword (if, while, return, etc.).
    Keyword,
    /// An operator (+, -, etc.).
    Operator,
    /// A literal value (number, string, character).
    Literal,
    /// An identifier (variable name, function name).
    Identifier,
    /// A type name.
    TypeName,
    /// Punctuation (parentheses, braces, brackets, semicolons).
    Punctuation,
    /// A comment.
    Comment,
    /// Unknown.
    Unknown,
}

/// Utility for classifying C tokens.
pub struct ClangTokenClassifier;

impl ClangTokenClassifier {
    /// Classify a token text into a category based on simple heuristics.
    pub fn classify(text: &str) -> TokenCategory {
        if text.is_empty() {
            return TokenCategory::Unknown;
        }

        // Check keywords
        if matches!(
            text,
            "if" | "else"
                | "while" | "for" | "do"
                | "switch" | "case" | "default"
                | "break" | "continue" | "return" | "goto"
                | "struct" | "union" | "enum" | "typedef"
                | "sizeof" | "typeof"
                | "const" | "volatile" | "restrict"
                | "static" | "extern" | "register" | "auto" | "inline"
                | "void" | "char" | "short" | "int" | "long"
                | "signed" | "unsigned" | "float" | "double"
                | "bool" | "_Bool"
        ) {
            return TokenCategory::Keyword;
        }

        // Check operators
        if matches!(
            text,
            "+" | "-" | "*" | "/" | "%"
                | "=" | "+=" | "-=" | "*=" | "/=" | "%="
                | "==" | "!=" | "<" | ">" | "<=" | ">="
                | "&&" | "||" | "!"
                | "&" | "|" | "^" | "~" | "<<" | ">>" | ">>>"
                | "&=" | "|=" | "^=" | "<<=" | ">>="
                | "++" | "--"
                | "." | "->"
                | "?" | ":"
        ) {
            return TokenCategory::Operator;
        }

        // Check punctuation
        if matches!(
            text,
            "(" | ")" | "{" | "}" | "[" | "]" | ";" | "," | "..."
        ) {
            return TokenCategory::Punctuation;
        }

        // Check numeric literals
        let first = text.chars().next().unwrap_or('\0');
        if first.is_ascii_digit() || (text.starts_with("0x") || text.starts_with("0X")) {
            return TokenCategory::Literal;
        }

        // Check string/char literals
        if text.starts_with('"') || text.starts_with('\'') {
            return TokenCategory::Literal;
        }

        // Default to identifier
        TokenCategory::Identifier
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::clang_node::{ClangOpTokenData, ClangTypeTokenData, ClangVariableDeclData, ClangTokenData};

    fn make_op(text: &str) -> ClangOpTokenData {
        ClangOpTokenData {
            text: Some(text.to_string()),
            syntax_type: Default::default(),
            op_ref: None,
            min_address: None,
        }
    }

    fn make_type(text: &str) -> ClangTypeTokenData {
        ClangTypeTokenData {
            token: ClangTokenData {
                text: Some(text.to_string()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn op_token_arithmetic() {
        let add = make_op("+");
        assert!(add.is_arithmetic());
        assert!(!add.is_assignment());
        assert!(!add.is_comparison());
        assert_eq!(add.precedence(), Some(4));
    }

    #[test]
    fn op_token_assignment() {
        let assign = make_op("+=");
        assert!(assign.is_assignment());
        assert!(!assign.is_arithmetic());
        assert!(assign.is_right_associative());
        assert_eq!(assign.precedence(), Some(14));
    }

    #[test]
    fn op_token_comparison() {
        let eq = make_op("==");
        assert!(eq.is_comparison());
        assert!(!eq.is_logical());
        assert!(!eq.is_right_associative());
        assert_eq!(eq.precedence(), Some(7));
    }

    #[test]
    fn op_token_logical() {
        let and = make_op("&&");
        assert!(and.is_logical());
        assert_eq!(and.precedence(), Some(11));
        let or = make_op("||");
        assert!(or.is_logical());
        let not = make_op("!");
        assert!(not.is_logical());
        assert!(not.is_unary_prefix());
    }

    #[test]
    fn op_token_member_access() {
        let dot = make_op(".");
        assert!(dot.is_member_access());
        assert_eq!(dot.precedence(), Some(1));
        let arrow = make_op("->");
        assert!(arrow.is_member_access());
    }

    #[test]
    fn op_token_ternary() {
        let q = make_op("?");
        assert!(q.is_ternary());
        assert!(q.is_right_associative());
    }

    #[test]
    fn op_token_none_text() {
        let op = ClangOpTokenData {
            text: None,
            syntax_type: Default::default(),
            op_ref: None,
            min_address: None,
        };
        assert!(!op.is_arithmetic());
        assert!(!op.is_assignment());
        assert!(op.precedence().is_none());
    }

    #[test]
    fn type_token_pointer() {
        let t = make_type("char *");
        assert!(t.is_pointer());
        assert_eq!(t.base_type(), Some("char"));
    }

    #[test]
    fn type_token_integer() {
        assert!(make_type("int").is_integer());
        assert!(make_type("uint32_t").is_integer());
        assert!(make_type("unsigned long").is_integer());
        assert!(!make_type("float").is_integer());
    }

    #[test]
    fn type_token_float() {
        assert!(make_type("float").is_float());
        assert!(make_type("double").is_float());
        assert!(!make_type("int").is_float());
    }

    #[test]
    fn type_token_struct() {
        assert!(make_type("struct foo").is_struct_or_union());
        assert!(make_type("union bar").is_struct_or_union());
        assert!(!make_type("int").is_struct_or_union());
    }

    #[test]
    fn type_token_enum() {
        assert!(make_type("enum color").is_enum());
        assert!(!make_type("int").is_enum());
    }

    #[test]
    fn type_token_qualifiers() {
        let t = make_type("const volatile int");
        assert!(t.is_const());
        assert!(t.is_volatile());
    }

    #[test]
    fn type_token_none() {
        let t = ClangTypeTokenData {
            token: ClangTokenData { text: None, ..Default::default() },
        };
        assert!(!t.is_pointer());
        assert!(!t.is_void());
        assert!(t.type_text().is_none());
    }

    #[test]
    fn variable_decl_ext() {
        let d = ClangVariableDeclData {
            group: Default::default(),
            sym_ref: Some(42),
            datatype_name: Some("int".to_string()),
            datatype_id: Some(1),
        };
        assert!(d.has_symbol());
        assert_eq!(d.sym_ref(), Some(42));
        assert_eq!(d.datatype_name(), Some("int"));
        assert!(d.has_datatype());
    }

    #[test]
    fn variable_decl_no_symbol() {
        let d = ClangVariableDeclData {
            group: Default::default(),
            sym_ref: None,
            datatype_name: None,
            datatype_id: None,
        };
        assert!(!d.has_symbol());
        assert!(!d.has_datatype());
    }

    #[test]
    fn classifier_keywords() {
        assert_eq!(ClangTokenClassifier::classify("if"), TokenCategory::Keyword);
        assert_eq!(ClangTokenClassifier::classify("return"), TokenCategory::Keyword);
        assert_eq!(ClangTokenClassifier::classify("struct"), TokenCategory::Keyword);
        assert_eq!(ClangTokenClassifier::classify("void"), TokenCategory::Keyword);
    }

    #[test]
    fn classifier_operators() {
        assert_eq!(ClangTokenClassifier::classify("+"), TokenCategory::Operator);
        assert_eq!(ClangTokenClassifier::classify("=="), TokenCategory::Operator);
        assert_eq!(ClangTokenClassifier::classify("->"), TokenCategory::Operator);
    }

    #[test]
    fn classifier_punctuation() {
        assert_eq!(ClangTokenClassifier::classify("("), TokenCategory::Punctuation);
        assert_eq!(ClangTokenClassifier::classify(";"), TokenCategory::Punctuation);
        assert_eq!(ClangTokenClassifier::classify("{"), TokenCategory::Punctuation);
    }

    #[test]
    fn classifier_literals() {
        assert_eq!(ClangTokenClassifier::classify("42"), TokenCategory::Literal);
        assert_eq!(ClangTokenClassifier::classify("0xFF"), TokenCategory::Literal);
        assert_eq!(ClangTokenClassifier::classify("\"hello\""), TokenCategory::Literal);
    }

    #[test]
    fn classifier_identifiers() {
        assert_eq!(ClangTokenClassifier::classify("myVar"), TokenCategory::Identifier);
        assert_eq!(ClangTokenClassifier::classify("x"), TokenCategory::Identifier);
    }

    #[test]
    fn op_token_precedence_ordering() {
        let mul = make_op("*");
        let add = make_op("+");
        let assign = make_op("=");
        assert!(mul.precedence().unwrap() < add.precedence().unwrap());
        assert!(add.precedence().unwrap() < assign.precedence().unwrap());
    }
}
