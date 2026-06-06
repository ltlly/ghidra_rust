//! `SearchSettings` -- immutable container for all search settings.
//!
//! Ported from `ghidra.features.base.memsearch.gui.SearchSettings`.

/// Immutable container for all relevant search settings.
///
/// Supports creating modified copies via the `with_*` builder methods.
///
/// Ported from `SearchSettings.java`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SearchSettings {
    /// Whether to use big-endian byte ordering.
    big_endian: bool,
    /// Whether string search is case-sensitive.
    case_sensitive: bool,
    /// Whether to process escape sequences in string input.
    use_escape_sequences: bool,
    /// Whether to include instructions in search scope.
    include_instructions: bool,
    /// Whether to include defined data in search scope.
    include_defined_data: bool,
    /// Whether to include undefined data in search scope.
    include_undefined_data: bool,
    /// Whether decimal values are unsigned.
    decimal_unsigned: bool,
    /// Byte size for decimal values (2, 4, 8, or 16).
    decimal_byte_size: usize,
    /// Address alignment for matches (1 = any address).
    alignment: usize,
    /// Character encoding name (e.g., "UTF-8", "UTF-16", "ASCII").
    charset_name: String,
    /// Index of the active search format.
    format_index: usize,
}

impl Default for SearchSettings {
    fn default() -> Self {
        Self {
            big_endian: false,
            case_sensitive: false,
            use_escape_sequences: false,
            include_instructions: true,
            include_defined_data: true,
            include_undefined_data: true,
            decimal_unsigned: false,
            decimal_byte_size: 4,
            alignment: 1,
            charset_name: "UTF-8".to_string(),
            format_index: 0,
        }
    }
}

impl SearchSettings {
    /// Create new default search settings.
    pub fn new() -> Self {
        Self::default()
    }

    // Accessor methods

    /// Whether to use big-endian byte ordering.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Whether string search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Whether to process escape sequences.
    pub fn use_escape_sequences(&self) -> bool {
        self.use_escape_sequences
    }

    /// Whether to include instructions in search scope.
    pub fn include_instructions(&self) -> bool {
        self.include_instructions
    }

    /// Whether to include defined data in search scope.
    pub fn include_defined_data(&self) -> bool {
        self.include_defined_data
    }

    /// Whether to include undefined data in search scope.
    pub fn include_undefined_data(&self) -> bool {
        self.include_undefined_data
    }

    /// Whether decimal values are unsigned.
    pub fn is_decimal_unsigned(&self) -> bool {
        self.decimal_unsigned
    }

    /// Byte size for decimal values.
    pub fn decimal_byte_size(&self) -> usize {
        self.decimal_byte_size
    }

    /// Address alignment for matches.
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Character encoding name.
    pub fn charset_name(&self) -> &str {
        &self.charset_name
    }

    /// Active search format index.
    pub fn format_index(&self) -> usize {
        self.format_index
    }

    // Builder methods (return new instances since settings are immutable)

    /// Create a copy with big-endian setting changed.
    pub fn with_big_endian(&self, big_endian: bool) -> Self {
        Self {
            big_endian,
            ..self.clone()
        }
    }

    /// Create a copy with case-sensitive setting changed.
    pub fn with_case_sensitive(&self, case_sensitive: bool) -> Self {
        Self {
            case_sensitive,
            ..self.clone()
        }
    }

    /// Create a copy with escape sequences setting changed.
    pub fn with_escape_sequences(&self, use_escape_sequences: bool) -> Self {
        Self {
            use_escape_sequences,
            ..self.clone()
        }
    }

    /// Create a copy with alignment setting changed.
    pub fn with_alignment(&self, alignment: usize) -> Self {
        Self {
            alignment: alignment.max(1),
            ..self.clone()
        }
    }

    /// Create a copy with decimal unsigned setting changed.
    pub fn with_decimal_unsigned(&self, decimal_unsigned: bool) -> Self {
        Self {
            decimal_unsigned,
            ..self.clone()
        }
    }

    /// Create a copy with decimal byte size changed.
    pub fn with_decimal_byte_size(&self, decimal_byte_size: usize) -> Self {
        Self {
            decimal_byte_size,
            ..self.clone()
        }
    }

    /// Create a copy with charset changed.
    pub fn with_charset(&self, charset_name: &str) -> Self {
        Self {
            charset_name: charset_name.to_string(),
            ..self.clone()
        }
    }

    /// Create a copy with format index changed.
    pub fn with_format_index(&self, format_index: usize) -> Self {
        Self {
            format_index,
            ..self.clone()
        }
    }

    /// Create a copy with include instructions changed.
    pub fn with_include_instructions(&self, include: bool) -> Self {
        Self {
            include_instructions: include,
            ..self.clone()
        }
    }

    /// Create a copy with include defined data changed.
    pub fn with_include_defined_data(&self, include: bool) -> Self {
        Self {
            include_defined_data: include,
            ..self.clone()
        }
    }

    /// Create a copy with include undefined data changed.
    pub fn with_include_undefined_data(&self, include: bool) -> Self {
        Self {
            include_undefined_data: include,
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let s = SearchSettings::default();
        assert!(!s.is_big_endian());
        assert!(!s.is_case_sensitive());
        assert!(s.include_instructions());
        assert_eq!(s.decimal_byte_size(), 4);
        assert_eq!(s.alignment(), 1);
    }

    #[test]
    fn test_builder_pattern() {
        let s = SearchSettings::default()
            .with_big_endian(true)
            .with_case_sensitive(true)
            .with_alignment(4);

        assert!(s.is_big_endian());
        assert!(s.is_case_sensitive());
        assert_eq!(s.alignment(), 4);
    }

    #[test]
    fn test_immutability() {
        let s1 = SearchSettings::default();
        let s2 = s1.with_big_endian(true);
        assert!(!s1.is_big_endian());
        assert!(s2.is_big_endian());
    }

    #[test]
    fn test_equality() {
        let s1 = SearchSettings::default();
        let s2 = SearchSettings::default();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_charset() {
        let s = SearchSettings::default().with_charset("UTF-16");
        assert_eq!(s.charset_name(), "UTF-16");
    }

    #[test]
    fn test_decimal_settings() {
        let s = SearchSettings::default()
            .with_decimal_unsigned(true)
            .with_decimal_byte_size(8);
        assert!(s.is_decimal_unsigned());
        assert_eq!(s.decimal_byte_size(), 8);
    }
}
