//! Utility functions for the data type manager.
//!
//! Ported from `ghidra.app.plugin.core.datamgr.DataTypeUtils`,
//! `ArchiveUtils`, and `DataTypeArchiveUtility`.

/// Utility functions for working with data types.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeUtils`.
pub struct DataTypeUtils;

impl DataTypeUtils {
    /// Normalize a data type name by trimming whitespace and removing
    /// excess internal whitespace.
    pub fn normalize_name(name: &str) -> String {
        name.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Check if a name is a valid data type name.
    pub fn is_valid_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 2048 {
            return false;
        }
        // Must not start with a digit
        if name.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            return false;
        }
        // Must not contain control characters
        !name.chars().any(|c| c.is_control())
    }

    /// Extract the base type name from a qualified name (strips pointers, arrays).
    pub fn base_type_name(type_name: &str) -> &str {
        let trimmed = type_name.trim();
        // Strip pointer suffix
        let no_ptr = trimmed.trim_end_matches('*').trim();
        // Strip array suffix
        if let Some(bracket) = no_ptr.find('[') {
            no_ptr[..bracket].trim()
        } else {
            no_ptr
        }
    }

    /// Check if a type name represents a pointer.
    pub fn is_pointer(type_name: &str) -> bool {
        type_name.contains('*')
    }

    /// Check if a type name represents an array.
    pub fn is_array(type_name: &str) -> bool {
        type_name.contains('[')
    }

    /// Strip whitespace from a type name (for display in compact form).
    pub fn strip_whitespace(name: &str) -> String {
        name.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Get the array element count from a type name like "int[10]".
    pub fn array_element_count(type_name: &str) -> Option<usize> {
        let start = type_name.find('[')?;
        let end = type_name.find(']')?;
        type_name[start + 1..end].parse().ok()
    }

    /// Make a pointer type name from a base type.
    pub fn make_pointer(base: &str) -> String {
        format!("{} *", base)
    }

    /// Make an array type name from a base type and count.
    pub fn make_array(base: &str, count: usize) -> String {
        format!("{}[{}]", base, count)
    }

    /// Compare two data type names (case-insensitive, then case-sensitive).
    pub fn compare_names(a: &str, b: &str) -> std::cmp::Ordering {
        let a_lower = a.to_lowercase();
        let b_lower = b.to_lowercase();
        a_lower.cmp(&b_lower).then_with(|| a.cmp(b))
    }
}

// ---------------------------------------------------------------------------
// ArchiveUtils
// ---------------------------------------------------------------------------

/// Utility functions for working with archives.
///
/// Ported from `ghidra.app.plugin.core.datamgr.ArchiveUtils`.
pub struct ArchiveUtils;

impl ArchiveUtils {
    /// Extract the file name from a full archive path.
    pub fn file_name(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }

    /// Get the extension of an archive file.
    pub fn extension(path: &str) -> Option<&str> {
        let name = Self::file_name(path);
        let pos = name.rfind('.')?;
        if pos == 0 {
            None
        } else {
            Some(&name[pos + 1..])
        }
    }

    /// Check if a path points to a Ghidra archive file.
    pub fn is_archive_file(path: &str) -> bool {
        matches!(
            Self::extension(path),
            Some("gzf") | Some("gdt") | Some("gdtf") | Some("gar")
        )
    }

    /// Check if a path points to a C header file.
    pub fn is_header_file(path: &str) -> bool {
        matches!(Self::extension(path), Some("h") | Some("hpp"))
    }

    /// Normalize a category path (ensure it starts with / and doesn't end with /).
    pub fn normalize_category_path(path: &str) -> String {
        let trimmed = path.trim();
        let with_leading = if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{}", trimmed)
        };
        if with_leading.len() > 1 && with_leading.ends_with('/') {
            with_leading[..with_leading.len() - 1].to_string()
        } else {
            with_leading
        }
    }

    /// Join two category path segments.
    pub fn join_paths(parent: &str, child: &str) -> String {
        let parent = Self::normalize_category_path(parent);
        let child = child.trim_start_matches('/');
        if parent == "/" {
            format!("/{}", child)
        } else {
            format!("{}/{}", parent, child)
        }
    }

    /// Get the parent category path.
    pub fn parent_path(path: &str) -> String {
        let normalized = Self::normalize_category_path(path);
        match normalized.rfind('/') {
            Some(pos) if pos > 0 => normalized[..pos].to_string(),
            _ => "/".to_string(),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_name() {
        assert_eq!(DataTypeUtils::normalize_name("  int  * "), "int *");
        assert_eq!(DataTypeUtils::normalize_name("int"), "int");
        assert_eq!(DataTypeUtils::normalize_name(""), "");
    }

    #[test]
    fn test_is_valid_name() {
        assert!(DataTypeUtils::is_valid_name("int"));
        assert!(DataTypeUtils::is_valid_name("MyStruct"));
        assert!(!DataTypeUtils::is_valid_name(""));
        assert!(!DataTypeUtils::is_valid_name("123abc"));
        assert!(!DataTypeUtils::is_valid_name("bad\x00name"));
    }

    #[test]
    fn test_base_type_name() {
        assert_eq!(DataTypeUtils::base_type_name("int *"), "int");
        assert_eq!(DataTypeUtils::base_type_name("int"), "int");
        assert_eq!(DataTypeUtils::base_type_name("char[10]"), "char");
        assert_eq!(DataTypeUtils::base_type_name("int **"), "int");
    }

    #[test]
    fn test_is_pointer_array() {
        assert!(DataTypeUtils::is_pointer("int *"));
        assert!(!DataTypeUtils::is_pointer("int"));
        assert!(DataTypeUtils::is_array("char[10]"));
        assert!(!DataTypeUtils::is_array("char"));
    }

    #[test]
    fn test_strip_whitespace() {
        assert_eq!(DataTypeUtils::strip_whitespace("int *"), "int*");
        assert_eq!(DataTypeUtils::strip_whitespace("  int  "), "int");
    }

    #[test]
    fn test_array_element_count() {
        assert_eq!(DataTypeUtils::array_element_count("int[10]"), Some(10));
        assert_eq!(DataTypeUtils::array_element_count("char[256]"), Some(256));
        assert_eq!(DataTypeUtils::array_element_count("int"), None);
        assert_eq!(DataTypeUtils::array_element_count("int[]"), None);
    }

    #[test]
    fn test_make_pointer_array() {
        assert_eq!(DataTypeUtils::make_pointer("int"), "int *");
        assert_eq!(DataTypeUtils::make_array("char", 10), "char[10]");
    }

    #[test]
    fn test_compare_names() {
        use std::cmp::Ordering;
        assert_eq!(DataTypeUtils::compare_names("abc", "ABC"), Ordering::Greater);
        assert_eq!(DataTypeUtils::compare_names("ABC", "abc"), Ordering::Less);
        assert_eq!(DataTypeUtils::compare_names("abc", "abc"), Ordering::Equal);
    }

    #[test]
    fn test_archive_utils_file_name() {
        assert_eq!(ArchiveUtils::file_name("/path/to/file.gdt"), "file.gdt");
        assert_eq!(ArchiveUtils::file_name("file.gdt"), "file.gdt");
    }

    #[test]
    fn test_archive_utils_extension() {
        assert_eq!(ArchiveUtils::extension("/path/to/file.gdt"), Some("gdt"));
        assert_eq!(ArchiveUtils::extension("file.h"), Some("h"));
        assert_eq!(ArchiveUtils::extension("noext"), None);
        assert_eq!(ArchiveUtils::extension(".hidden"), None);
    }

    #[test]
    fn test_archive_utils_is_archive() {
        assert!(ArchiveUtils::is_archive_file("types.gdt"));
        assert!(ArchiveUtils::is_archive_file("archive.gzf"));
        assert!(!ArchiveUtils::is_archive_file("code.c"));
    }

    #[test]
    fn test_archive_utils_is_header() {
        assert!(ArchiveUtils::is_header_file("types.h"));
        assert!(ArchiveUtils::is_header_file("types.hpp"));
        assert!(!ArchiveUtils::is_header_file("types.c"));
    }

    #[test]
    fn test_archive_utils_normalize_category_path() {
        assert_eq!(ArchiveUtils::normalize_category_path("/MyLib"), "/MyLib");
        assert_eq!(ArchiveUtils::normalize_category_path("MyLib"), "/MyLib");
        assert_eq!(ArchiveUtils::normalize_category_path("/MyLib/"), "/MyLib");
        assert_eq!(ArchiveUtils::normalize_category_path("/"), "/");
    }

    #[test]
    fn test_archive_utils_join_paths() {
        assert_eq!(ArchiveUtils::join_paths("/Parent", "Child"), "/Parent/Child");
        assert_eq!(ArchiveUtils::join_paths("/", "Child"), "/Child");
        assert_eq!(ArchiveUtils::join_paths("Parent", "/Child"), "/Parent/Child");
    }

    #[test]
    fn test_archive_utils_parent_path() {
        assert_eq!(ArchiveUtils::parent_path("/A/B/C"), "/A/B");
        assert_eq!(ArchiveUtils::parent_path("/A"), "/");
        assert_eq!(ArchiveUtils::parent_path("/"), "/");
    }
}
