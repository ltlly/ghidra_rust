//! Naming and hashing utilities for the filesystem store.
//!
//! Provides [`NamingUtilities`] for case-sensitive name mangling on
//! case-insensitive filesystems, and [`MD5Utilities`] for computing MD5
//! hashes of data, files, and strings.
//!
//! Corresponds to `ghidra.util.NamingUtilities` and `ghidra.util.MD5Utilities`.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::error::GhidraError;

// ============================================================================
// NamingUtilities
// ============================================================================

/// The mangle character used to escape uppercase letters.
const MANGLE_CHAR: char = '_';

/// Static utility class with methods for validating project file names
/// and performing case-sensitive name mangling.
///
/// On case-insensitive filesystems, Ghidra stores names using a mangling
/// scheme where uppercase letters are prefixed with `_` and lowercased,
/// and literal underscores are doubled.
///
/// Corresponds to `ghidra.util.NamingUtilities`.
pub struct NamingUtilities;

impl NamingUtilities {
    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /// Test whether the given string is a valid project name.
    ///
    /// Rules:
    /// - Name may not be blank.
    /// - Name may not start with a period.
    /// - All characters must be a letter, digit, or within the allowed set:
    ///   `.`, `-`, `=`, `@`, ` `, `_`, `(`, `)`, `[`, `]`, `~`
    pub fn is_valid_project_name(name: &str) -> bool {
        Self::check_project_name(name).is_ok()
    }

    /// Check the specified project name for character restrictions.
    ///
    /// Returns `Err` with a descriptive message if the name is invalid.
    pub fn check_project_name(name: &str) -> Result<(), GhidraError> {
        Self::check_name(name, "Project name")
    }

    /// Check a path element name for character restrictions.
    ///
    /// Restrictions:
    /// - May not be blank.
    /// - May not start with `.` (prevents `.` and `..` path traversal).
    /// - May only contain letters, digits, or the allowed symbol set.
    ///
    /// `element_type` is a descriptive label used in error messages; pass
    /// `"Path element"` or a custom string.
    pub fn check_name(path_element: &str, element_type: &str) -> Result<(), GhidraError> {
        let kind = if element_type.is_empty() {
            "Path element"
        } else {
            element_type
        };

        if path_element.trim().is_empty() {
            return Err(GhidraError::InvalidData(format!(
                "A blank {} is not allowed",
                kind
            )));
        }
        if path_element.starts_with('.') {
            return Err(GhidraError::InvalidData(format!(
                "{} starting with '.' is not permitted",
                kind
            )));
        }
        if let Some(ch) = Self::find_invalid_char(path_element) {
            return Err(GhidraError::InvalidData(format!(
                "{} contains invalid character: '{}'",
                kind, ch
            )));
        }
        Ok(())
    }

    /// Identify the first invalid/unsupported character in `name`, or `None`.
    pub fn find_invalid_char(name: &str) -> Option<char> {
        for ch in name.chars() {
            if ch.is_alphanumeric() {
                continue;
            }
            if (ch as u32) <= 0x7F && Self::is_valid_symbol(ch) {
                continue;
            }
            return Some(ch);
        }
        None
    }

    /// Returns `true` if `ch` is in the allowed symbol set.
    pub fn is_valid_symbol(ch: char) -> bool {
        matches!(
            ch,
            '.' | '-' | '=' | '@' | ' ' | '_' | '(' | ')' | '[' | ']' | '~'
        )
    }

    // ------------------------------------------------------------------
    // Name mangling
    // ------------------------------------------------------------------

    /// Mangle a name for case-insensitive storage.
    ///
    /// Uppercase characters become `_<lowercase>`. Literal underscores are
    /// doubled to `__`. All other characters pass through unchanged.
    ///
    /// `"Foo.exe"` becomes `"_foo.exe"`.
    pub fn mangle(name: &str) -> String {
        let mut buf = String::with_capacity(name.len() * 2);
        for ch in name.chars() {
            if ch == MANGLE_CHAR {
                buf.push(MANGLE_CHAR);
                buf.push(MANGLE_CHAR);
            } else if ch.is_ascii_uppercase() {
                buf.push(MANGLE_CHAR);
                buf.push(ch.to_ascii_lowercase());
            } else {
                buf.push(ch);
            }
        }
        buf
    }

    /// Reverse the mangling performed by [`NamingUtilities::mangle`].
    ///
    /// Characters following a mangle char are uppercased; a double mangle
    /// char becomes a single underscore.
    pub fn demangle(mangled: &str) -> String {
        let mut buf = String::with_capacity(mangled.len());
        let chars: Vec<char> = mangled.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == MANGLE_CHAR {
                i += 1;
                if i < chars.len() {
                    if chars[i] == MANGLE_CHAR {
                        buf.push(MANGLE_CHAR);
                    } else {
                        buf.push(chars[i].to_ascii_uppercase());
                    }
                    i += 1;
                } else {
                    // trailing mangle char with nothing after
                    buf.push(MANGLE_CHAR);
                }
            } else {
                buf.push(chars[i]);
                i += 1;
            }
        }
        buf
    }

    /// Returns `true` if `name` contains no uppercase characters, meaning
    /// it is a valid mangled name that can be safely demangled.
    pub fn is_valid_mangled_name(name: &str) -> bool {
        name.chars().all(|c| !c.is_ascii_uppercase())
    }

    /// Escape the hidden directory prefix character `~` so it is not
    /// confused with Ghidra's hidden directory convention.
    ///
    /// A leading `~` becomes `__` (double underscore after mangling).
    pub fn escape_hidden_prefix(name: &str) -> String {
        if name.starts_with('~') {
            format!("__{}", &name[1..])
        } else {
            name.to_string()
        }
    }

    /// Reverse of [`NamingUtilities::escape_hidden_prefix`].
    pub fn unescape_hidden_prefix(name: &str) -> String {
        if name.starts_with("__") {
            format!("~{}", &name[2..])
        } else {
            name.to_string()
        }
    }
}

// ============================================================================
// MD5Utilities
// ============================================================================

/// Provides static methods for computing MD5 hashes of files, streams,
/// strings, and binary data.
///
/// Corresponds to `ghidra.util.MD5Utilities`.
pub struct MD5Utilities;

impl MD5Utilities {
    /// Salt length used by Ghidra's password hashing (4 bytes).
    pub const SALT_LENGTH: usize = 4;

    /// Length of an unsalted MD5 hex string (32 characters).
    pub const UNSALTED_HASH_LENGTH: usize = 32;

    /// Length of a salted MD5 hex string (salt prefix + 32 hash chars = 36).
    pub const SALTED_HASH_LENGTH: usize = 36;

    // ------------------------------------------------------------------
    // Raw MD5 (no salt)
    // ------------------------------------------------------------------

    /// Generate an MD5 hash of `data` as a lowercase hex string.
    pub fn md5_hex(data: &[u8]) -> String {
        use md5::Digest;
        let digest = md5::Md5::digest(data);
        format!("{:x}", digest)
    }

    /// Generate an MD5 hash of a file's contents as a lowercase hex string.
    pub fn md5_file(path: &Path) -> io::Result<String> {
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(Self::md5_hex(&buf))
    }

    /// Generate an MD5 hash from a reader (reads until EOF).
    pub fn md5_reader<R: Read>(reader: &mut R) -> io::Result<String> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(Self::md5_hex(&buf))
    }

    /// Generate a combined MD5 hash from a list of strings.
    ///
    /// Each string is hashed in order; the final digest covers all of them
    /// concatenated.
    pub fn md5_strings(values: &[&str]) -> String {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        for v in values {
            hasher.update(v.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    // ------------------------------------------------------------------
    // Salted MD5
    // ------------------------------------------------------------------

    /// Generate a salted MD5 hash.
    ///
    /// The salt is prepended to the message before hashing. The returned
    /// string is `salt_hex (8 chars) + hash_hex (32 chars)` = 40 characters.
    pub fn salted_md5(salt: &[u8], msg: &[u8]) -> String {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(salt);
        hasher.update(msg);
        let hash = format!("{:x}", hasher.finalize());
        let salt_hex = hex_encode(salt);
        format!("{}{}", salt_hex, hash)
    }

    /// Generate a salted MD5 hash with a random 4-byte salt.
    ///
    /// Returns `salt_hex (8 chars) + hash_hex (32 chars)`.
    pub fn salted_md5_random(msg: &[u8]) -> String {
        let salt = random_salt();
        Self::salted_md5(&salt, msg)
    }

    /// Verify a salted MD5 hash.
    ///
    /// The first `SALT_LENGTH * 2` hex characters of `stored_hash` are the
    /// salt; the remainder is the expected hash.
    ///
    /// Returns `true` if the hash matches.
    pub fn verify_salted_md5(stored_hash: &str, msg: &[u8]) -> bool {
        let salt_hex_len = Self::SALT_LENGTH * 2;
        if stored_hash.len() < salt_hex_len {
            return false;
        }
        let salt_hex = &stored_hash[..salt_hex_len];
        let salt = match hex_decode(salt_hex) {
            Some(b) => b,
            None => return false,
        };
        let computed = Self::salted_md5(&salt, msg);
        constant_time_eq(stored_hash.as_bytes(), computed.as_bytes())
    }

    // ------------------------------------------------------------------
    // Hex dump
    // ------------------------------------------------------------------

    /// Convert binary data to a hex character string (lowercase).
    pub fn hex_dump(data: &[u8]) -> String {
        hex_encode(data)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Encode bytes as lowercase hex.
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decode a hex string to bytes. Returns `None` on invalid hex.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for chunk in chars.chunks(2) {
        let s: String = chunk.iter().collect();
        let b = u8::from_str_radix(&s, 16).ok()?;
        bytes.push(b);
    }
    Some(bytes)
}

/// Generate a random 4-byte salt.
fn random_salt() -> [u8; 4] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut salt = [0u8; 4];
    salt[0] = (nanos >> 24) as u8;
    salt[1] = (nanos >> 16) as u8;
    salt[2] = (nanos >> 8) as u8;
    salt[3] = nanos as u8;
    salt
}

/// Constant-time comparison to avoid timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // NamingUtilities tests
    // ------------------------------------------------------------------

    #[test]
    fn test_mangle_basic() {
        assert_eq!(NamingUtilities::mangle("Foo.exe"), "_foo.exe");
        assert_eq!(NamingUtilities::mangle("hello"), "hello");
        assert_eq!(NamingUtilities::mangle("AB"), "_a_b");
    }

    #[test]
    fn test_mangle_underscore() {
        assert_eq!(NamingUtilities::mangle("a_b"), "a__b");
        assert_eq!(NamingUtilities::mangle("_"), "__");
    }

    #[test]
    fn test_demangle_basic() {
        assert_eq!(NamingUtilities::demangle("_foo.exe"), "Foo.exe");
        assert_eq!(NamingUtilities::demangle("hello"), "hello");
        assert_eq!(NamingUtilities::demangle("_a_b"), "AB");
    }

    #[test]
    fn test_demangle_double_underscore() {
        assert_eq!(NamingUtilities::demangle("a__b"), "a_b");
        assert_eq!(NamingUtilities::demangle("__"), "_");
    }

    #[test]
    fn test_mangle_demangle_roundtrip() {
        let names = vec![
            "Foo.exe",
            "hello_world",
            "ALLCAPS",
            "MiXeD_CaSe",
            "_leading",
            "trailing_",
            "A_B_C",
        ];
        for name in names {
            let mangled = NamingUtilities::mangle(name);
            let demangled = NamingUtilities::demangle(&mangled);
            assert_eq!(demangled, name, "Roundtrip failed for '{}'", name);
        }
    }

    #[test]
    fn test_is_valid_mangled_name() {
        assert!(NamingUtilities::is_valid_mangled_name("_foo.exe"));
        assert!(NamingUtilities::is_valid_mangled_name("hello"));
        assert!(!NamingUtilities::is_valid_mangled_name("Hello"));
        assert!(!NamingUtilities::is_valid_mangled_name("fooBar"));
    }

    #[test]
    fn test_valid_project_name() {
        assert!(NamingUtilities::is_valid_project_name("MyProject"));
        assert!(NamingUtilities::is_valid_project_name("test-1.0"));
        assert!(NamingUtilities::is_valid_project_name("a b c"));
        assert!(!NamingUtilities::is_valid_project_name(""));
        assert!(!NamingUtilities::is_valid_project_name("   "));
        assert!(!NamingUtilities::is_valid_project_name(".hidden"));
        assert!(!NamingUtilities::is_valid_project_name("bad/name"));
        assert!(!NamingUtilities::is_valid_project_name("bad\\name"));
    }

    #[test]
    fn test_find_invalid_char() {
        assert_eq!(NamingUtilities::find_invalid_char("hello"), None);
        assert_eq!(NamingUtilities::find_invalid_char("hello world"), None);
        assert_eq!(NamingUtilities::find_invalid_char("bad/name"), Some('/'));
        assert_eq!(NamingUtilities::find_invalid_char("bad\\name"), Some('\\'));
        assert_eq!(NamingUtilities::find_invalid_char("bad:name"), Some(':'));
    }

    #[test]
    fn test_check_name_valid() {
        assert!(NamingUtilities::check_name("valid_name", "Test").is_ok());
        assert!(NamingUtilities::check_name("a", "Test").is_ok());
    }

    #[test]
    fn test_check_name_blank() {
        assert!(NamingUtilities::check_name("", "Test").is_err());
        assert!(NamingUtilities::check_name("   ", "Test").is_err());
    }

    #[test]
    fn test_check_name_dot_prefix() {
        assert!(NamingUtilities::check_name(".hidden", "Test").is_err());
        assert!(NamingUtilities::check_name(".", "Test").is_err());
        assert!(NamingUtilities::check_name("..", "Test").is_err());
    }

    #[test]
    fn test_check_name_invalid_chars() {
        assert!(NamingUtilities::check_name("bad/name", "Test").is_err());
        assert!(NamingUtilities::check_name("bad:name", "Test").is_err());
        assert!(NamingUtilities::check_name("bad*name", "Test").is_err());
    }

    #[test]
    fn test_escape_hidden_prefix() {
        assert_eq!(NamingUtilities::escape_hidden_prefix("~hidden"), "__hidden");
        assert_eq!(NamingUtilities::escape_hidden_prefix("normal"), "normal");
    }

    #[test]
    fn test_unescape_hidden_prefix() {
        assert_eq!(NamingUtilities::unescape_hidden_prefix("__hidden"), "~hidden");
        assert_eq!(NamingUtilities::unescape_hidden_prefix("normal"), "normal");
    }

    #[test]
    fn test_escape_unescape_roundtrip() {
        let names = vec!["~hidden", "normal", "~test~", "__already"];
        for name in names {
            let escaped = NamingUtilities::escape_hidden_prefix(name);
            let unescaped = NamingUtilities::unescape_hidden_prefix(&escaped);
            assert_eq!(
                unescaped, name,
                "Escape/unescape roundtrip failed for '{}'",
                name
            );
        }
    }

    // ------------------------------------------------------------------
    // MD5Utilities tests
    // ------------------------------------------------------------------

    #[test]
    fn test_md5_hex_basic() {
        let hash = MD5Utilities::md5_hex(b"hello");
        assert_eq!(hash.len(), 32);
        // Known MD5 of "hello"
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_md5_hex_empty() {
        let hash = MD5Utilities::md5_hex(b"");
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_strings() {
        let hash = MD5Utilities::md5_strings(&["hello", " ", "world"]);
        assert_eq!(hash.len(), 32);
        // Should be same as md5 of "hello world"
        let expected = MD5Utilities::md5_hex(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let data = vec![0x00, 0x0F, 0xFF, 0xAB, 0xCD, 0xEF];
        let hex = hex_encode(&data);
        assert_eq!(hex, "000fffabcdef");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("xyz").is_none());
        assert!(hex_decode("0").is_none()); // odd length
        assert!(hex_decode("").is_some()); // empty = empty
    }

    #[test]
    fn test_salted_md5() {
        let salt = b"salt";
        let msg = b"password";
        let hash = MD5Utilities::salted_md5(salt, msg);
        assert_eq!(hash.len(), 40); // 8 salt hex + 32 hash hex

        // Verify should succeed
        assert!(MD5Utilities::verify_salted_md5(&hash, msg));
        // Wrong password should fail
        assert!(!MD5Utilities::verify_salted_md5(&hash, b"wrong"));
    }

    #[test]
    fn test_salted_md5_random() {
        let hash1 = MD5Utilities::salted_md5_random(b"test");
        let hash2 = MD5Utilities::salted_md5_random(b"test");
        // Different random salts => different hashes (very high probability)
        assert_ne!(hash1, hash2);
        // But both should verify
        assert!(MD5Utilities::verify_salted_md5(&hash1, b"test"));
        assert!(MD5Utilities::verify_salted_md5(&hash2, b"test"));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_md5_file() {
        let dir = std::env::temp_dir().join("ghidra_test_md5util");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let hash = MD5Utilities::md5_file(&path).unwrap();
        let expected = MD5Utilities::md5_hex(b"hello world");
        assert_eq!(hash, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_md5_reader() {
        let data = b"test data for reader";
        let mut reader: &[u8] = data;
        let hash = MD5Utilities::md5_reader(&mut reader).unwrap();
        let expected = MD5Utilities::md5_hex(data);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hex_dump() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(MD5Utilities::hex_dump(&data), "deadbeef");
    }
}
