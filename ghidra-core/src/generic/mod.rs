//! Generic utilities for Ghidra Rust.
//!
//! Provides logging, error reporting, string/numeric utilities, file
//! operations, collection helpers, date formatting, task monitoring,
//! and system information.

pub mod system;
pub mod task;

pub use system::SystemInfo;
pub use task::{CancelledError, ProgressMonitor as TaskProgressMonitor, Worker};
pub use task::TaskMonitor as Monitor;

use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ======================================================================
// Logging macros
// ======================================================================

/// Log an info-level message. Delegates to the `log` crate.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        log::info!($($arg)*)
    };
}

/// Log a warning-level message. Delegates to the `log` crate.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        log::warn!($($arg)*)
    };
}

/// Log an error-level message. Delegates to the `log` crate.
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        log::error!($($arg)*)
    };
}

/// Log a debug-level message. Delegates to the `log` crate.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*)
    };
}

/// Log a trace-level message. Delegates to the `log` crate.
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        log::trace!($($arg)*)
    };
}

// ======================================================================
// MessageType / ErrorLogger / Msg
// ======================================================================

/// Logging severity levels (Ghidra `MessageType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageType {
    Info,
    Alert,
    Warning,
    Error,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Info => write!(f, "INFO"),
            MessageType::Alert => write!(f, "ALERT"),
            MessageType::Warning => write!(f, "WARNING"),
            MessageType::Error => write!(f, "ERROR"),
        }
    }
}

/// Trait for error logging (Ghidra `ErrorLogger`).
pub trait ErrorLogger: Send + Sync {
    fn trace(&self, originator: &str, message: &str);
    fn trace_with_error(
        &self,
        originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    );
    fn debug(&self, originator: &str, message: &str);
    fn debug_with_error(
        &self,
        originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    );
    fn info(&self, originator: &str, message: &str);
    fn info_with_error(
        &self,
        originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    );
    fn warn(&self, originator: &str, message: &str);
    fn warn_with_error(
        &self,
        originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    );
    fn error(&self, originator: &str, message: &str);
    fn error_with_error(
        &self,
        originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    );
}

/// Default error logger that writes to stdout/stderr.
pub struct DefaultErrorLogger;

impl ErrorLogger for DefaultErrorLogger {
    fn trace(&self, _originator: &str, _message: &str) {}
    fn trace_with_error(
        &self,
        _originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    ) {
        if let Some(e) = error {
            eprintln!("TRACE: {} | {}", message, e);
        }
    }
    fn debug(&self, _originator: &str, message: &str) {
        log::debug!("{}", message);
    }
    fn debug_with_error(
        &self,
        _originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    ) {
        if let Some(e) = error {
            log::debug!("{} | {}", message, e);
        } else {
            log::debug!("{}", message);
        }
    }
    fn info(&self, _originator: &str, message: &str) {
        log::info!("{}", message);
    }
    fn info_with_error(
        &self,
        _originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    ) {
        if let Some(e) = error {
            log::info!("{} | {}", message, e);
        } else {
            log::info!("{}", message);
        }
    }
    fn warn(&self, _originator: &str, message: &str) {
        log::warn!("{}", message);
    }
    fn warn_with_error(
        &self,
        _originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    ) {
        if let Some(e) = error {
            log::warn!("{} | {}", message, e);
        } else {
            log::warn!("{}", message);
        }
    }
    fn error(&self, _originator: &str, message: &str) {
        log::error!("{}", message);
    }
    fn error_with_error(
        &self,
        _originator: &str,
        message: &str,
        error: Option<&(dyn std::error::Error + 'static)>,
    ) {
        if let Some(e) = error {
            log::error!("{} | {}", message, e);
        } else {
            log::error!("{}", message);
        }
    }
}

/// Global error logger (Ghidra `Msg` class).
pub mod msg {
    use super::*;
    use std::sync::RwLock;

    use std::sync::LazyLock;
    static LOGGER: LazyLock<RwLock<Box<dyn ErrorLogger>>> =
        LazyLock::new(|| RwLock::new(Box::new(super::DefaultErrorLogger)));

    pub fn set_error_logger(logger: Box<dyn ErrorLogger>) {
        if let Ok(mut g) = LOGGER.write() {
            *g = logger;
        }
    }

    pub fn out(message: &str) {
        eprintln!("{}", message);
    }

    pub fn trace(originator: &str, message: &str) {
        if let Ok(logger) = LOGGER.read() {
            logger.trace(originator, message);
        }
    }
    pub fn trace_err(
        originator: &str,
        message: &str,
        error: &(dyn std::error::Error + 'static),
    ) {
        if let Ok(logger) = LOGGER.read() {
            logger.trace_with_error(originator, message, Some(error));
        }
    }
    pub fn debug(originator: &str, message: &str) {
        if let Ok(logger) = LOGGER.read() {
            logger.debug(originator, message);
        }
    }
    pub fn debug_err(
        originator: &str,
        message: &str,
        error: &(dyn std::error::Error + 'static),
    ) {
        if let Ok(logger) = LOGGER.read() {
            logger.debug_with_error(originator, message, Some(error));
        }
    }
    pub fn info(originator: &str, message: &str) {
        if let Ok(logger) = LOGGER.read() {
            logger.info(originator, message);
        }
    }
    pub fn info_err(
        originator: &str,
        message: &str,
        error: &(dyn std::error::Error + 'static),
    ) {
        if let Ok(logger) = LOGGER.read() {
            logger.info_with_error(originator, message, Some(error));
        }
    }
    pub fn warn(originator: &str, message: &str) {
        if let Ok(logger) = LOGGER.read() {
            logger.warn(originator, message);
        }
    }
    pub fn warn_err(
        originator: &str,
        message: &str,
        error: &(dyn std::error::Error + 'static),
    ) {
        if let Ok(logger) = LOGGER.read() {
            logger.warn_with_error(originator, message, Some(error));
        }
    }
    pub fn error(originator: &str, message: &str) {
        if let Ok(logger) = LOGGER.read() {
            logger.error(originator, message);
        }
    }
    pub fn error_err(
        originator: &str,
        message: &str,
        error: &(dyn std::error::Error + 'static),
    ) {
        if let Ok(logger) = LOGGER.read() {
            logger.error_with_error(originator, message, Some(error));
        }
    }

    pub fn show_info(originator: &str, title: &str, message: &str) {
        let full = format!("[{}] {}", title, message);
        if crate::generic::system::is_headless() {
            info(originator, &full);
        } else {
            info(originator, &full);
        }
    }

    pub fn show_warn(originator: &str, title: &str, message: &str) {
        let full = format!("[{}] {}", title, message);
        warn(originator, &full);
    }

    pub fn show_error(originator: &str, title: &str, message: &str) {
        let full = format!("[{}] {}", title, message);
        error(originator, &full);
    }

    pub fn show_error_err(
        originator: &str,
        title: &str,
        message: &str,
        error: &(dyn std::error::Error + 'static),
    ) {
        let full = format!("[{}] {}", title, message);
        error_err(originator, &full, error);
    }
}

// ======================================================================
// Numeric utilities
// ======================================================================

/// Numeric parsing and formatting (Ghidra `NumericUtilities`).
pub mod numeric {
    use num::bigint::BigInt;
    use num::traits::{Num, Zero};

    pub fn max_unsigned_long() -> BigInt {
        BigInt::from(u64::MAX)
    }

    pub fn max_signed_long() -> BigInt {
        BigInt::from(i64::MAX)
    }

    pub const HEX_PREFIX: &str = "0x";
    pub const BIN_PREFIX: &str = "0b";
    pub const OCT_PREFIX: &str = "0";

    /// Parse a decimal or hex string as an `i32`.
    pub fn parse_int(s: &str) -> Result<i32, std::num::ParseIntError> {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
            i32::from_str_radix(hex, 16)
        } else {
            s.parse::<i32>()
        }
    }

    /// Parse with a default value on failure.
    pub fn parse_int_default(s: &str, default_val: i32) -> i32 {
        parse_int(s).unwrap_or(default_val)
    }

    /// Parse a decimal or hex string as an `i64`.
    pub fn parse_long(s: &str) -> Result<i64, std::num::ParseIntError> {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16)
        } else {
            s.parse::<i64>()
        }
    }

    /// Parse with a default value.
    pub fn parse_long_default(s: &str, default_val: i64) -> i64 {
        parse_long(s).unwrap_or(default_val)
    }

    /// Parse a hex string as `u64`.
    pub fn parse_hex_long(s: &str) -> Result<u64, std::num::ParseIntError> {
        let s = s.trim();
        let s = s
            .strip_prefix("0x")
            .or(s.strip_prefix("0X"))
            .unwrap_or(s);
        u64::from_str_radix(s, 16)
    }

    /// Parse hex/binary/octal/decimal into `BigInt`.
    pub fn decode_big_integer(s: &str) -> Result<BigInt, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty string".to_string());
        }
        let (negative, rest) = if let Some(r) = s.strip_prefix('-') {
            (true, r)
        } else if let Some(r) = s.strip_prefix('+') {
            (false, r)
        } else {
            (false, s)
        };
        let magnitude = decode_magnitude(rest)?;
        Ok(if negative { -magnitude } else { magnitude })
    }

    fn decode_magnitude(s: &str) -> Result<BigInt, String> {
        if s == "0" {
            return Ok(BigInt::zero());
        }
        if let Some(hex) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
            return BigInt::from_str_radix(hex, 16).map_err(|e| e.to_string());
        }
        if let Some(bin) = s.strip_prefix("0b").or(s.strip_prefix("0B")) {
            return BigInt::from_str_radix(bin, 2).map_err(|e| e.to_string());
        }
        if s.starts_with('0') && s.len() > 1 {
            return BigInt::from_str_radix(&s[1..], 8).map_err(|e| e.to_string());
        }
        BigInt::from_str_radix(s, 10).map_err(|e| e.to_string())
    }

    /// Format u64 as "0x..." hex string.
    pub fn to_hex_string(value: u64) -> String {
        format!("0x{:x}", value)
    }

    /// Format i64 as signed hex string.
    pub fn to_signed_hex_string(value: i64) -> String {
        if value < 0 {
            format!("-0x{:x}", value.unsigned_abs())
        } else {
            format!("0x{:x}", value as u64)
        }
    }

    /// Convert unsigned u64 (stored as i64) to BigInt.
    pub fn unsigned_long_to_big_integer(value: i64) -> BigInt {
        if value >= 0 {
            BigInt::from(value)
        } else {
            BigInt::from(u64::MAX) + BigInt::from(value) + 1u64
        }
    }

    /// Convert bytes to hex string.
    pub fn convert_bytes_to_string(bytes: &[u8], delimiter: Option<&str>) -> String {
        let delim = delimiter.unwrap_or("");
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(delim)
    }

    /// Convert hex string (with optional spaces/commas) to bytes.
    pub fn convert_string_to_bytes(hex_string: &str) -> Result<Vec<u8>, String> {
        let cleaned: String = hex_string
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ',')
            .collect();
        if cleaned.len() % 2 != 0 {
            return Err("Hex string must have an even number of characters".to_string());
        }
        (0..cleaned.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&cleaned[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex: {}", e))
            })
            .collect()
    }
}

pub use numeric::{
    convert_bytes_to_string, convert_string_to_bytes, decode_big_integer,
};

// ======================================================================
// String utilities
// ======================================================================

/// String manipulation utilities (Ghidra `StringUtilities`).
pub mod string_utils {
    use regex::Regex;
    use std::collections::HashMap;
    use std::sync::LazyLock;

    pub const DEFAULT_TAB_SIZE: usize = 8;

    pub fn line_separator() -> &'static str {
        if cfg!(windows) {
            "\r\n"
        } else {
            "\n"
        }
    }

    pub const UNICODE_BE_BOM: u32 = 0xFEFF;
    pub const UNICODE_LE16_BOM: u32 = 0xFFFE;
    pub const UNICODE_LE32_BOM: u32 = 0xFFFE_0000;
    pub const UNICODE_REPLACEMENT: u32 = 0xFFFD;

    static CONTROL_TO_ESCAPE: LazyLock<HashMap<char, &'static str>> = LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert('\t', "\\t");
        m.insert('\u{08}', "\\b");
        m.insert('\r', "\\r");
        m.insert('\n', "\\n");
        m.insert('\u{0C}', "\\f");
        m.insert('\\', "\\\\");
        m.insert('\u{0B}', "\\v");
        m.insert('\u{07}', "\\a");
        m
    });

    static ESCAPE_TO_CONTROL: LazyLock<HashMap<&'static str, char>> = LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert("\\t", '\t');
        m.insert("\\b", '\u{08}');
        m.insert("\\r", '\r');
        m.insert("\\n", '\n');
        m.insert("\\f", '\u{0C}');
        m.insert("\\\\", '\\');
        m.insert("\\v", '\u{0B}');
        m.insert("\\a", '\u{07}');
        m.insert("\\0", '\0');
        m
    });

    static DOUBLE_QUOTED_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^"((?:[^\\"]|\\.)*)"$"#).unwrap());

    pub fn is_control_char_or_backslash(c: char) -> bool {
        CONTROL_TO_ESCAPE.contains_key(&c)
    }

    pub fn is_displayable(c: u32) -> bool {
        (0x20..0x7F).contains(&c)
    }

    pub fn is_ascii_char(c: u32) -> bool {
        (0x20..=0x7F).contains(&c)
    }

    pub fn is_valid_c_language_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    pub fn is_all_blank(strings: &[&str]) -> bool {
        strings.iter().all(|s| s.trim().is_empty())
    }

    pub fn is_double_quoted(s: &str) -> bool {
        DOUBLE_QUOTED_RE.is_match(s)
    }

    pub fn extract_from_double_quotes(s: &str) -> String {
        if let Some(caps) = DOUBLE_QUOTED_RE.captures(s) {
            caps.get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| s.to_string())
        } else {
            s.to_string()
        }
    }

    pub fn count_occurrences(s: &str, c: char) -> usize {
        s.chars().filter(|&ch| ch == c).count()
    }

    pub fn equals(s1: &str, s2: &str, case_sensitive: bool) -> bool {
        if case_sensitive {
            s1 == s2
        } else {
            s1.eq_ignore_ascii_case(s2)
        }
    }

    pub fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
        let lower_s = s.to_ascii_lowercase();
        let lower_p = prefix.to_ascii_lowercase();
        lower_s.starts_with(&lower_p)
    }

    pub fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
        let lower_s = s.to_ascii_lowercase();
        let lower_suf = suffix.to_ascii_lowercase();
        lower_s.ends_with(&lower_suf)
    }

    pub fn contains_all(to_search: &str, searches: &[&str]) -> bool {
        if to_search.is_empty() || searches.is_empty() {
            return false;
        }
        searches.iter().all(|s| to_search.contains(s))
    }

    pub fn contains_any_ignore_case(to_search: &str, searches: &[&str]) -> bool {
        if to_search.is_empty() {
            return false;
        }
        let lower = to_search.to_lowercase();
        searches
            .iter()
            .any(|s| lower.contains(&s.to_lowercase()))
    }

    pub fn convert_tabs_to_spaces(s: &str, tab_size: usize) -> String {
        let mut result = String::with_capacity(s.len());
        let mut line_pos = 0usize;
        for c in s.chars() {
            if c == '\t' {
                let n_spaces = tab_size - (line_pos % tab_size);
                result.push_str(&" ".repeat(n_spaces));
                line_pos += n_spaces;
            } else {
                result.push(c);
                line_pos += 1;
                if c == '\n' {
                    line_pos = 0;
                }
            }
        }
        result
    }

    pub fn to_lines(s: &str, preserve_tokens: bool) -> Vec<String> {
        if preserve_tokens {
            s.split('\n').map(|l| l.to_string()).collect()
        } else {
            s.split('\n')
                .filter(|l| !l.is_empty())
                .map(|l| l.to_string())
                .collect()
        }
    }

    pub fn pad(source: &str, filler: char, length: isize) -> String {
        let len = length.unsigned_abs() as usize;
        let source_len = source.chars().count();
        if len <= source_len {
            return source.to_string();
        }
        let n = len - source_len;
        let pad_str: String = std::iter::repeat(filler).take(n).collect();
        if length >= 0 {
            format!("{}{}", pad_str, source)
        } else {
            format!("{}{}", source, pad_str)
        }
    }

    pub fn indent_lines(s: &str, indent: &str) -> String {
        let lines: Vec<&str> = s.split('\n').filter(|l| !l.is_empty()).collect();
        let mut result = String::new();
        for line in &lines {
            result.push_str(indent);
            result.push_str(line);
            result.push('\n');
        }
        if !result.is_empty() {
            result.pop();
        }
        result
    }

    pub fn trim(s: &str, max: usize) -> String {
        let ellipsis = "...";
        let minimum = ellipsis.len() + 1;
        assert!(max >= minimum, "max cannot be less than {}", minimum);
        if s.len() > max {
            format!("{}{}", &s[..max - ellipsis.len()], ellipsis)
        } else {
            s.to_string()
        }
    }

    pub fn trim_middle(s: &str, max: usize) -> String {
        let ellipsis = "...";
        if s.len() <= max {
            return s.to_string();
        }
        let minimum = ellipsis.len() + 2;
        assert!(max >= minimum, "max cannot be less than {}", minimum);
        let to_remove = (s.len() - max) + ellipsis.len();
        let to_keep = s.len() - to_remove;
        let lhs_size = to_keep / 2;
        let rhs_size = if to_keep % 2 != 0 {
            lhs_size + 1
        } else {
            lhs_size
        };
        format!(
            "{}{}{}",
            &s[..lhs_size],
            ellipsis,
            &s[s.len() - rhs_size..]
        )
    }

    pub fn get_last_word(s: &str, separator: &str) -> String {
        s.split(separator)
            .filter(|p| !p.is_empty())
            .last()
            .unwrap_or("")
            .to_string()
    }

    /// Generate a quoted string from bytes (C escape conventions).
    pub fn to_quoted_string(bytes: &[u8]) -> String {
        let mut builder = String::new();
        for &b in bytes {
            append_char_escaped(b as u32, 1, &mut builder);
        }
        if bytes.len() == 1 {
            let escaped = builder.replace('\'', "\\'");
            format!("'{}'", escaped)
        } else {
            let escaped = builder.replace('"', "\\\"");
            format!("\"{}\"", escaped)
        }
    }

    fn append_char_escaped(c: u32, char_size: usize, builder: &mut String) {
        if let Some(&esc) = CONTROL_TO_ESCAPE.get(&char::from_u32(c).unwrap_or('\0')) {
            builder.push_str(esc);
        } else if (0x20..=0x7F).contains(&c) {
            builder.push(char::from_u32(c).unwrap_or('?'));
        } else if char_size <= 1 {
            builder.push_str(&format!("\\x{:02x}", c & 0xFF));
        } else if char_size == 2 {
            builder.push_str(&format!("\\u{:04x}", c & 0xFFFF));
        } else {
            builder.push_str(&format!("\\U{:08x}", c));
        }
    }

    /// Convert escape sequences to control characters.
    pub fn convert_escape_sequences(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if i + 1 < chars.len() {
                let pair: String = chars[i..i + 2].iter().collect();
                if let Some(&c) = ESCAPE_TO_CONTROL.get(pair.as_str()) {
                    result.push(c);
                    i += 2;
                    continue;
                }
            }
            if i + 3 < chars.len() && chars[i] == '\\' && chars[i + 1] == 'x' {
                let hex_str: String = chars[i + 2..i + 4].iter().collect();
                if let Ok(val) = u8::from_str_radix(&hex_str, 16) {
                    result.push(val as char);
                    i += 4;
                    continue;
                }
            }
            if i + 5 < chars.len() && chars[i] == '\\' && chars[i + 1] == 'u' {
                let hex_str: String = chars[i + 2..i + 6].iter().collect();
                if let Ok(val) = u32::from_str_radix(&hex_str, 16) {
                    if let Some(c) = char::from_u32(val) {
                        result.push(c);
                        i += 6;
                        continue;
                    }
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        result
    }

    /// Convert control characters to escape sequences.
    pub fn convert_control_chars_to_escape_sequences(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for c in s.chars() {
            if let Some(&esc) = CONTROL_TO_ESCAPE.get(&c) {
                result.push_str(esc);
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Merge two strings.
    pub fn merge_strings(s1: Option<&str>, s2: Option<&str>) -> Option<String> {
        match (s1, s2) {
            (None, None) => None,
            (Some(a), None) if !a.is_empty() => Some(a.to_string()),
            (None, Some(b)) if !b.is_empty() => Some(b.to_string()),
            (Some(a), Some(b)) => {
                if a.is_empty() && b.is_empty() {
                    Some(String::new())
                } else if a.is_empty() {
                    Some(b.to_string())
                } else if b.is_empty() {
                    Some(a.to_string())
                } else if a.contains(b) {
                    Some(a.to_string())
                } else if b.contains(a) {
                    Some(b.to_string())
                } else {
                    Some(format!("{}\n{}", a, b))
                }
            }
            (Some(_), _) => None,
            (_, Some(_)) => None,
        }
    }

    pub fn fix_multiple_asterisks(value: &str) -> String {
        let re = Regex::new(r"\*{2,}").unwrap();
        re.replace_all(value, "*").to_string()
    }

    pub fn trim_trailing_nulls(s: &str) -> String {
        s.trim_end_matches('\0').to_string()
    }

    pub fn whitespace_to_underscores(s: &str) -> String {
        let re = Regex::new(r"[\x00-\x20]").unwrap();
        re.replace_all(s.trim(), "_").to_string()
    }

    pub fn wrap_to_width(s: &str, width: usize) -> String {
        if width == 0 {
            return s.to_string();
        }
        let mut result = String::new();
        let mut line_len = 0;
        for word in s.split_whitespace() {
            if line_len + word.len() + 1 > width && line_len > 0 {
                result.push('\n');
                line_len = 0;
            }
            if line_len > 0 {
                result.push(' ');
                line_len += 1;
            }
            result.push_str(word);
            line_len += word.len();
        }
        result
    }
}

pub use string_utils::{
    convert_control_chars_to_escape_sequences, convert_escape_sequences,
};

// ======================================================================
// File utilities
// ======================================================================

/// File and I/O operations (Ghidra `FileUtilities`).
pub mod file_utils {
    use super::*;

    pub const IO_BUFFER_SIZE: usize = 32 * 1024;
    pub const MAX_FILE_SIZE: u64 = 0x10000000;

    pub fn get_bytes_from_file(path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    pub fn get_bytes_from_file_range(
        path: &Path,
        offset: u64,
        length: u64,
    ) -> io::Result<Vec<u8>> {
        if length > MAX_FILE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File too large: max {} bytes", MAX_FILE_SIZE),
            ));
        }
        use std::io::Seek;
        let mut file = fs::File::open(path)?;
        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; length as usize];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn get_bytes_from_stream<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    }

    pub fn get_bytes_from_stream_exact<R: Read>(
        reader: &mut R,
        expected_length: usize,
    ) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; expected_length];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
        fs::write(path, bytes)
    }

    pub fn get_lines(path: &Path) -> io::Result<Vec<String>> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        reader.lines().collect()
    }

    pub fn get_lines_from_reader<R: Read>(reader: R) -> io::Result<Vec<String>> {
        BufReader::new(reader).lines().collect()
    }

    pub fn get_text(path: &Path) -> io::Result<String> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_FILE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("File too large: {} bytes", metadata.len()),
            ));
        }
        fs::read_to_string(path)
    }

    pub fn get_text_from_reader<R: Read>(reader: R) -> io::Result<String> {
        let reader = BufReader::new(reader);
        let mut result = String::new();
        for line in reader.lines() {
            result.push_str(&line?);
            result.push('\n');
        }
        Ok(result)
    }

    pub fn write_lines_to_file(path: &Path, lines: &[String]) -> io::Result<()> {
        let mut file = fs::File::create(path)?;
        for line in lines {
            writeln!(file, "{}", line)?;
        }
        Ok(())
    }

    pub fn write_string_to_file(path: &Path, s: &str) -> io::Result<()> {
        fs::write(path, s)
    }

    pub fn copy_file(from: &Path, to: &Path) -> io::Result<u64> {
        fs::copy(from, to)
    }

    pub fn copy_stream_to_file<R: Read>(
        reader: &mut R,
        to: &Path,
        append: bool,
    ) -> io::Result<u64> {
        let mut file = if append {
            fs::OpenOptions::new().create(true).append(true).open(to)?
        } else {
            fs::File::create(to)?
        };
        copy_stream_to_stream(reader, &mut file)
    }

    pub fn copy_stream_to_stream<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<u64> {
        let mut buf = vec![0u8; IO_BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            total += n as u64;
        }
        writer.flush()?;
        Ok(total)
    }

    pub fn create_dir(path: &Path) -> bool {
        if path.is_dir() {
            return true;
        }
        fs::create_dir(path).is_ok()
    }

    pub fn mkdirs(path: &Path) -> bool {
        if path.is_dir() {
            return true;
        }
        if let Some(parent) = path.parent() {
            if !mkdirs(parent) {
                return false;
            }
        }
        create_dir(path)
    }

    pub fn delete_dir(path: &Path) -> io::Result<bool> {
        if !path.exists() {
            return Ok(true);
        }
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    delete_dir(&entry_path)?;
                } else {
                    fs::remove_file(&entry_path)?;
                }
            }
        }
        fs::remove_dir(path)?;
        Ok(true)
    }

    pub fn copy_dir(from: &Path, to: &Path) -> io::Result<usize> {
        if !from.exists() || !from.is_dir() {
            return Ok(0);
        }
        mkdirs(to);
        let mut count = 0;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let path = entry.path();
            let dest = to.join(path.file_name().unwrap());
            if path.is_dir() {
                count += copy_dir(&path, &dest)?;
            } else {
                fs::copy(&path, &dest)?;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn is_empty(path: &Path) -> bool {
        path.is_file()
            && path
                .metadata()
                .map(|m| m.len() == 0)
                .unwrap_or(false)
    }

    pub fn starts_with(parent: &str, other: &str) -> bool {
        Path::new(other).starts_with(Path::new(parent))
    }

    pub fn is_path_contained_within(parent: &Path, other: &Path) -> bool {
        if let (Ok(canon_parent), Ok(canon_other)) =
            (parent.canonicalize(), other.canonicalize())
        {
            canon_other.starts_with(&canon_parent)
        } else {
            other.starts_with(parent)
        }
    }

    pub fn relativize_path(parent: &Path, child: &Path) -> Option<String> {
        if let (Ok(canon_parent), Ok(canon_child)) =
            (parent.canonicalize(), child.canonicalize())
        {
            canon_child
                .strip_prefix(&canon_parent)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        }
    }

    pub fn format_length(length: u64) -> String {
        if length < 1000 {
            format!("{}B", length)
        } else if length < 1_000_000 {
            format!("{:.1}KB", length as f64 / 1000.0)
        } else {
            format!("{:.1}MB", length as f64 / 1_000_000.0)
        }
    }

    pub fn list_files(path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                files.push(entry?.path());
            }
        }
        Ok(files)
    }
}

pub use file_utils::{
    copy_file, get_bytes_from_file, get_lines, get_text, write_bytes,
};

// ======================================================================
// Collection utilities
// ======================================================================

/// Collection helper functions (Ghidra `CollectionUtils`).
pub mod collection_utils {
    pub fn as_set<T: Eq + std::hash::Hash + Clone>(
        items: &[T],
    ) -> std::collections::HashSet<T> {
        items.iter().cloned().collect()
    }

    pub fn as_set_from_iter<T: Eq + std::hash::Hash>(
        iter: impl IntoIterator<Item = T>,
    ) -> std::collections::HashSet<T> {
        iter.into_iter().collect()
    }

    pub fn as_list<T: Clone>(items: &[T]) -> Vec<T> {
        items.to_vec()
    }

    pub fn as_list_from_iter<T>(iter: impl IntoIterator<Item = T>) -> Vec<T> {
        iter.into_iter().collect()
    }

    pub fn as_list_opt<T: Clone>(opt: Option<&Vec<T>>) -> Vec<T> {
        opt.cloned().unwrap_or_default()
    }

    pub fn is_one_of<T: PartialEq>(item: &T, possibilities: &[T]) -> bool {
        possibilities.iter().any(|p| p == item)
    }

    pub fn is_all_none<T>(items: &[Option<T>]) -> bool {
        items.iter().all(|x| x.is_none())
    }

    pub fn is_blank<T>(items: Option<&[T]>) -> bool {
        items.map_or(true, |v| v.is_empty())
    }

    pub fn any<T: Clone>(items: &[T]) -> Option<T> {
        items.first().cloned()
    }

    pub fn get<T: Clone>(items: &[T]) -> Option<T> {
        if items.len() == 1 {
            items.first().cloned()
        } else {
            None
        }
    }
}

// ======================================================================
// Date utilities
// ======================================================================

/// Date formatting and time utilities (Ghidra `DateUtils`).
pub mod date_utils {
    use chrono::{Datelike, Duration, Local, NaiveDate, NaiveDateTime, Weekday};

    pub const MS_PER_SEC: i64 = 1000;
    pub const MS_PER_MIN: i64 = MS_PER_SEC * 60;
    pub const MS_PER_HOUR: i64 = MS_PER_MIN * 60;
    pub const MS_PER_DAY: i64 = MS_PER_HOUR * 24;

    pub const DATE_TIME_FORMAT: &str = "%b %d, %Y %I:%M %p";
    pub const DATE_FORMAT: &str = "%m/%d/%Y";
    pub const TIME_FORMAT: &str = "%-H:%M";

    pub fn format_date_timestamp(dt: &NaiveDateTime) -> String {
        dt.format(DATE_TIME_FORMAT).to_string()
    }

    pub fn format_date(date: &NaiveDate) -> String {
        date.format(DATE_FORMAT).to_string()
    }

    pub fn format_current_time() -> String {
        let now: chrono::DateTime<Local> = Local::now();
        now.format(TIME_FORMAT).to_string()
    }

    pub fn get_date(year: i32, month: u32, day: u32) -> Option<NaiveDate> {
        NaiveDate::from_ymd_opt(year, month, day)
    }

    pub fn get_days_between(d1: NaiveDate, d2: NaiveDate) -> i64 {
        let (start, end) = if d1 <= d2 { (d1, d2) } else { (d2, d1) };
        (end - start).num_days()
    }

    pub fn get_business_days_between(d1: NaiveDate, d2: NaiveDate) -> i64 {
        let (start, end) = if d1 <= d2 { (d1, d2) } else { (d2, d1) };
        let mut current = start;
        let mut days = 0;
        while current < end {
            current += Duration::days(1);
            if is_business_day(current) {
                days += 1;
            }
        }
        days
    }

    pub fn is_weekend(date: NaiveDate) -> bool {
        matches!(date.weekday(), Weekday::Sat | Weekday::Sun)
    }

    pub fn is_business_day(date: NaiveDate) -> bool {
        !is_weekend(date) && !is_us_holiday(date)
    }

    /// US federal holiday detection (observed).
    pub fn is_us_holiday(date: NaiveDate) -> bool {
        let year = date.year();
        if is_observed_holiday(date, year, 1, 1) {
            return true;
        }
        if date == nth_weekday_of_month(year, 1, Weekday::Mon, 3) {
            return true;
        }
        if date == nth_weekday_of_month(year, 2, Weekday::Mon, 3) {
            return true;
        }
        if date == last_weekday_of_month(year, 5, Weekday::Mon) {
            return true;
        }
        if is_observed_holiday(date, year, 7, 4) {
            return true;
        }
        if date == nth_weekday_of_month(year, 9, Weekday::Mon, 1) {
            return true;
        }
        if date == nth_weekday_of_month(year, 10, Weekday::Mon, 2) {
            return true;
        }
        if is_observed_holiday(date, year, 11, 11) {
            return true;
        }
        if date == nth_weekday_of_month(year, 11, Weekday::Thu, 4) {
            return true;
        }
        if is_observed_holiday(date, year, 12, 25) {
            return true;
        }
        false
    }

    fn is_observed_holiday(date: NaiveDate, year: i32, month: u32, day: u32) -> bool {
        let holiday = NaiveDate::from_ymd_opt(year, month, day).unwrap();
        match holiday.weekday() {
            Weekday::Sat => date == holiday - Duration::days(1),
            Weekday::Sun => date == holiday + Duration::days(1),
            _ => date == holiday,
        }
    }

    fn nth_weekday_of_month(
        year: i32,
        month: u32,
        weekday: Weekday,
        n: u32,
    ) -> NaiveDate {
        let first = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
        let days_until = ((weekday.num_days_from_monday() as i64
            - first.weekday().num_days_from_monday() as i64
            + 7)
            % 7) as i64;
        first + Duration::days(days_until + (n as i64 - 1) * 7)
    }

    fn last_weekday_of_month(year: i32, month: u32, weekday: Weekday) -> NaiveDate {
        let next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap()
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap()
        };
        let last_day = next_month - Duration::days(1);
        let days_back = ((last_day.weekday().num_days_from_monday() as i64
            - weekday.num_days_from_monday() as i64
            + 7)
            % 7) as i64;
        last_day - Duration::days(days_back)
    }

    /// Format a millisecond duration as human-readable string.
    pub fn format_duration(millis: i64) -> String {
        let mut ms = millis;
        let days = ms / MS_PER_DAY;
        ms %= MS_PER_DAY;
        let hours = ms / MS_PER_HOUR;
        ms %= MS_PER_HOUR;
        let minutes = ms / MS_PER_MIN;
        ms %= MS_PER_MIN;
        let seconds = ms / MS_PER_SEC;

        let mut parts = Vec::new();
        if days > 0 {
            parts.push(format!("{} days", days));
        }
        if hours > 0 || !parts.is_empty() {
            parts.push(format!("{} hours", hours));
        }
        if minutes > 0 || !parts.is_empty() {
            parts.push(format!("{} mins", minutes));
        }
        parts.push(format!("{} secs", seconds));
        parts.join(", ")
    }
}

// ======================================================================
// TaskMonitor trait
// ======================================================================

/// Trait for cooperative cancellation and progress reporting.
///
/// This is the primary interface for long-running operations that need
/// cancellation support and progress feedback. Implementations should be
/// thread-safe (`Send + Sync`).
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::{TaskMonitor, CancelledException};
///
/// fn do_work(monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
///     monitor.set_message("Starting work...");
///     monitor.set_progress(0);
///     for i in 0..100 {
///         monitor.check_cancelled()?;
///         monitor.set_progress(i);
///         monitor.increment_progress();
///     }
///     Ok(())
/// }
/// ```
pub trait TaskMonitor: Send + Sync {
    /// Returns `true` when cancellation has been requested.
    fn is_cancelled(&self) -> bool;

    /// Set the progress value (0-based, up to the maximum).
    fn set_progress(&self, value: i64);

    /// Set a human-readable status message.
    fn set_message(&self, msg: &str);

    /// Increment progress by 1 unit.
    fn increment_progress(&self);

    /// Check if cancelled and return an error if so.
    ///
    /// Call this periodically during long operations to enable
    /// cooperative cancellation.
    fn check_cancelled(&self) -> Result<(), CancelledException> {
        if self.is_cancelled() {
            Err(CancelledException::new("User cancelled operation"))
        } else {
            Ok(())
        }
    }

    /// Register a listener that will be notified on cancellation.
    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>);

    /// Get the current progress value (0-based, up to the maximum).
    ///
    /// Default implementation returns 0.
    fn get_progress(&self) -> i64 {
        0
    }

    /// Get the current status message.
    ///
    /// Default implementation returns an empty string.
    fn get_message(&self) -> String {
        String::new()
    }

    /// Set the maximum progress value.
    ///
    /// Default implementation is a no-op.
    fn set_max_progress(&self, _max: i64) {}

    /// Set whether this monitor is in indeterminate mode.
    ///
    /// When indeterminate, progress values are not meaningful.
    /// Default implementation is a no-op.
    fn set_indeterminate(&self, _indeterminate: bool) {}
}

// ---------------------------------------------------------------------------
// CancelledException
// ---------------------------------------------------------------------------

/// Error indicating that the operation was cancelled by the user.
///
/// Ghidra's `CancelledException` equivalent. This is distinct from
/// [`CancelledError`] in that it carries a human-readable message.
#[derive(Debug, Clone)]
pub struct CancelledException {
    /// Human-readable cancellation reason.
    pub message: String,
}

impl CancelledException {
    /// Create a new `CancelledException` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns `true` when this exception was caused by a user-initiated cancel.
    pub fn is_user_cancelled(&self) -> bool {
        true
    }
}

impl std::fmt::Display for CancelledException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cancelled: {}", self.message)
    }
}

impl std::error::Error for CancelledException {}

impl From<CancelledError> for CancelledException {
    fn from(_err: CancelledError) -> Self {
        CancelledException::new("Operation cancelled")
    }
}

// ---------------------------------------------------------------------------
// CancelledListener
// ---------------------------------------------------------------------------

/// Callback trait notified when a task is cancelled.
///
/// Register listeners via [`TaskMonitor::add_cancelled_listener`].
pub trait CancelledListener: Send + Sync {
    /// Called when the monitored task is cancelled.
    fn cancelled(&self);
}

// ---------------------------------------------------------------------------
// ProgressMonitor — concrete implementation with percentage tracking
// ---------------------------------------------------------------------------

/// A concrete progress monitor with percentage-based tracking.
///
/// Wraps a [`task::TaskMonitor`] (struct) and adds percentage calculation,
/// elapsed-time tracking, and an indeterminate mode.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::ProgressMonitor;
///
/// let pm = ProgressMonitor::new("Loading data");
/// pm.initialize_work(200);
/// for i in 0..200 {
///     pm.worked(1);
/// }
/// pm.done();
/// assert!((pm.percentage() - 100.0).abs() < 0.01);
/// ```
pub struct ProgressMonitor {
    inner: Monitor,
    message: Arc<Mutex<String>>,
    total_work: Arc<Mutex<i64>>,
    completed: Arc<Mutex<bool>>,
    indeterminate: Arc<Mutex<bool>>,
    listeners: Arc<Mutex<Vec<Box<dyn CancelledListener>>>>,
    /// Time at which this monitor was created.
    pub start_time: std::time::Instant,
}

impl std::fmt::Debug for ProgressMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressMonitor")
            .field("inner", &self.inner)
            .field("message", &self.message)
            .field("total_work", &self.total_work)
            .field("completed", &self.completed)
            .field("indeterminate", &self.indeterminate)
            .field("listeners", &format_args!("{} listeners", self.listeners.lock().unwrap().len()))
            .field("start_time", &self.start_time)
            .finish()
    }
}

impl Default for ProgressMonitor {
    fn default() -> Self {
        Self::new("")
    }
}

impl ProgressMonitor {
    /// Create a new progress monitor with an optional initial message.
    pub fn new(message: impl Into<String>) -> Self {
        let mon = Monitor::new();
        let msg = message.into();
        mon.set_message(&msg);
        Self {
            inner: mon,
            message: Arc::new(Mutex::new(msg)),
            total_work: Arc::new(Mutex::new(0)),
            completed: Arc::new(Mutex::new(false)),
            indeterminate: Arc::new(Mutex::new(true)),
            listeners: Arc::new(Mutex::new(Vec::new())),
            start_time: std::time::Instant::now(),
        }
    }

    /// Create a `ProgressMonitor` that wraps an existing [`Monitor`].
    pub fn wrap(monitor: Monitor) -> Self {
        Self {
            inner: monitor,
            message: Arc::new(Mutex::new(String::new())),
            total_work: Arc::new(Mutex::new(0)),
            completed: Arc::new(Mutex::new(false)),
            indeterminate: Arc::new(Mutex::new(true)),
            listeners: Arc::new(Mutex::new(Vec::new())),
            start_time: std::time::Instant::now(),
        }
    }

    // ------------------------------------------------------------------
    // TaskMonitor trait implementation (delegation)
    // ------------------------------------------------------------------

    /// Returns `true` when cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Request cancellation of the monitored work.
    pub fn cancel(&self) {
        self.inner.cancel();
        // Notify listeners
        if let Ok(listeners) = self.listeners.lock() {
            for l in listeners.iter() {
                l.cancelled();
            }
        }
    }

    /// Set the current progress value.
    pub fn set_progress(&self, value: i64) {
        self.inner.set_progress(value);
    }

    /// Set a human-readable status message.
    pub fn set_message(&self, msg: impl Into<String>) {
        let m = msg.into();
        if let Ok(mut guard) = self.message.lock() {
            *guard = m.clone();
        }
        self.inner.set_message(&m);
    }

    /// Get the current status message.
    pub fn get_message(&self) -> String {
        self.message.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Initialize progress tracking with a total amount of work units.
    pub fn initialize_work(&self, total: i64) {
        if let Ok(mut t) = self.total_work.lock() {
            *t = total;
        }
        if let Ok(mut ind) = self.indeterminate.lock() {
            *ind = total <= 0;
        }
        self.inner.initialize(total);
    }

    /// Report incremental progress (1 unit).
    pub fn worked(&self, delta: i64) {
        self.inner.increment_progress(delta);
    }

    /// Mark the monitored work as complete.
    pub fn done(&self) {
        if let Ok(mut c) = self.completed.lock() {
            *c = true;
        }
    }

    /// Returns `true` when `done()` has been called.
    pub fn is_done(&self) -> bool {
        self.completed.lock().map(|g| *g).unwrap_or(false)
    }

    /// Check cancellation and return an error if cancelled.
    pub fn check_cancelled(&self) -> Result<(), CancelledException> {
        if self.is_cancelled() {
            Err(CancelledException::new(
                self.get_message(),
            ))
        } else {
            Ok(())
        }
    }

    /// Increment progress and check for cancellation in one call.
    pub fn increment_progress_check(&self, delta: i64) -> Result<(), CancelledException> {
        self.check_cancelled()?;
        self.worked(delta);
        Ok(())
    }

    /// Register a cancellation listener.
    pub fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(listener);
        }
    }

    /// Get the current progress value (0-based, up to the maximum).
    pub fn get_progress(&self) -> i64 {
        self.inner.get_progress()
    }

    /// Set the maximum progress value.
    pub fn set_max_progress(&self, max: i64) {
        if let Ok(mut t) = self.total_work.lock() {
            *t = max;
        }
        if let Ok(mut ind) = self.indeterminate.lock() {
            *ind = max <= 0;
        }
        self.inner.set_maximum(max);
    }

    /// Returns the time at which this monitor was created.
    pub fn get_start_time(&self) -> std::time::Instant {
        self.start_time
    }

    /// Returns the elapsed time since this monitor was created.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Reset the start time to the current instant.
    pub fn reset_start_time(&mut self) {
        self.start_time = std::time::Instant::now();
    }

    /// Returns `true` when the underlying monitor has cancellation enabled.
    pub fn is_cancel_enabled(&self) -> bool {
        self.inner.is_cancel_enabled()
    }

    /// Enable or disable the cancel button on the underlying monitor.
    pub fn set_cancel_enabled(&self, enable: bool) {
        self.inner.set_cancel_enabled(enable);
    }

    // ------------------------------------------------------------------
    // Percentage tracking
    // ------------------------------------------------------------------

    /// The percentage of work completed (0.0 to 100.0).
    ///
    /// Returns 0.0 for indeterminate monitors or when total work is zero.
    /// Returns 100.0 when `done()` has been called.
    pub fn percentage(&self) -> f64 {
        if self.is_done() {
            return 100.0;
        }
        let total = self.total_work.lock().map(|g| *g).unwrap_or(0);
        if total <= 0 {
            return 0.0;
        }
        let current = self.inner.get_progress();
        let pct = (current as f64 / total as f64) * 100.0;
        pct.clamp(0.0, 100.0)
    }

    /// Set progress as a percentage value.
    pub fn set_percentage(&self, pct: f64) {
        let pct = pct.clamp(0.0, 100.0);
        let total = self.total_work.lock().map(|g| *g).unwrap_or(0);
        if total > 0 {
            let value = ((pct / 100.0) * total as f64) as i64;
            self.inner.set_progress(value);
        }
    }

    /// The ratio of work completed (0.0 to 1.0).
    pub fn ratio(&self) -> f64 {
        self.percentage() / 100.0
    }

    // ------------------------------------------------------------------
    // Indeterminate mode
    // ------------------------------------------------------------------

    /// Returns `true` when progress is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate.lock().map(|g| *g).unwrap_or(true)
    }

    /// Enable or disable indeterminate progress mode.
    pub fn set_indeterminate(&self, value: bool) {
        if let Ok(mut ind) = self.indeterminate.lock() {
            *ind = value;
        }
    }

    /// Returns the underlying task monitor for direct access.
    pub fn as_task_monitor(&self) -> &Monitor {
        &self.inner
    }

    /// Returns a view of this monitor as a `&dyn TaskMonitor`.
    pub fn as_trait(&self) -> &dyn TaskMonitor {
        self
    }
}

// Implement TaskMonitor trait for ProgressMonitor
impl TaskMonitor for ProgressMonitor {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }

    fn set_progress(&self, value: i64) {
        self.set_progress(value);
    }

    fn set_message(&self, msg: &str) {
        self.set_message(msg);
    }

    fn increment_progress(&self) {
        self.worked(1);
    }

    fn check_cancelled(&self) -> Result<(), CancelledException> {
        self.check_cancelled()
    }

    fn add_cancelled_listener(&self, listener: Box<dyn CancelledListener>) {
        self.add_cancelled_listener(listener);
    }

    fn get_progress(&self) -> i64 {
        self.get_progress()
    }

    fn get_message(&self) -> String {
        self.get_message()
    }

    fn set_max_progress(&self, max: i64) {
        self.set_max_progress(max);
    }

    fn set_indeterminate(&self, indeterminate: bool) {
        self.set_indeterminate(indeterminate);
    }
}

// ======================================================================
// ElapsedTimer
// ======================================================================

/// A simple elapsed-time tracker for performance measurement.
///
/// Tracks wall-clock time from creation or the last reset. Useful for
/// timing analysis tasks, file operations, and other duration measurements.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::ElapsedTimer;
///
/// let timer = ElapsedTimer::new("analysis");
/// // ... do work ...
/// println!("{}", timer.elapsed_formatted());
/// ```
#[derive(Debug, Clone)]
pub struct ElapsedTimer {
    /// The instant at which this timer started.
    start: std::time::Instant,
    /// A human-readable label for this timer.
    label: String,
}

impl ElapsedTimer {
    /// Create a new timer with the given label, starting now.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            start: std::time::Instant::now(),
            label: label.into(),
        }
    }

    /// Create a new unnamed timer.
    pub fn unnamed() -> Self {
        Self::new("unnamed")
    }

    /// Return the label of this timer.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set a new label.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = label.into();
    }

    /// Elapsed time in milliseconds since creation or the last reset.
    pub fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }

    /// Elapsed time in seconds (as floating-point) since creation or the last reset.
    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Raw elapsed [`Duration`] since creation or the last reset.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }

    /// Elapsed time in microseconds.
    pub fn elapsed_micros(&self) -> u128 {
        self.start.elapsed().as_micros()
    }

    /// Elapsed time in nanoseconds.
    pub fn elapsed_nanos(&self) -> u128 {
        self.start.elapsed().as_nanos()
    }

    /// Reset the timer to the current instant.
    pub fn reset(&mut self) {
        self.start = std::time::Instant::now();
    }

    /// Return a human-readable elapsed-time string (e.g., "2.5s", "1m 30s", "2h 15m 10s").
    pub fn elapsed_formatted(&self) -> String {
        let d = self.elapsed();
        let total_secs = d.as_secs();
        if total_secs < 1 {
            format!("{}ms", d.as_millis())
        } else if total_secs < 60 {
            format!("{:.1}s", d.as_secs_f64())
        } else if total_secs < 3600 {
            format!("{}m {}s", total_secs / 60, total_secs % 60)
        } else {
            format!(
                "{}h {}m {}s",
                total_secs / 3600,
                (total_secs % 3600) / 60,
                total_secs % 60
            )
        }
    }

    /// Check whether at least `duration` has elapsed.
    pub fn has_elapsed(&self, duration: std::time::Duration) -> bool {
        self.elapsed() >= duration
    }

    /// Check whether at least `millis` milliseconds have elapsed.
    pub fn has_elapsed_ms(&self, millis: u64) -> bool {
        self.elapsed_ms() >= millis as u128
    }
}

impl std::fmt::Display for ElapsedTimer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.label, self.elapsed_formatted())
    }
}

// ======================================================================
// MessageLog
// ======================================================================

/// Accumulates log messages with timestamps and severity levels.
///
/// A bounded or unbounded message buffer for collecting diagnostic output
/// during long-running operations. Thread-safe and cheaply cloneable (all
/// clones share the same backing storage).
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::{MessageLog, MessageType};
///
/// let log = MessageLog::new(100);
/// log.add(MessageType::Info, "Starting analysis");
/// log.add(MessageType::Warning, "Suspicious call at 0x401000");
/// log.add(MessageType::Error, "Failed to decode instruction");
/// println!("{}", log.to_string());
/// ```
#[derive(Debug, Clone)]
pub struct MessageLog {
    messages: Arc<Mutex<Vec<LogEntry>>>,
    /// Maximum number of entries to retain (oldest entries are dropped).
    /// A value of 0 means unbounded.
    max_entries: usize,
}

/// A single log entry with level, message text, and timestamp.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Severity level of the message.
    pub level: MessageType,
    /// The message text.
    pub message: String,
    /// Timestamp when the entry was created.
    pub timestamp: chrono::DateTime<chrono::Local>,
}

impl MessageLog {
    /// Create a new message log.
    ///
    /// `max_entries` is the maximum number of entries to retain. When the
    /// limit is exceeded, oldest entries are removed first. A value of 0
    /// means unbounded storage.
    pub fn new(max_entries: usize) -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
            max_entries,
        }
    }

    /// Create an unbounded message log.
    pub fn unbounded() -> Self {
        Self::new(0)
    }

    /// Add a message to the log.
    ///
    /// If the log has a size limit and is full, the oldest entry is removed.
    pub fn add(&self, level: MessageType, message: impl Into<String>) {
        let entry = LogEntry {
            level,
            message: message.into(),
            timestamp: chrono::Local::now(),
        };
        if let Ok(mut msgs) = self.messages.lock() {
            msgs.push(entry);
            if self.max_entries > 0 {
                while msgs.len() > self.max_entries {
                    msgs.remove(0);
                }
            }
        }
    }

    /// Add an info-level message.
    pub fn info(&self, message: impl Into<String>) {
        self.add(MessageType::Info, message);
    }

    /// Add a warning-level message.
    pub fn warn(&self, message: impl Into<String>) {
        self.add(MessageType::Warning, message);
    }

    /// Add an error-level message.
    pub fn error(&self, message: impl Into<String>) {
        self.add(MessageType::Error, message);
    }

    /// Add an alert-level message.
    pub fn alert(&self, message: impl Into<String>) {
        self.add(MessageType::Alert, message);
    }

    /// Append a string to the last message in the log without changing its
    /// level or timestamp. Useful for building messages incrementally.
    /// Does nothing if the log is empty.
    pub fn append_to_last(&self, suffix: impl AsRef<str>) {
        if let Ok(mut msgs) = self.messages.lock() {
            if let Some(last) = msgs.last_mut() {
                last.message.push_str(suffix.as_ref());
            }
        }
    }

    /// Get all messages in insertion order (oldest first).
    pub fn get_messages(&self) -> Vec<LogEntry> {
        self.messages
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Get messages filtered by severity level, in insertion order.
    pub fn get_by_type(&self, level: MessageType) -> Vec<LogEntry> {
        self.messages
            .lock()
            .map(|g| {
                g.iter()
                    .filter(|e| e.level == level)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get messages filtered by multiple severity levels.
    pub fn get_by_types(&self, levels: &[MessageType]) -> Vec<LogEntry> {
        self.messages
            .lock()
            .map(|g| {
                g.iter()
                    .filter(|e| levels.contains(&e.level))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get error and warning messages only.
    pub fn get_problems(&self) -> Vec<LogEntry> {
        self.get_by_types(&[MessageType::Error, MessageType::Warning])
    }

    /// Remove all entries from the log.
    pub fn clear(&self) {
        if let Ok(mut msgs) = self.messages.lock() {
            msgs.clear();
        }
    }

    /// Return the number of entries currently in the log.
    pub fn len(&self) -> usize {
        self.messages.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Return `true` when the log contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the maximum number of entries this log will hold (0 = unbounded).
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Change the maximum number of entries (truncates if needed).
    pub fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
        if max > 0 {
            if let Ok(mut msgs) = self.messages.lock() {
                while msgs.len() > max {
                    msgs.remove(0);
                }
            }
        }
    }

    /// Format all messages as a single string with timestamps and levels.
    pub fn to_string(&self) -> String {
        self.messages
            .lock()
            .map(|g| {
                g.iter()
                    .map(|e| {
                        format!(
                            "[{}] {} {}",
                            e.timestamp.format("%H:%M:%S"),
                            e.level,
                            e.message
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }

    /// Format only error and warning messages as a string.
    pub fn problems_to_string(&self) -> String {
        self.get_problems()
            .iter()
            .map(|e| {
                format!(
                    "[{}] {} {}",
                    e.timestamp.format("%H:%M:%S"),
                    e.level,
                    e.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Return true if the log contains any error-level messages.
    pub fn has_errors(&self) -> bool {
        self.messages
            .lock()
            .map(|g| g.iter().any(|e| e.level == MessageType::Error))
            .unwrap_or(false)
    }

    /// Return true if the log contains any warning-level messages.
    pub fn has_warnings(&self) -> bool {
        self.messages
            .lock()
            .map(|g| g.iter().any(|e| e.level == MessageType::Warning))
            .unwrap_or(false)
    }

    /// Count messages by severity level.
    pub fn count_by_type(&self, level: MessageType) -> usize {
        self.messages
            .lock()
            .map(|g| g.iter().filter(|e| e.level == level).count())
            .unwrap_or(0)
    }
}

impl std::fmt::Display for MessageLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_int() {
        assert_eq!(numeric::parse_int("42").unwrap(), 42);
        assert_eq!(numeric::parse_int("0xFF").unwrap(), 255);
        assert_eq!(numeric::parse_int("-10").unwrap(), -10);
    }

    #[test]
    fn test_parse_hex_long() {
        assert_eq!(numeric::parse_hex_long("FF").unwrap(), 255);
        assert_eq!(numeric::parse_hex_long("0xFF").unwrap(), 255);
    }

    #[test]
    fn test_decode_big_integer() {
        assert_eq!(
            numeric::decode_big_integer("255").unwrap(),
            num::bigint::BigInt::from(255u32)
        );
        assert_eq!(
            numeric::decode_big_integer("0xFF").unwrap(),
            num::bigint::BigInt::from(255u32)
        );
        assert_eq!(
            numeric::decode_big_integer("0b11111111").unwrap(),
            num::bigint::BigInt::from(255u32)
        );
        let neg = numeric::decode_big_integer("-10").unwrap();
        assert_eq!(neg, num::bigint::BigInt::from(-10));
    }

    #[test]
    fn test_convert_bytes() {
        let hex = convert_bytes_to_string(&[0xAB, 0xCD, 0xEF], Some(" "));
        assert_eq!(hex, "ab cd ef");
        let bytes = convert_string_to_bytes("ab cd ef").unwrap();
        assert_eq!(bytes, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_starts_with_ignore_case() {
        assert!(string_utils::starts_with_ignore_case("HelloWorld", "hello"));
        assert!(!string_utils::starts_with_ignore_case("HelloWorld", "xyz"));
    }

    #[test]
    fn test_trim() {
        assert_eq!(string_utils::trim("Hello, World!", 8), "Hello...");
        assert_eq!(string_utils::trim("Hi", 8), "Hi");
    }

    #[test]
    fn test_to_quoted_string() {
        let s = string_utils::to_quoted_string(b"AB");
        assert!(s.starts_with('"') && s.ends_with('"'));
        let s = string_utils::to_quoted_string(b"A");
        assert!(s.starts_with('\'') && s.ends_with('\''));
    }

    #[test]
    fn test_escape_sequences() {
        let result = string_utils::convert_escape_sequences(r"Hello\nWorld");
        assert_eq!(result, "Hello\nWorld");
    }

    #[test]
    fn test_format_length() {
        assert_eq!(file_utils::format_length(500), "500B");
        assert_eq!(file_utils::format_length(1500), "1.5KB");
        assert_eq!(file_utils::format_length(2_500_000), "2.5MB");
    }

    #[test]
    fn test_format_duration() {
        let d = date_utils::format_duration(5000);
        assert!(d.contains("secs"));
    }

    #[test]
    fn test_is_weekend() {
        let sat = chrono::NaiveDate::from_ymd_opt(2026, 6, 6).unwrap();
        assert!(date_utils::is_weekend(sat));
    }

    // ------------------------------------------------------------------
    // TaskMonitor trait tests
    // ------------------------------------------------------------------

    #[test]
    fn test_task_monitor_trait_is_cancelled() {
        let pm = ProgressMonitor::new("test");
        assert!(!pm.is_cancelled());
        pm.cancel();
        assert!(pm.is_cancelled());
    }

    #[test]
    fn test_task_monitor_trait_set_progress() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(100);
        pm.set_progress(50);
        assert!(pm.percentage() > 0.0);
    }

    #[test]
    fn test_task_monitor_trait_set_message() {
        let pm = ProgressMonitor::new("test");
        pm.set_message("loading...");
        assert_eq!(pm.get_message(), "loading...");
    }

    #[test]
    fn test_task_monitor_trait_increment_progress() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(10);
        pm.worked(1);
        pm.worked(1);
        assert!((pm.percentage() - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_task_monitor_trait_check_cancelled() {
        let pm = ProgressMonitor::new("test");
        assert!(pm.check_cancelled().is_ok());
        pm.cancel();
        assert!(pm.check_cancelled().is_err());
    }

    #[test]
    fn test_task_monitor_trait_add_cancelled_listener() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let pm = ProgressMonitor::new("test");

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        struct TestListener {
            called: Arc<AtomicBool>,
        }
        impl CancelledListener for TestListener {
            fn cancelled(&self) {
                self.called.store(true, Ordering::Relaxed);
            }
        }

        pm.add_cancelled_listener(Box::new(TestListener {
            called: called_clone,
        }));

        pm.cancel();
        assert!(called.load(Ordering::Relaxed));
    }

    // ------------------------------------------------------------------
    // CancelledException tests
    // ------------------------------------------------------------------

    #[test]
    fn test_cancelled_exception_creation() {
        let ex = CancelledException::new("User pressed cancel");
        assert_eq!(ex.message, "User pressed cancel");
        assert!(ex.is_user_cancelled());
        assert_eq!(ex.to_string(), "Cancelled: User pressed cancel");
    }

    #[test]
    fn test_cancelled_exception_from_cancelled_error() {
        let err = CancelledError;
        let ex: CancelledException = err.into();
        assert!(ex.to_string().contains("Cancelled"));
    }

    // ------------------------------------------------------------------
    // ProgressMonitor percentage tests
    // ------------------------------------------------------------------

    #[test]
    fn test_progress_monitor_percentage_zero() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(100);
        assert!((pm.percentage() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_progress_monitor_percentage_half() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(200);
        pm.worked(100);
        assert!((pm.percentage() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_progress_monitor_percentage_done() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(100);
        pm.worked(100);
        pm.done();
        assert!((pm.percentage() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_progress_monitor_set_percentage() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(1000);
        pm.set_percentage(75.0);
        assert!((pm.percentage() - 75.0).abs() < 1.0);
    }

    #[test]
    fn test_progress_monitor_ratio() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(100);
        pm.worked(25);
        assert!((pm.ratio() - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_progress_monitor_indeterminate() {
        let pm = ProgressMonitor::new("test");
        assert!(pm.is_indeterminate());
        pm.initialize_work(100);
        assert!(!pm.is_indeterminate());
    }

    #[test]
    fn test_progress_monitor_set_indeterminate() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(100);
        pm.set_indeterminate(true);
        assert!(pm.is_indeterminate());
        pm.set_indeterminate(false);
        assert!(!pm.is_indeterminate());
    }

    #[test]
    fn test_progress_monitor_clamped_percentage() {
        let pm = ProgressMonitor::new("test");
        pm.initialize_work(100);
        pm.set_percentage(150.0);
        assert!((pm.percentage() - 100.0).abs() < 0.01);
        pm.set_percentage(-10.0);
        assert!((pm.percentage() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_progress_monitor_default() {
        let pm = ProgressMonitor::default();
        assert!(!pm.is_cancelled());
        assert!(pm.is_indeterminate());
        assert!(!pm.is_done());
    }

    // ------------------------------------------------------------------
    // Macros tests
    // ------------------------------------------------------------------

    #[test]
    fn test_logging_macros_exist() {
        // Verify macros compile and do not panic (they are no-ops in test)
        info!("test info message");
        warn!("test warn message");
        error!("test error message");
        debug!("test debug message");
        trace!("test trace message");
    }

    // ------------------------------------------------------------------
    // ElapsedTimer tests
    // ------------------------------------------------------------------

    #[test]
    fn test_elapsed_timer_new() {
        let timer = ElapsedTimer::new("test");
        assert_eq!(timer.label(), "test");
        assert!(timer.elapsed_ms() < 1000); // Should be nearly instant
    }

    #[test]
    fn test_elapsed_timer_unnamed() {
        let timer = ElapsedTimer::unnamed();
        assert_eq!(timer.label(), "unnamed");
    }

    #[test]
    fn test_elapsed_timer_reset() {
        let mut timer = ElapsedTimer::new("test");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(timer.elapsed_ms() >= 10);
        timer.reset();
        assert!(timer.elapsed_ms() < 100);
    }

    #[test]
    fn test_elapsed_timer_formatted() {
        let timer = ElapsedTimer::new("test");
        let formatted = timer.elapsed_formatted();
        assert!(!formatted.is_empty());
    }

    #[test]
    fn test_elapsed_timer_has_elapsed() {
        let timer = ElapsedTimer::new("test");
        assert!(timer.has_elapsed(std::time::Duration::from_millis(0)));
        assert!(!timer.has_elapsed(std::time::Duration::from_secs(3600)));
        assert!(timer.has_elapsed_ms(0));
    }

    #[test]
    fn test_elapsed_timer_display() {
        let timer = ElapsedTimer::new("perf");
        let s = format!("{}", timer);
        assert!(s.contains("perf"));
    }

    #[test]
    fn test_elapsed_timer_micros_nanos() {
        let timer = ElapsedTimer::new("test");
        assert!(timer.elapsed_nanos() > 0);
        assert!(timer.elapsed_micros() < 1_000_000);
    }

    // ------------------------------------------------------------------
    // MessageLog tests
    // ------------------------------------------------------------------

    #[test]
    fn test_message_log_new() {
        let log = MessageLog::new(10);
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        assert_eq!(log.max_entries(), 10);
    }

    #[test]
    fn test_message_log_unbounded() {
        let log = MessageLog::unbounded();
        assert_eq!(log.max_entries(), 0);
    }

    #[test]
    fn test_message_log_add_and_get() {
        let log = MessageLog::new(100);
        log.add(MessageType::Info, "message 1");
        log.add(MessageType::Warning, "message 2");
        log.add(MessageType::Error, "message 3");

        assert_eq!(log.len(), 3);
        assert!(!log.is_empty());

        let msgs = log.get_messages();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].level, MessageType::Info);
        assert_eq!(msgs[0].message, "message 1");
        assert_eq!(msgs[1].level, MessageType::Warning);
        assert_eq!(msgs[2].level, MessageType::Error);
    }

    #[test]
    fn test_message_log_by_type() {
        let log = MessageLog::new(100);
        log.info("info msg");
        log.warn("warn msg");
        log.error("error msg");

        let infos = log.get_by_type(MessageType::Info);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].message, "info msg");

        let warns = log.get_by_type(MessageType::Warning);
        assert_eq!(warns.len(), 1);
    }

    #[test]
    fn test_message_log_by_types() {
        let log = MessageLog::new(100);
        log.info("info");
        log.warn("warn");
        log.error("error");
        log.alert("alert");

        let problems = log.get_by_types(&[MessageType::Error, MessageType::Warning]);
        assert_eq!(problems.len(), 2);
    }

    #[test]
    fn test_message_log_problems() {
        let log = MessageLog::new(100);
        log.info("info");
        log.warn("warn");
        log.error("error");

        let problems = log.get_problems();
        assert_eq!(problems.len(), 2);
    }

    #[test]
    fn test_message_log_clear() {
        let log = MessageLog::new(100);
        log.add(MessageType::Info, "test");
        assert_eq!(log.len(), 1);
        log.clear();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
    }

    #[test]
    fn test_message_log_overflow() {
        let log = MessageLog::new(3);
        log.add(MessageType::Info, "msg1");
        log.add(MessageType::Info, "msg2");
        log.add(MessageType::Info, "msg3");
        log.add(MessageType::Info, "msg4");

        let msgs = log.get_messages();
        assert_eq!(msgs.len(), 3);
        // Oldest should be dropped
        assert_eq!(msgs[0].message, "msg2");
        assert_eq!(msgs[2].message, "msg4");
    }

    #[test]
    fn test_message_log_has_errors_warnings() {
        let log = MessageLog::new(100);
        assert!(!log.has_errors());
        assert!(!log.has_warnings());

        log.warn("a warning");
        assert!(!log.has_errors());
        assert!(log.has_warnings());

        log.error("an error");
        assert!(log.has_errors());
        assert!(log.has_warnings());
    }

    #[test]
    fn test_message_log_count() {
        let log = MessageLog::new(100);
        log.info("a");
        log.info("b");
        log.warn("c");
        log.error("d");
        log.error("e");

        assert_eq!(log.count_by_type(MessageType::Info), 2);
        assert_eq!(log.count_by_type(MessageType::Warning), 1);
        assert_eq!(log.count_by_type(MessageType::Error), 2);
        assert_eq!(log.count_by_type(MessageType::Alert), 0);
    }

    #[test]
    fn test_message_log_append_to_last() {
        let log = MessageLog::new(100);
        log.info("part1");
        log.append_to_last(" + part2");
        let msgs = log.get_messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].message, "part1 + part2");
    }

    #[test]
    fn test_message_log_append_empty() {
        let log = MessageLog::new(100);
        log.append_to_last("nothing");
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_message_log_set_max_entries() {
        let mut log = MessageLog::new(100);
        for i in 0..10 {
            log.info(format!("msg{}", i));
        }
        log.set_max_entries(5);
        assert_eq!(log.len(), 5);
        assert_eq!(log.max_entries(), 5);
    }

    #[test]
    fn test_message_log_to_string() {
        let log = MessageLog::new(100);
        log.info("hello");
        let s = log.to_string();
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_message_log_display() {
        let log = MessageLog::new(100);
        log.error("fail");
        let s = format!("{}", log);
        assert!(s.contains("fail"));
    }

    #[test]
    fn test_message_log_problems_to_string() {
        let log = MessageLog::new(100);
        log.info("ok");
        log.warn("hmm");
        log.error("bad");
        let s = log.problems_to_string();
        assert!(s.contains("hmm"));
        assert!(s.contains("bad"));
        assert!(!s.contains("ok"));
    }
}
