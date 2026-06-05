//! Encoded strings plugin -- ported from Ghidra's
//! `ghidra.app.plugin.core.strings.EncodedStringsPlugin` and related classes.
//!
//! Searches for strings using specific character encodings and allows filtering
//! results by Unicode script, string model validation, and other criteria.
//!
//! # Key Types
//!
//! - [`EncodedStringsPlugin`] -- Plugin coordinating encoded string search
//! - [`EncodedStringsOptions`] -- Options controlling search and filtering
//! - [`EncodedStringsRow`] -- A single row in the encoded strings table
//! - [`EncodedStringsTableModel`] -- Table model for encoded string results
//! - [`StringInfo`] -- Analysis of a string's Unicode properties
//! - [`StringInfoFeature`] -- Feature flags for string analysis
//! - [`Trigram`] -- A 3-character n-gram for string model validation
//! - [`TrigramStringValidator`] -- Validates strings using a trigram model
//! - [`EncodedStringsFilterStats`] -- Statistics about filtered results
//! - [`CharacterScriptUtils`] -- Utilities for Unicode script analysis

use std::collections::{HashMap, HashSet};

/// Maximum trigram order for the string model.
const MAX_TRIGRAM_ORDER: usize = 3;

// ---------------------------------------------------------------------------
// StringInfoFeature
// ---------------------------------------------------------------------------

/// Feature flags describing properties of a string's characters.
///
/// Ported from `ghidra.app.plugin.core.strings.StringInfoFeature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringInfoFeature {
    /// The string contains a codec error (bad byte or replacement char).
    CodecError,
    /// The string contains non-standard control characters.
    NonStdCtrlChars,
    /// The string is pure ASCII.
    PureAscii,
    /// The string contains null bytes (embedded).
    ContainsNull,
    /// The string has mixed directionality (LTR + RTL).
    MixedDirectionality,
    /// The string contains only digits.
    NumericOnly,
    /// The string contains whitespace only.
    WhitespaceOnly,
}

impl StringInfoFeature {
    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::CodecError => "Codec Error",
            Self::NonStdCtrlChars => "Non-Standard Control Characters",
            Self::PureAscii => "Pure ASCII",
            Self::ContainsNull => "Contains Null",
            Self::MixedDirectionality => "Mixed Directionality",
            Self::NumericOnly => "Numeric Only",
            Self::WhitespaceOnly => "Whitespace Only",
        }
    }
}

// ---------------------------------------------------------------------------
// Unicode script enum (Rust equivalent of java.lang.Character.UnicodeScript)
// ---------------------------------------------------------------------------

/// Unicode script categories, mirroring `java.lang.Character.UnicodeScript`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnicodeScript {
    /// Latin script.
    Latin,
    /// Common script (shared across many writing systems).
    Common,
    /// Inherited script (inherits from surrounding text).
    Inherited,
    /// Cyrillic script.
    Cyrillic,
    /// Greek script.
    Greek,
    /// Arabic script.
    Arabic,
    /// Hebrew script.
    Hebrew,
    /// Devanagari script.
    Devanagari,
    /// CJK Unified Ideographs.
    Han,
    /// Hiragana.
    Hiragana,
    /// Katakana.
    Katakana,
    /// Hangul.
    Hangul,
    /// Thai script.
    Thai,
    /// Unknown script.
    Unknown,
    /// Any other script not explicitly listed.
    Other(u32),
}

impl UnicodeScript {
    /// Whether this script is commonly ignored in script-based filtering.
    pub fn is_ignored(&self) -> bool {
        matches!(self, Self::Common | Self::Inherited | Self::Unknown)
    }
}

/// Standard control characters that are acceptable in strings.
const STD_CTRL_CHARS: [char; 3] = ['\n', '\t', '\r'];

// ---------------------------------------------------------------------------
// StringInfo
// ---------------------------------------------------------------------------

/// Analysis of a string's Unicode properties.
///
/// Ported from `ghidra.app.plugin.core.strings.StringInfo`.
#[derive(Debug, Clone)]
pub struct StringInfo {
    /// The string value.
    pub string_value: String,
    /// Unicode scripts found in the string.
    pub scripts: HashSet<UnicodeScript>,
    /// Feature flags about the string.
    pub features: HashSet<StringInfoFeature>,
}

impl StringInfo {
    /// Create a [`StringInfo`] by analyzing a string.
    ///
    /// Ported from `StringInfo.fromString(String)`.
    pub fn from_string(s: &str) -> Self {
        let mut scripts = HashSet::new();
        let mut features = HashSet::new();
        let mut has_digit_only = true;
        let mut has_whitespace_only = true;
        let mut has_null = false;

        for ch in s.chars() {
            // Script classification
            let script = classify_script(ch);
            if script == UnicodeScript::Unknown {
                features.insert(StringInfoFeature::CodecError);
            } else {
                scripts.insert(script);
            }

            // Codec error detection
            if ch == '\u{FFFD}' {
                features.insert(StringInfoFeature::CodecError);
            }

            // Non-standard control chars
            if (ch.is_control() && !STD_CTRL_CHARS.contains(&ch)) || ch == '\0' {
                features.insert(StringInfoFeature::NonStdCtrlChars);
            }

            if ch == '\0' {
                has_null = true;
            }

            if !ch.is_ascii_digit() {
                has_digit_only = false;
            }
            if !ch.is_whitespace() {
                has_whitespace_only = false;
            }
        }

        if s.is_empty() || s.chars().all(|c| c.is_ascii()) {
            features.insert(StringInfoFeature::PureAscii);
        }

        if has_null {
            features.insert(StringInfoFeature::ContainsNull);
        }

        if !s.is_empty() && has_digit_only {
            features.insert(StringInfoFeature::NumericOnly);
        }

        if !s.is_empty() && has_whitespace_only {
            features.insert(StringInfoFeature::WhitespaceOnly);
        }

        StringInfo {
            string_value: s.to_string(),
            scripts,
            features,
        }
    }

    /// Whether the string has codec errors.
    pub fn has_codec_error(&self) -> bool {
        self.features.contains(&StringInfoFeature::CodecError)
    }

    /// Whether the string has non-standard control characters.
    pub fn has_non_std_ctrl_chars(&self) -> bool {
        self.features.contains(&StringInfoFeature::NonStdCtrlChars)
    }

    /// Whether the string contains null bytes.
    pub fn has_null_bytes(&self) -> bool {
        self.features.contains(&StringInfoFeature::ContainsNull)
    }

    /// Number of distinct Unicode scripts in the string.
    pub fn script_count(&self) -> usize {
        self.scripts.len()
    }

    /// Non-ignored scripts in this string.
    pub fn significant_scripts(&self) -> HashSet<UnicodeScript> {
        self.scripts.iter().copied().filter(|s| !s.is_ignored()).collect()
    }
}

/// Simplified Unicode script classification for a character.
fn classify_script(ch: char) -> UnicodeScript {
    let cp = ch as u32;
    if (0x0041..=0x007A).contains(&cp) || (0x00C0..=0x024F).contains(&cp) {
        UnicodeScript::Latin
    } else if (0x0400..=0x04FF).contains(&cp) {
        UnicodeScript::Cyrillic
    } else if (0x0370..=0x03FF).contains(&cp) {
        UnicodeScript::Greek
    } else if (0x0600..=0x06FF).contains(&cp) {
        UnicodeScript::Arabic
    } else if (0x0590..=0x05FF).contains(&cp) {
        UnicodeScript::Hebrew
    } else if (0x0900..=0x097F).contains(&cp) {
        UnicodeScript::Devanagari
    } else if (0x4E00..=0x9FFF).contains(&cp) {
        UnicodeScript::Han
    } else if (0x3040..=0x309F).contains(&cp) {
        UnicodeScript::Hiragana
    } else if (0x30A0..=0x30FF).contains(&cp) {
        UnicodeScript::Katakana
    } else if (0xAC00..=0xD7AF).contains(&cp) {
        UnicodeScript::Hangul
    } else if (0x0E00..=0x0E7F).contains(&cp) {
        UnicodeScript::Thai
    } else if ch.is_ascii() || ch.is_whitespace() || ch.is_ascii_punctuation() {
        UnicodeScript::Common
    } else if ch.is_control() {
        UnicodeScript::Inherited
    } else {
        UnicodeScript::Unknown
    }
}

// ---------------------------------------------------------------------------
// CharacterScriptUtils
// ---------------------------------------------------------------------------

/// Utilities for Unicode script analysis.
///
/// Ported from `ghidra.app.plugin.core.strings.CharacterScriptUtils`.
pub struct CharacterScriptUtils;

impl CharacterScriptUtils {
    /// Scripts that are always ignored during script-based filtering.
    pub const IGNORED_SCRIPTS: &'static [UnicodeScript] = &[
        UnicodeScript::Common,
        UnicodeScript::Inherited,
        UnicodeScript::Unknown,
    ];

    /// Get all scripts present in a string.
    pub fn get_scripts(s: &str) -> HashSet<UnicodeScript> {
        let info = StringInfo::from_string(s);
        info.scripts
    }

    /// Get only the "significant" (non-ignored) scripts.
    pub fn get_significant_scripts(s: &str) -> HashSet<UnicodeScript> {
        let info = StringInfo::from_string(s);
        info.significant_scripts()
    }

    /// Check if a string contains any of the given scripts.
    pub fn contains_any_script(s: &str, scripts: &[UnicodeScript]) -> bool {
        let info = StringInfo::from_string(s);
        scripts.iter().any(|sc| info.scripts.contains(sc))
    }

    /// Check if a string contains only scripts from the given set (plus ignored scripts).
    pub fn contains_only_scripts(s: &str, allowed: &[UnicodeScript]) -> bool {
        let info = StringInfo::from_string(s);
        let significant = info.significant_scripts();
        significant.iter().all(|sc| allowed.contains(sc))
    }
}

// ---------------------------------------------------------------------------
// Trigram
// ---------------------------------------------------------------------------

/// A 3-character n-gram used for string model validation.
///
/// Ported from `ghidra.app.plugin.core.strings.Trigram`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Trigram(pub [u8; 3]);

impl Trigram {
    /// Create a new trigram from three bytes.
    pub fn new(a: u8, b: u8, c: u8) -> Self {
        Self([a, b, c])
    }

    /// Extract all trigrams from a byte slice.
    pub fn extract_from_bytes(data: &[u8]) -> Vec<Trigram> {
        if data.len() < 3 {
            return Vec::new();
        }
        data.windows(3).map(|w| Trigram([w[0], w[1], w[2]])).collect()
    }

    /// Extract all trigrams from a string (using UTF-8 bytes).
    pub fn extract_from_string(s: &str) -> Vec<Trigram> {
        Self::extract_from_bytes(s.as_bytes())
    }
}

impl std::fmt::Display for Trigram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            self.0[0] as char,
            self.0[1] as char,
            self.0[2] as char
        )
    }
}

// ---------------------------------------------------------------------------
// TrigramStringValidator
// ---------------------------------------------------------------------------

/// Validates strings using a trigram-based language model.
///
/// Ported from `ghidra.app.plugin.core.strings.TrigramStringValidator`.
/// The validator checks if a string's trigram distribution is consistent
/// with known "valid" string patterns.
#[derive(Debug)]
pub struct TrigramStringValidator {
    /// Known valid trigrams with their log-probability scores.
    valid_trigrams: HashMap<Trigram, f64>,
    /// Minimum score threshold for a valid string.
    min_score: f64,
    /// The model name.
    model_name: String,
}

impl TrigramStringValidator {
    /// Create a new validator with no trained trigrams.
    pub fn new(model_name: impl Into<String>) -> Self {
        Self {
            valid_trigrams: HashMap::new(),
            min_score: -10.0,
            model_name: model_name.into(),
        }
    }

    /// Load trigrams from a model file content (tab-separated trigram + log-prob).
    ///
    /// Format: each line is `<byte1><byte2><byte3>\t<log_probability>`
    pub fn load_from_text(&mut self, text: &str) {
        for line in text.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let bytes = parts[0].as_bytes();
                if bytes.len() >= 3 {
                    let trigram = Trigram::new(bytes[0], bytes[1], bytes[2]);
                    if let Ok(prob) = parts[1].parse::<f64>() {
                        self.valid_trigrams.insert(trigram, prob);
                    }
                }
            }
        }
    }

    /// Add a single trigram with a log-probability score.
    pub fn add_trigram(&mut self, trigram: Trigram, log_prob: f64) {
        self.valid_trigrams.insert(trigram, log_prob);
    }

    /// Set the minimum score threshold.
    pub fn set_min_score(&mut self, score: f64) {
        self.min_score = score;
    }

    /// Get the minimum score threshold.
    pub fn min_score(&self) -> f64 {
        self.min_score
    }

    /// Get the model name.
    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    /// Number of trigrams in the model.
    pub fn trigram_count(&self) -> usize {
        self.valid_trigrams.len()
    }

    /// Validate whether a string is likely a "real" string.
    ///
    /// Returns `true` if the string's average trigram score exceeds the threshold.
    pub fn is_valid_string(&self, s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        let score = self.score_string(s);
        score >= self.min_score
    }

    /// Score a string against the model.
    ///
    /// Returns the average log-probability of its trigrams. Trigrams
    /// not found in the model receive a penalty score.
    pub fn score_string(&self, s: &str) -> f64 {
        let trigrams = Trigram::extract_from_string(s);
        if trigrams.is_empty() {
            return self.min_score - 1.0;
        }

        let unknown_penalty = self.min_score - 5.0;
        let total: f64 = trigrams
            .iter()
            .map(|t| {
                self.valid_trigrams
                    .get(t)
                    .copied()
                    .unwrap_or(unknown_penalty)
            })
            .sum();

        total / trigrams.len() as f64
    }
}

// ---------------------------------------------------------------------------
// EncodedStringsFilterStats
// ---------------------------------------------------------------------------

/// Statistics about how many strings were filtered out and why.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsFilterStats`.
#[derive(Debug, Clone, Default)]
pub struct EncodedStringsFilterStats {
    /// Total strings examined.
    pub total: usize,
    /// Filtered by minimum string length.
    pub string_length: usize,
    /// Filtered by codec errors.
    pub codec_errors: usize,
    /// Filtered by non-standard control characters.
    pub non_std_ctrl_chars: usize,
    /// Filtered by required scripts.
    pub required_scripts: usize,
    /// Filtered by allowed scripts.
    pub other_scripts: usize,
    /// Filtered by Latin script (when not allowed).
    pub latin_script: usize,
    /// Filtered by Common script (when not allowed).
    pub common_script: usize,
    /// Filtered by string model validation.
    pub failed_string_model: usize,
    /// Script counts for strings that passed so far.
    pub found_script_counts: HashMap<UnicodeScript, usize>,
}

impl EncodedStringsFilterStats {
    /// Total number of strings that were filtered out.
    pub fn total_filtered(&self) -> usize {
        self.string_length
            + self.codec_errors
            + self.non_std_ctrl_chars
            + self.required_scripts
            + self.other_scripts
            + self.latin_script
            + self.common_script
            + self.failed_string_model
    }

    /// Number of strings that passed all filters.
    pub fn passed(&self) -> usize {
        self.total.saturating_sub(self.total_filtered())
    }

    /// Pass rate as a percentage.
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.passed() as f64 / self.total as f64) * 100.0
        }
    }

    /// Merge stats from another source.
    pub fn merge(&mut self, other: &EncodedStringsFilterStats) {
        self.total += other.total;
        self.string_length += other.string_length;
        self.codec_errors += other.codec_errors;
        self.non_std_ctrl_chars += other.non_std_ctrl_chars;
        self.required_scripts += other.required_scripts;
        self.other_scripts += other.other_scripts;
        self.latin_script += other.latin_script;
        self.common_script += other.common_script;
        self.failed_string_model += other.failed_string_model;
        for (script, count) in &other.found_script_counts {
            *self.found_script_counts.entry(*script).or_insert(0) += count;
        }
    }
}

// ---------------------------------------------------------------------------
// EncodedStringsOptions
// ---------------------------------------------------------------------------

/// Options controlling the encoded strings search and filtering.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsOptions`.
#[derive(Debug, Clone)]
pub struct EncodedStringsOptions {
    /// Minimum string length to include.
    pub min_string_length: usize,
    /// The default charset name (e.g., "US-ASCII", "UTF-8").
    pub charset: String,
    /// Exclude strings with codec errors.
    pub exclude_codec_errors: bool,
    /// Exclude strings with non-standard control characters.
    pub exclude_non_std_ctrl_chars: bool,
    /// Required Unicode scripts (string must contain all).
    pub required_scripts: Vec<UnicodeScript>,
    /// Allowed Unicode scripts (string may contain these in addition to required).
    pub allowed_scripts: Vec<UnicodeScript>,
    /// Whether to require the string model to validate the string.
    pub require_valid_string: bool,
    /// The string model filename.
    pub string_model_filename: String,
}

impl Default for EncodedStringsOptions {
    fn default() -> Self {
        Self {
            min_string_length: 5,
            charset: "US-ASCII".to_string(),
            exclude_codec_errors: true,
            exclude_non_std_ctrl_chars: true,
            required_scripts: Vec::new(),
            allowed_scripts: Vec::new(),
            require_valid_string: false,
            string_model_filename: "stringngrams/StringModel.sng".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// EncodedStringsRow
// ---------------------------------------------------------------------------

/// A single row in the encoded strings results table.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsRow`.
#[derive(Debug, Clone)]
pub struct EncodedStringsRow {
    /// The string value.
    pub string_value: String,
    /// The address where the string is located.
    pub address: u64,
    /// String analysis information.
    pub string_info: StringInfo,
    /// Number of references to this string.
    pub ref_count: usize,
    /// Number of offcut references (references into the middle of the string).
    pub offcut_count: usize,
    /// Whether the string passed model validation.
    pub valid_string: bool,
}

impl EncodedStringsRow {
    /// Create a new encoded strings row.
    pub fn new(string_value: impl Into<String>, address: u64) -> Self {
        let val = string_value.into();
        let string_info = StringInfo::from_string(&val);
        Self {
            string_value: val,
            address,
            string_info,
            ref_count: 0,
            offcut_count: 0,
            valid_string: true,
        }
    }

    /// Check whether this row matches the given options.
    ///
    /// Updates the stats with the reason for filtering.
    pub fn matches(&self, options: &EncodedStringsOptions, stats: &mut EncodedStringsFilterStats) -> bool {
        stats.total += 1;

        let str = &self.string_value;

        if options.min_string_length > 0 && str.len() < options.min_string_length {
            stats.string_length += 1;
            return false;
        }

        if options.exclude_codec_errors && self.string_info.has_codec_error() {
            stats.codec_errors += 1;
            return false;
        }

        if options.exclude_non_std_ctrl_chars && self.string_info.has_non_std_ctrl_chars() {
            stats.non_std_ctrl_chars += 1;
            return false;
        }

        // Update script counts
        for script in &self.string_info.scripts {
            *stats.found_script_counts.entry(*script).or_insert(0) += 1;
        }

        // Check required scripts
        if !options.required_scripts.is_empty() {
            let has_all = options.required_scripts.iter().all(|sc| self.string_info.scripts.contains(sc));
            if !has_all {
                stats.required_scripts += 1;
                return false;
            }
        }

        // Check allowed scripts
        if !options.allowed_scripts.is_empty() {
            let mut significant = self.string_info.significant_scripts();
            // Remove required scripts from the check
            for rs in &options.required_scripts {
                significant.remove(rs);
            }

            let had_latin = significant.remove(&UnicodeScript::Latin);
            let had_common = significant.remove(&UnicodeScript::Common);

            // Check if any remaining scripts are not in the allowed list
            let disallowed: Vec<_> = significant
                .iter()
                .filter(|sc| !options.allowed_scripts.contains(sc))
                .collect();
            if !disallowed.is_empty() {
                stats.other_scripts += 1;
                return false;
            }
            if had_latin && !options.allowed_scripts.contains(&UnicodeScript::Latin) {
                stats.latin_script += 1;
                return false;
            }
            if had_common && !options.allowed_scripts.contains(&UnicodeScript::Common) {
                stats.common_script += 1;
                return false;
            }
        }

        // Check string model validation
        if options.require_valid_string && !self.valid_string {
            stats.failed_string_model += 1;
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// EncodedStringsTableModel
// ---------------------------------------------------------------------------

/// Table model for the encoded strings results.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsTableModel`.
#[derive(Debug)]
pub struct EncodedStringsTableModel {
    /// All rows.
    rows: Vec<EncodedStringsRow>,
    /// Current options.
    options: EncodedStringsOptions,
    /// Filter stats from the last filter pass.
    last_stats: EncodedStringsFilterStats,
}

impl EncodedStringsTableModel {
    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            options: EncodedStringsOptions::default(),
            last_stats: EncodedStringsFilterStats::default(),
        }
    }

    /// Set all rows.
    pub fn set_rows(&mut self, rows: Vec<EncodedStringsRow>) {
        self.rows = rows;
    }

    /// Add a single row.
    pub fn add_row(&mut self, row: EncodedStringsRow) {
        self.rows.push(row);
    }

    /// Get the options.
    pub fn options(&self) -> &EncodedStringsOptions {
        &self.options
    }

    /// Get mutable options.
    pub fn options_mut(&mut self) -> &mut EncodedStringsOptions {
        &mut self.options
    }

    /// Get the filtered rows.
    pub fn filtered_rows(&self) -> Vec<&EncodedStringsRow> {
        let mut stats = EncodedStringsFilterStats::default();
        self.rows
            .iter()
            .filter(|r| r.matches(&self.options, &mut stats))
            .collect()
    }

    /// Get the total row count.
    pub fn total_count(&self) -> usize {
        self.rows.len()
    }

    /// Run a filter pass and return stats.
    pub fn compute_filter_stats(&mut self) -> &EncodedStringsFilterStats {
        let mut stats = EncodedStringsFilterStats::default();
        for row in &self.rows {
            row.matches(&self.options, &mut stats);
        }
        self.last_stats = stats;
        &self.last_stats
    }

    /// Get the last computed filter stats.
    pub fn last_stats(&self) -> &EncodedStringsFilterStats {
        &self.last_stats
    }
}

impl Default for EncodedStringsTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EncodedStringsPlugin
// ---------------------------------------------------------------------------

/// Plugin for searching encoded strings.
///
/// Ported from `ghidra.app.plugin.core.strings.EncodedStringsPlugin`.
#[derive(Debug)]
pub struct EncodedStringsPlugin {
    /// Plugin name.
    name: String,
    /// The table model.
    model: EncodedStringsTableModel,
    /// The string model validator.
    validator: Option<TrigramStringValidator>,
    /// Default charset.
    default_charset: String,
    /// Whether a search dialog is open.
    dialog_open: bool,
}

impl EncodedStringsPlugin {
    /// Plugin name constant.
    pub const ACTION_NAME: &'static str = "Search For Encoded Strings";

    /// Create a new encoded strings plugin.
    pub fn new() -> Self {
        Self {
            name: "EncodedStringsPlugin".to_string(),
            model: EncodedStringsTableModel::new(),
            validator: None,
            default_charset: "US-ASCII".to_string(),
            dialog_open: false,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the table model.
    pub fn model(&self) -> &EncodedStringsTableModel {
        &self.model
    }

    /// Get a mutable reference to the table model.
    pub fn model_mut(&mut self) -> &mut EncodedStringsTableModel {
        &mut self.model
    }

    /// Set the string model validator.
    pub fn set_validator(&mut self, validator: TrigramStringValidator) {
        self.validator = Some(validator);
    }

    /// Get the validator.
    pub fn validator(&self) -> Option<&TrigramStringValidator> {
        self.validator.as_ref()
    }

    /// Set the default charset.
    pub fn set_default_charset(&mut self, charset: impl Into<String>) {
        self.default_charset = charset.into();
    }

    /// Get the default charset.
    pub fn default_charset(&self) -> &str {
        &self.default_charset
    }

    /// Whether a dialog is open.
    pub fn is_dialog_open(&self) -> bool {
        self.dialog_open
    }

    /// Set dialog state.
    pub fn set_dialog_open(&mut self, open: bool) {
        self.dialog_open = open;
    }
}

impl Default for EncodedStringsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_info_ascii() {
        let info = StringInfo::from_string("hello world");
        assert!(info.features.contains(&StringInfoFeature::PureAscii));
        assert!(!info.has_codec_error());
        assert!(!info.has_non_std_ctrl_chars());
        assert!(info.scripts.contains(&UnicodeScript::Latin));
    }

    #[test]
    fn test_string_info_cyrillic() {
        let info = StringInfo::from_string("\u{041f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}");
        assert!(info.scripts.contains(&UnicodeScript::Cyrillic));
        assert!(!info.features.contains(&StringInfoFeature::PureAscii));
    }

    #[test]
    fn test_string_info_control_chars() {
        let info = StringInfo::from_string("test\x01value");
        assert!(info.has_non_std_ctrl_chars());
    }

    #[test]
    fn test_string_info_null() {
        let info = StringInfo::from_string("test\x00value");
        assert!(info.has_null_bytes());
    }

    #[test]
    fn test_string_info_numeric_only() {
        let info = StringInfo::from_string("12345");
        assert!(info.features.contains(&StringInfoFeature::NumericOnly));
    }

    #[test]
    fn test_string_info_whitespace_only() {
        let info = StringInfo::from_string("   \t\n");
        assert!(info.features.contains(&StringInfoFeature::WhitespaceOnly));
    }

    #[test]
    fn test_string_info_features() {
        assert_eq!(StringInfoFeature::CodecError.display_name(), "Codec Error");
        assert_eq!(StringInfoFeature::PureAscii.display_name(), "Pure ASCII");
    }

    #[test]
    fn test_character_script_utils() {
        let scripts = CharacterScriptUtils::get_scripts("hello");
        assert!(scripts.contains(&UnicodeScript::Latin));

        let sig = CharacterScriptUtils::get_significant_scripts("hello");
        assert!(sig.contains(&UnicodeScript::Latin));
        // Common scripts like space should be ignored
        assert!(!sig.contains(&UnicodeScript::Common));
    }

    #[test]
    fn test_character_script_contains_only() {
        assert!(CharacterScriptUtils::contains_only_scripts(
            "hello",
            &[UnicodeScript::Latin]
        ));
        assert!(!CharacterScriptUtils::contains_only_scripts(
            "hello \u{041f}",
            &[UnicodeScript::Latin]
        ));
    }

    #[test]
    fn test_trigram_extract() {
        let trigrams = Trigram::extract_from_string("hello");
        assert_eq!(trigrams.len(), 3); // "hel", "ell", "llo"
        assert_eq!(trigrams[0], Trigram::new(b'h', b'e', b'l'));
        assert_eq!(trigrams[2], Trigram::new(b'l', b'l', b'o'));
    }

    #[test]
    fn test_trigram_short_string() {
        let trigrams = Trigram::extract_from_string("hi");
        assert!(trigrams.is_empty());
    }

    #[test]
    fn test_trigram_display() {
        let t = Trigram::new(b'a', b'b', b'c');
        assert_eq!(format!("{}", t), "abc");
    }

    #[test]
    fn test_trigram_validator() {
        let mut validator = TrigramStringValidator::new("test_model");
        validator.add_trigram(Trigram::new(b'h', b'e', b'l'), -1.0);
        validator.add_trigram(Trigram::new(b'e', b'l', b'l'), -1.0);
        validator.add_trigram(Trigram::new(b'l', b'l', b'o'), -1.0);
        validator.set_min_score(-5.0);

        assert_eq!(validator.trigram_count(), 3);
        assert!(validator.is_valid_string("hello"));
        assert!(!validator.is_valid_string("xyz"));
    }

    #[test]
    fn test_trigram_validator_empty() {
        let validator = TrigramStringValidator::new("test");
        assert!(!validator.is_valid_string(""));
    }

    #[test]
    fn test_encoded_strings_row_matches() {
        let row = EncodedStringsRow::new("hello", 0x1000);
        let options = EncodedStringsOptions::default();
        let mut stats = EncodedStringsFilterStats::default();
        assert!(row.matches(&options, &mut stats));
        assert_eq!(stats.total, 1);
    }

    #[test]
    fn test_encoded_strings_row_filter_length() {
        let row = EncodedStringsRow::new("hi", 0x1000);
        let options = EncodedStringsOptions {
            min_string_length: 5,
            ..Default::default()
        };
        let mut stats = EncodedStringsFilterStats::default();
        assert!(!row.matches(&options, &mut stats));
        assert_eq!(stats.string_length, 1);
    }

    #[test]
    fn test_encoded_strings_row_filter_codec_errors() {
        let mut row = EncodedStringsRow::new("test\u{FFFD}", 0x1000);
        row.valid_string = false;
        let options = EncodedStringsOptions {
            min_string_length: 0,
            exclude_codec_errors: true,
            ..Default::default()
        };
        let mut stats = EncodedStringsFilterStats::default();
        assert!(!row.matches(&options, &mut stats));
        assert_eq!(stats.codec_errors, 1);
    }

    #[test]
    fn test_encoded_strings_row_required_scripts() {
        let row = EncodedStringsRow::new("hello", 0x1000);
        let options = EncodedStringsOptions {
            min_string_length: 0,
            required_scripts: vec![UnicodeScript::Cyrillic],
            ..Default::default()
        };
        let mut stats = EncodedStringsFilterStats::default();
        assert!(!row.matches(&options, &mut stats));
        assert_eq!(stats.required_scripts, 1);
    }

    #[test]
    fn test_encoded_strings_filter_stats() {
        let mut stats = EncodedStringsFilterStats::default();
        stats.total = 100;
        stats.string_length = 5;
        stats.codec_errors = 3;
        assert_eq!(stats.total_filtered(), 8);
        assert_eq!(stats.passed(), 92);
    }

    #[test]
    fn test_encoded_strings_filter_stats_merge() {
        let mut s1 = EncodedStringsFilterStats::default();
        s1.total = 10;
        s1.codec_errors = 2;

        let mut s2 = EncodedStringsFilterStats::default();
        s2.total = 20;
        s2.codec_errors = 5;

        s1.merge(&s2);
        assert_eq!(s1.total, 30);
        assert_eq!(s1.codec_errors, 7);
    }

    #[test]
    fn test_encoded_strings_table_model() {
        let mut model = EncodedStringsTableModel::new();
        assert_eq!(model.total_count(), 0);

        model.add_row(EncodedStringsRow::new("hello", 0x1000));
        model.add_row(EncodedStringsRow::new("world", 0x2000));
        assert_eq!(model.total_count(), 2);
    }

    #[test]
    fn test_encoded_strings_plugin() {
        let mut plugin = EncodedStringsPlugin::new();
        assert_eq!(plugin.name(), "EncodedStringsPlugin");
        assert!(!plugin.is_dialog_open());
        assert!(plugin.validator().is_none());

        plugin.set_dialog_open(true);
        assert!(plugin.is_dialog_open());
    }

    #[test]
    fn test_unicode_script_is_ignored() {
        assert!(UnicodeScript::Common.is_ignored());
        assert!(UnicodeScript::Inherited.is_ignored());
        assert!(UnicodeScript::Unknown.is_ignored());
        assert!(!UnicodeScript::Latin.is_ignored());
        assert!(!UnicodeScript::Cyrillic.is_ignored());
    }

    #[test]
    fn test_string_info_multi_script() {
        let info = StringInfo::from_string("hello \u{041f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}");
        assert!(info.scripts.contains(&UnicodeScript::Latin));
        assert!(info.scripts.contains(&UnicodeScript::Cyrillic));
        assert!(info.script_count() >= 2);
    }

    #[test]
    fn test_encoded_strings_options_defaults() {
        let opts = EncodedStringsOptions::default();
        assert_eq!(opts.min_string_length, 5);
        assert_eq!(opts.charset, "US-ASCII");
        assert!(opts.exclude_codec_errors);
        assert!(opts.exclude_non_std_ctrl_chars);
        assert!(!opts.require_valid_string);
    }
}
